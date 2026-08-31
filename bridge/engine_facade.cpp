#include "bridge/engine_facade.hpp"

#include "ce-gtk/src/bridge.rs.h"
#include "core/target_profile.hpp"
#include "core/version.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

namespace ce::bridge {

rust::String EngineFacade::version() const {
    return std::string(ce::version());
}

namespace {

constexpr std::uint32_t kMaxProcessPageSize = 512;
constexpr std::size_t kMaxProcessQuerySize = 256;
constexpr std::size_t kMaxDisplayNameSize = 256;
constexpr std::size_t kMemoryProbeLimit = 8;
constexpr std::uint32_t kMaxScanPageSize = 256;

std::string ascii_lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string process_name(std::int32_t pid, rust::Str requested) {
    std::string name(requested);
    if (name.size() > kMaxDisplayNameSize) name.resize(kMaxDisplayNameSize);
    for (char& character : name) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 0x20 || byte == 0x7f) character = ' ';
    }

    if (name.find_first_not_of(' ') != std::string::npos) return name;

    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    std::getline(comm, name);
    return name.empty() ? std::to_string(pid) : name;
}

std::string yama_ptrace_scope() {
    std::ifstream scope("/proc/sys/kernel/yama/ptrace_scope");
    std::string value;
    std::getline(scope, value);
    return value.empty() ? "unknown" : value;
}

std::string endian_name(ce::TargetProfile::Endian endian) {
    switch (endian) {
        case ce::TargetProfile::Endian::Little: return "little";
        case ce::TargetProfile::Endian::Big: return "big";
        default: return "unknown";
    }
}

AttachResult base_attach_result(std::int32_t pid, const std::string& name) {
    AttachResult result;
    result.success = false;
    result.pid = pid;
    result.name = name;
    result.summary = "";
    result.arch = "unknown";
    result.endianness = "unknown";
    result.wine = false;
    result.sandboxed = false;
    result.already_traced = false;
    result.tracer_pid = 0;
    result.yama_scope = yama_ptrace_scope();
    result.error_code = "";
    result.error_message = "";
    return result;
}

void copy_profile(const ce::TargetProfile& profile, AttachResult& result) {
    result.summary = profile.summary();
    result.arch = profile.archName();
    result.endianness = endian_name(profile.endianness);
    result.wine = profile.wine;
    result.sandboxed = profile.pidNamespaced;
    result.already_traced = profile.tracerPid != 0;
    result.tracer_pid = static_cast<std::int32_t>(profile.tracerPid);
    for (const auto& note : profile.notes) result.notes.push_back(note);
}

void set_memory_error(AttachResult& result, const ce::TargetProfile& profile,
                      const std::optional<std::error_code>& error) {
    if (profile.tracerPid != 0) {
        result.error_code = "already_traced";
        result.error_message = "The process is already being traced by PID " +
            std::to_string(profile.tracerPid) +
            ". Its memory cannot be opened until that tracer detaches.";
        return;
    }

    if (error && (error->value() == ESRCH || *error == std::errc::no_such_process)) {
        result.error_code = "process_gone";
        result.error_message = "The process exited while the session was being opened.";
        return;
    }

    if (error && (error->value() == EPERM || error->value() == EACCES ||
                  *error == std::errc::permission_denied ||
                  *error == std::errc::operation_not_permitted)) {
        const std::string scope(result.yama_scope.c_str(), result.yama_scope.size());
        result.error_code = "permission_denied";
        result.error_message =
            "Linux denied memory access (Yama ptrace_scope=" + scope +
            "). Launch the target as a child of the app or grant the installed "
            "binary CAP_SYS_PTRACE.";
        return;
    }

    result.error_code = "memory_unreadable";
    result.error_message = error
        ? "The process memory could not be read: " + error->message() + "."
        : "The process has no readable memory mappings.";
}

} // namespace

EngineFacade::~EngineFacade() {
    cancel_scan();
    join_scan_worker();
}

rust::Vec<ProcessRow> EngineFacade::list_processes(rust::Str query,
                                                    std::uint32_t limit) const {
    std::string needle(query);
    if (needle.size() > kMaxProcessQuerySize)
        needle.resize(kMaxProcessQuerySize);
    needle = ascii_lower(std::move(needle));

    ce::os::LinuxProcessEnumerator enumerator;
    auto processes = enumerator.list();
    std::sort(processes.begin(), processes.end(), [](const auto& left, const auto& right) {
        auto leftName = ascii_lower(left.name);
        auto rightName = ascii_lower(right.name);
        if (leftName != rightName) return leftName < rightName;
        return left.pid < right.pid;
    });

    rust::Vec<ProcessRow> rows;
    const auto pageSize = std::min(limit, kMaxProcessPageSize);
    if (pageSize == 0) return rows;

    for (const auto& process : processes) {
        if (!needle.empty()) {
            auto searchable = ascii_lower(process.name + "\n" + process.path);
            if (searchable.find(needle) == std::string::npos) continue;
        }

        rows.push_back(ProcessRow{
            .pid = static_cast<std::int32_t>(process.pid),
            .name = process.name,
            .path = process.path,
            .sandboxed = process.sandboxed,
        });
        if (rows.size() >= pageSize) break;
    }
    return rows;
}

AttachResult EngineFacade::attach(std::int32_t pid, rust::Str display_name) {
    const auto name = process_name(pid, display_name);
    auto result = base_attach_result(pid, name);
    if (scan_running_.load(std::memory_order_acquire)) {
        result.error_code = "scan_in_progress";
        result.error_message = "Cancel or finish the current scan before changing processes.";
        return result;
    }
    join_scan_worker();

    const auto profile = ce::probeTarget(static_cast<pid_t>(pid));
    if (!profile.valid) {
        result.error_code = "process_not_found";
        result.error_message = "The process is no longer running or /proc cannot inspect it.";
        return result;
    }
    copy_profile(profile, result);

    auto candidate = std::make_unique<ce::os::LinuxProcessHandle>(static_cast<pid_t>(pid));
    const auto regions = candidate->queryRegions();
    bool saw_readable = false;
    std::size_t attempted = 0;
    std::optional<std::error_code> last_error;
    for (const auto& region : regions) {
        if (!(region.protection & ce::MemProt::Read) || region.size == 0) continue;
        saw_readable = true;
        std::uint8_t byte = 0;
        auto read = candidate->read(region.base, &byte, sizeof byte);
        if (read && *read == sizeof byte) {
            clear_scan_state();
            process_ = std::move(candidate);
            result.success = true;
            return result;
        }
        if (!read) last_error = read.error();
        if (++attempted >= kMemoryProbeLimit) break;
    }

    if (!saw_readable) {
        result.error_code = regions.empty() ? "memory_map_unavailable" : "no_readable_memory";
        result.error_message = regions.empty()
            ? "The process memory map could not be read. It may have exited or /proc is restricted."
            : "The process has no readable memory mappings to scan.";
        return result;
    }

    set_memory_error(result, profile, last_error);
    return result;
}

void EngineFacade::detach() noexcept {
    cancel_scan();
    join_scan_worker();
    clear_scan_state();
    process_.reset();
}

bool EngineFacade::is_attached() const noexcept {
    return process_ != nullptr;
}

std::int32_t EngineFacade::attached_pid() const noexcept {
    return process_ ? static_cast<std::int32_t>(process_->pid()) : 0;
}

ScanStartResult EngineFacade::start_first_scan_i32(std::int32_t value,
                                                    std::uint64_t start_address,
                                                    std::uint64_t stop_address,
                                                    std::uint32_t alignment) {
    ScanStartResult response;
    response.accepted = false;
    response.error_code = "";
    response.error_message = "";

    if (!process_) {
        response.error_code = "no_session";
        response.error_message = "Attach to a process before scanning.";
        return response;
    }
    if (scan_running_.load(std::memory_order_acquire)) {
        response.error_code = "scan_in_progress";
        response.error_message = "A memory scan is already running.";
        return response;
    }
    if (start_address >= stop_address) {
        response.error_code = "invalid_range";
        response.error_message = "The scan start address must be below the stop address.";
        return response;
    }
    if (alignment == 0 || alignment > 4096) {
        response.error_code = "invalid_alignment";
        response.error_message = "Scan alignment must be between 1 and 4096 bytes.";
        return response;
    }

    join_scan_worker();
    {
        std::lock_guard lock(scan_mutex_);
        scan_result_.reset();
        scan_error_.clear();
        scan_generation_.fetch_add(1, std::memory_order_acq_rel);
    }
    scanner_ = std::make_unique<ce::MemoryScanner>();
    scan_cancel_requested_.store(false, std::memory_order_release);
    scan_started_.store(true, std::memory_order_release);
    scan_running_.store(true, std::memory_order_release);

    ce::ScanConfig config;
    config.valueType = ce::ValueType::Int32;
    config.compareType = ce::ScanCompare::Exact;
    config.intValue = value;
    config.alignment = alignment;
    config.startAddress = static_cast<std::uintptr_t>(std::min<std::uint64_t>(
        start_address, std::numeric_limits<std::uintptr_t>::max()));
    config.stopAddress = static_cast<std::uintptr_t>(std::min<std::uint64_t>(
        stop_address, std::numeric_limits<std::uintptr_t>::max()));

    auto* const target = process_.get();
    scan_worker_ = std::thread([this, target, config = std::move(config)] {
        try {
            auto result = std::make_unique<ce::ScanResult>(scanner_->firstScan(*target, config));
            std::lock_guard lock(scan_mutex_);
            scan_result_ = std::move(result);
        } catch (const std::exception& error) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = error.what();
        } catch (...) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = "Unknown scanner failure.";
        }
        scan_running_.store(false, std::memory_order_release);
    });

    // firstScan() resets its reusable cancellation flag on entry. Do not return
    // control (and expose Cancel in GTK) until that reset has happened, otherwise
    // an immediate cancel could be overwritten by the worker a moment later.
    while (scan_running_.load(std::memory_order_acquire) && !scanner_->running())
        std::this_thread::yield();

    response.accepted = true;
    return response;
}

ScanStatus EngineFacade::scan_status() const {
    ScanStatus status;
    status.started = scan_started_.load(std::memory_order_acquire);
    status.generation = scan_generation_.load(std::memory_order_acquire);
    status.running = scan_running_.load(std::memory_order_acquire);
    status.cancel_requested = scan_cancel_requested_.load(std::memory_order_acquire);
    status.cancelled = false;
    status.completed = false;
    status.progress = scanner_ ? scanner_->progress() : 0.0f;
    status.result_count = 0;
    status.write_error = false;
    status.error_message = "";

    std::lock_guard lock(scan_mutex_);
    status.error_message = scan_error_;
    status.cancelled = status.started && !status.running && status.cancel_requested;
    status.completed = status.started && !status.running && !status.cancelled &&
                       scan_error_.empty() && scan_result_ != nullptr;
    if (scan_result_) {
        status.result_count = static_cast<std::uint64_t>(scan_result_->count());
        status.write_error = scan_result_->hasWriteError();
    }
    return status;
}

ScanPage EngineFacade::scan_rows(std::uint64_t generation, std::uint64_t start,
                                 std::uint32_t limit) const {
    ScanPage page;
    page.generation = scan_generation_.load(std::memory_order_acquire);
    page.start = start;
    page.total_count = 0;
    page.stale = false;
    page.error_message = "";

    std::lock_guard lock(scan_mutex_);
    page.generation = scan_generation_.load(std::memory_order_acquire);
    page.stale = generation != page.generation;
    if (page.stale) return page;
    if (scan_running_.load(std::memory_order_acquire)) {
        page.error_message = "Scan results are not ready yet.";
        return page;
    }
    if (!scan_result_) {
        page.error_message = "No completed scan result is available.";
        return page;
    }

    page.total_count = static_cast<std::uint64_t>(scan_result_->count());
    page.start = std::min<std::uint64_t>(start, page.total_count);
    const auto bounded_start = static_cast<std::size_t>(std::min<std::uint64_t>(
        page.start, std::numeric_limits<std::size_t>::max()));
    const auto bounded_limit = static_cast<std::size_t>(std::min(limit, kMaxScanPageSize));
    scan_result_->forRange(
        bounded_start, bounded_limit,
        [&page](std::uintptr_t address, const void* bytes, std::size_t size) {
            if (size != sizeof(std::int32_t)) return;
            std::int32_t value = 0;
            std::memcpy(&value, bytes, sizeof value);
            page.rows.push_back(ScanHit{
                .address = static_cast<std::uint64_t>(address),
                .value = std::to_string(value),
            });
        },
        sizeof(std::int32_t));
    return page;
}

void EngineFacade::cancel_scan() noexcept {
    if (!scan_running_.load(std::memory_order_acquire) || !scanner_) return;
    scan_cancel_requested_.store(true, std::memory_order_release);
    scanner_->cancel();
}

void EngineFacade::join_scan_worker() noexcept {
    if (scan_worker_.joinable()) scan_worker_.join();
}

void EngineFacade::clear_scan_state() noexcept {
    std::lock_guard lock(scan_mutex_);
    scan_result_.reset();
    scanner_.reset();
    scan_error_.clear();
    scan_started_.store(false, std::memory_order_release);
    scan_running_.store(false, std::memory_order_release);
    scan_cancel_requested_.store(false, std::memory_order_release);
    scan_generation_.fetch_add(1, std::memory_order_acq_rel);
}

std::unique_ptr<EngineFacade> create_engine_facade() {
    return std::make_unique<EngineFacade>();
}

} // namespace ce::bridge
