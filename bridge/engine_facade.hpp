#pragma once

#include "rust/cxx.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace ce {
class MemoryScanner;
class ProcessHandle;
class ScanResult;
}

namespace ce::bridge {

struct ProcessRow;
struct AttachResult;
struct ScanStartResult;
struct ScanStatus;

/// Stable, toolkit-neutral entry point exposed to the Rust frontend.
///
/// Keep implementation details and libcecore's template-heavy public surface on
/// the C++ side.  Only explicitly reviewed bridge-safe values belong here.
class EngineFacade {
public:
    EngineFacade() noexcept = default;
    ~EngineFacade();

    rust::String version() const;
    rust::Vec<ProcessRow> list_processes(rust::Str query, std::uint32_t limit) const;
    AttachResult attach(std::int32_t pid, rust::Str display_name);
    void detach() noexcept;
    bool is_attached() const noexcept;
    std::int32_t attached_pid() const noexcept;
    ScanStartResult start_first_scan_i32(std::int32_t value, std::uint64_t start_address,
                                         std::uint64_t stop_address, std::uint32_t alignment);
    ScanStatus scan_status() const;
    void cancel_scan() noexcept;

private:
    void join_scan_worker() noexcept;
    void clear_scan_state() noexcept;

    std::unique_ptr<ce::ProcessHandle> process_;
    std::unique_ptr<ce::MemoryScanner> scanner_;
    std::unique_ptr<ce::ScanResult> scan_result_;
    std::thread scan_worker_;
    mutable std::mutex scan_mutex_;
    std::string scan_error_;
    std::atomic<bool> scan_started_{false};
    std::atomic<bool> scan_running_{false};
    std::atomic<bool> scan_cancel_requested_{false};
};

std::unique_ptr<EngineFacade> create_engine_facade();

} // namespace ce::bridge
