#pragma once

#include "rust/cxx.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace ce {
class AddressListController;
class MemoryScanner;
class ProcessHandle;
class ScanResult;
struct ScanConfig;
}

namespace ce::bridge {

struct ProcessRow;
struct AttachResult;
struct ScanStartResult;
struct ScanActionResult;
struct ScanRequest;
struct ScanStatus;
struct ScanPage;
struct AddressRow;
struct AddressPage;
struct AddressActionResult;
struct TableActionResult;
struct TableScriptRow;
struct TableScriptPage;
struct TableScriptTextPage;
struct LuaExecutionResult;
struct LuaConsoleResult;
struct RuntimeTickResult;

/// Stable, toolkit-neutral entry point exposed to the Rust frontend.
///
/// Keep implementation details and libcecore's template-heavy public surface on
/// the C++ side.  Only explicitly reviewed bridge-safe values belong here.
class EngineFacade {
public:
    EngineFacade();
    ~EngineFacade();

    rust::String version() const;
    rust::Vec<ProcessRow> list_processes(rust::Str query, std::uint32_t limit) const;
    AttachResult attach(std::int32_t pid, rust::Str display_name);
    AddressActionResult detach();
    bool is_attached() const noexcept;
    std::int32_t attached_pid() const noexcept;
    ScanStartResult start_first_scan(const ScanRequest& request);
    ScanStartResult start_next_scan(const ScanRequest& request);
    ScanActionResult undo_scan();
    ScanStatus scan_status() const;
    ScanPage scan_rows(std::uint64_t generation, std::uint64_t start,
                       std::uint32_t limit) const;
    void cancel_scan() noexcept;
    AddressPage address_rows(std::uint64_t start, std::uint32_t limit,
                             bool refresh_values);
    AddressPage visible_address_rows(std::uint64_t start, std::uint32_t limit,
                                     bool refresh_values);
    AddressActionResult add_scan_result(std::uint64_t scan_generation,
                                        std::uint64_t scan_index,
                                        rust::Str description);
    AddressActionResult add_address(std::uint64_t address, std::uint8_t value_type,
                                    rust::Str description, std::uint32_t byte_count,
                                    bool show_as_hex);
    AddressActionResult set_address_value(std::int32_t id, rust::Str value);
    AddressActionResult set_address_active(std::int32_t id, bool active);
    AddressActionResult set_address_freeze_mode(std::int32_t id, std::uint8_t mode);
    AddressActionResult delete_address(std::int32_t id);
    AddressActionResult add_address_group(rust::Str description);
    AddressActionResult group_addresses(rust::Slice<const std::int32_t> ids,
                                        rust::Str description);
    AddressActionResult move_address(std::int32_t id, std::int32_t direction);
    AddressActionResult set_address_collapsed(std::int32_t id, bool collapsed);
    TableActionResult load_table(rust::Str path);
    TableActionResult load_protected_table(rust::Str path, rust::Str password);
    TableActionResult save_table(rust::Str path, bool json) const;
    TableScriptPage table_scripts(std::uint64_t start,
                                  std::uint32_t limit) const;
    TableScriptTextPage table_script_text(std::int32_t record_id,
                                          std::uint8_t kind,
                                          std::uint64_t offset,
                                          std::uint32_t limit) const;
    AddressActionResult set_table_scripts_trusted(bool trusted);
    bool table_scripts_trusted() const noexcept;
    AddressActionResult set_table_lua_trusted(bool trusted);
    bool table_lua_trusted() const noexcept;
    LuaExecutionResult execute_table_lua(std::int32_t record_id,
                                         std::uint8_t kind);
    LuaConsoleResult execute_lua_console(rust::Str source);
    std::uint64_t lua_runtime_generation() const noexcept;
    RuntimeTickResult periodic_tick();

private:
    struct ScriptRuntime;

    void join_scan_worker() noexcept;
    void clear_scan_state() noexcept;
    bool deactivate_scripts(const std::vector<int>& ids, std::string& errorCode,
                            std::string& errorMessage) noexcept;
    bool deactivate_all_scripts(std::string& errorCode,
                                std::string& errorMessage) noexcept;

    std::unique_ptr<ce::ProcessHandle> process_;
    std::unique_ptr<ce::MemoryScanner> scanner_;
    std::unique_ptr<ce::ScanResult> scan_result_;
    std::unique_ptr<ce::ScanResult> undo_scan_result_;
    std::unique_ptr<ce::ScanConfig> scan_config_;
    std::unique_ptr<ce::ScanConfig> undo_scan_config_;
    std::unique_ptr<ce::AddressListController> address_list_;
    std::unique_ptr<ScriptRuntime> script_runtime_;
    bool scan_display_hex_ = false;
    bool undo_scan_display_hex_ = false;
    std::thread scan_worker_;
    mutable std::mutex scan_mutex_;
    std::string scan_error_;
    std::atomic<bool> scan_started_{false};
    std::atomic<bool> scan_running_{false};
    std::atomic<bool> scan_cancel_requested_{false};
    std::atomic<std::uint64_t> scan_generation_{0};
};

std::unique_ptr<EngineFacade> create_engine_facade();

} // namespace ce::bridge
