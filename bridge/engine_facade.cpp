#include "bridge/engine_facade.hpp"

#include "ce-gtk/src/bridge.rs.h"
#include "arch/assembler.hpp"
#include "arch/disassembler.hpp"
#include "core/address_list_controller.hpp"
#include "core/autoasm.hpp"
#include "core/target_profile.hpp"
#include "core/value_transform.hpp"
#include "core/version.hpp"
#include "debug/debug_session.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"
#include "scripting/lua_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
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
constexpr std::uint32_t kDefaultMemoryViewBytes = 512;
constexpr std::uint32_t kMaxMemoryViewBytes = 4096;
constexpr std::uint32_t kDefaultDisassemblyRows = 128;
constexpr std::uint32_t kMaxDisassemblyRows = 256;
constexpr std::size_t kMaxMemoryPatternSize = 4096;
constexpr std::uint32_t kDefaultMemorySearchPageBytes = 1u << 20;
constexpr std::uint32_t kMaxMemorySearchPageBytes = 8u << 20;
constexpr std::size_t kMaxMemoryWriteSize = 4096;
constexpr std::size_t kMaxAssemblySourceSize = 4096;
constexpr std::size_t kMaxAssemblyOutputSize = 4096;
constexpr std::size_t kMaxSoftwareBreakpoints = 4096;
constexpr std::uint32_t kMaxAddressPageSize = 256;
constexpr std::size_t kMaxScanValueSize = 1u << 20;
constexpr std::size_t kMaxScanTextSize = 1u << 20;
constexpr std::size_t kMaxAddressTextSize = 1u << 20;
constexpr std::size_t kMaxAddressDescriptionSize = 1024;
constexpr std::size_t kMaxAddressGroupSelection = 4096;
constexpr std::size_t kMaxTablePathSize = 4096;
constexpr std::size_t kMaxTablePasswordSize = 4096;
constexpr std::size_t kMaxTableCompatibilityIssues = 16;
constexpr std::size_t kMaxTableCompatibilityTextSize = 2048;
constexpr std::uint32_t kMaxTableScriptPageSize = 256;
constexpr std::uint32_t kMaxTableScriptTextSize = 64u << 10;
constexpr std::size_t kMaxTableScriptDescriptionSize = 1024;
constexpr std::size_t kMaxLuaScriptSize = 1u << 20;
constexpr std::size_t kMaxLuaOutputSize = 64u << 10;
constexpr int kLuaInstructionLimit = 2'000'000;
constexpr int kLuaTimerInstructionLimit = 200'000;
constexpr std::size_t kMaxLuaTimerCallbacksPerTick = 32;
constexpr double kAddressFreezeIntervalMs = 100.0;
constexpr double kAddressRefreshIntervalMs = 500.0;

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

std::string instruction_bytes(const std::vector<std::uint8_t>& bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    if (!bytes.empty()) result.reserve(bytes.size() * 3 - 1);
    for (const auto byte : bytes) {
        if (!result.empty()) result.push_back(' ');
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 0x0f]);
    }
    return result;
}

std::uint64_t instruction_follow_target(const ce::Instruction& instruction) {
    const auto& mnemonic = instruction.mnemonic;
    const bool isBranch = mnemonic == "call" || mnemonic == "jmp" ||
        (mnemonic.size() > 1 && mnemonic.front() == 'j');
    if (isBranch && instruction.operands.find('[') == std::string::npos) {
        const auto marker = instruction.operands.find("0x");
        if (marker != std::string::npos) {
            try {
                return std::stoull(instruction.operands.substr(marker + 2), nullptr, 16);
            } catch (const std::exception&) {
                // Keep the row usable even if Capstone returned an unexpected operand.
            }
        }
    }
    return static_cast<std::uint64_t>(instruction.ripTarget);
}

std::string memory_region_description(const ce::MemoryRegion& region) {
    std::string protection;
    protection.push_back(region.protection & ce::MemProt::Read ? 'r' : '-');
    protection.push_back(region.protection & ce::MemProt::Write ? 'w' : '-');
    protection.push_back(region.protection & ce::MemProt::Exec ? 'x' : '-');
    const char* type = "private";
    if (region.type == ce::MemType::Mapped) type = "mapped";
    else if (region.type == ce::MemType::Image) type = "image";

    const auto regionEnd = region.size > std::numeric_limits<std::uintptr_t>::max() - region.base
        ? std::numeric_limits<std::uintptr_t>::max()
        : region.base + region.size;
    std::ostringstream summary;
    summary << "0x" << std::hex << std::uppercase << region.base << "–0x"
            << regionEnd << std::dec << " · " << protection
            << " · " << type;
    if (!region.path.empty()) summary << " · " << region.path;
    return summary.str();
}

std::uintptr_t memory_region_end(const ce::MemoryRegion& region) {
    return region.size > std::numeric_limits<std::uintptr_t>::max() - region.base
        ? std::numeric_limits<std::uintptr_t>::max()
        : region.base + region.size;
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

struct ParsedScanConfig {
    std::optional<ce::ScanConfig> config;
    std::string error_code;
    std::string error_message;
};

ParsedScanConfig scan_request_error(std::string code, std::string message) {
    return {.config = std::nullopt,
            .error_code = std::move(code),
            .error_message = std::move(message)};
}

std::optional<ce::ValueType> scan_value_type(std::uint8_t value) {
    if (value > 13) return std::nullopt;
    static constexpr ce::ValueType types[] = {
        ce::ValueType::Byte, ce::ValueType::Int16, ce::ValueType::Int32,
        ce::ValueType::Int64, ce::ValueType::Float, ce::ValueType::Double,
        ce::ValueType::String, ce::ValueType::UnicodeString,
        ce::ValueType::ByteArray, ce::ValueType::Binary, ce::ValueType::All,
        ce::ValueType::Pointer, ce::ValueType::Grouped, ce::ValueType::Custom,
    };
    return types[value];
}

std::optional<ce::ScanCompare> scan_comparison(std::uint8_t value) {
    if (value > 11) return std::nullopt;
    static constexpr ce::ScanCompare comparisons[] = {
        ce::ScanCompare::Exact, ce::ScanCompare::Greater, ce::ScanCompare::Less,
        ce::ScanCompare::Between, ce::ScanCompare::Unknown,
        ce::ScanCompare::Changed, ce::ScanCompare::Unchanged,
        ce::ScanCompare::Increased, ce::ScanCompare::Decreased,
        ce::ScanCompare::IncreasedBy, ce::ScanCompare::DecreasedBy,
        ce::ScanCompare::SameAsFirst,
    };
    return comparisons[value];
}

std::uint8_t bridge_value_type(ce::ValueType type) {
    switch (type) {
        case ce::ValueType::Byte: return 0;
        case ce::ValueType::Int16: return 1;
        case ce::ValueType::Int32: return 2;
        case ce::ValueType::Int64: return 3;
        case ce::ValueType::Float: return 4;
        case ce::ValueType::Double: return 5;
        case ce::ValueType::String: return 6;
        case ce::ValueType::UnicodeString: return 7;
        case ce::ValueType::ByteArray: return 8;
        case ce::ValueType::Binary: return 9;
        case ce::ValueType::All: return 10;
        case ce::ValueType::Pointer: return 11;
        case ce::ValueType::Grouped: return 12;
        case ce::ValueType::Custom: return 13;
    }
    return 2;
}

std::optional<ce::ProtMatch> protection_match(std::uint8_t value) {
    switch (value) {
        case 0: return ce::ProtMatch::Any;
        case 1: return ce::ProtMatch::Yes;
        case 2: return ce::ProtMatch::No;
        default: return std::nullopt;
    }
}

bool is_numeric_type(ce::ValueType type) {
    switch (type) {
        case ce::ValueType::Byte:
        case ce::ValueType::Int16:
        case ce::ValueType::Int32:
        case ce::ValueType::Int64:
        case ce::ValueType::Float:
        case ce::ValueType::Double:
        case ce::ValueType::Pointer:
            return true;
        default:
            return false;
    }
}

bool comparison_takes_value(ce::ScanCompare comparison) {
    return comparison == ce::ScanCompare::Exact ||
           comparison == ce::ScanCompare::Greater ||
           comparison == ce::ScanCompare::Less ||
           comparison == ce::ScanCompare::Between ||
           comparison == ce::ScanCompare::IncreasedBy ||
           comparison == ce::ScanCompare::DecreasedBy;
}

bool comparison_allowed(ce::ValueType type, ce::ScanCompare comparison, bool first) {
    if (first) {
        const bool initial = comparison == ce::ScanCompare::Exact ||
                             comparison == ce::ScanCompare::Greater ||
                             comparison == ce::ScanCompare::Less ||
                             comparison == ce::ScanCompare::Between ||
                             comparison == ce::ScanCompare::Unknown;
        if (!initial) return false;
        if (is_numeric_type(type) || type == ce::ValueType::All) return true;
        return comparison == ce::ScanCompare::Exact ||
               comparison == ce::ScanCompare::Unknown;
    }

    if (is_numeric_type(type)) return true;
    if (type == ce::ValueType::All)
        return comparison == ce::ScanCompare::Unknown ||
               comparison == ce::ScanCompare::Changed ||
               comparison == ce::ScanCompare::Unchanged ||
               comparison == ce::ScanCompare::SameAsFirst;
    return comparison == ce::ScanCompare::Exact ||
           comparison == ce::ScanCompare::Unknown ||
           comparison == ce::ScanCompare::Changed ||
           comparison == ce::ScanCompare::Unchanged ||
           comparison == ce::ScanCompare::SameAsFirst;
}

bool parse_double_value(std::string text, double& value) {
    if (text.find('.') == std::string::npos)
        std::replace(text.begin(), text.end(), ',', '.');
    errno = 0;
    char* end = nullptr;
    value = std::strtod(text.c_str(), &end);
    return end != text.c_str() && *end == '\0' && errno != ERANGE &&
           std::isfinite(value);
}

int decimal_places(const std::string& text) {
    auto separator = text.find_first_of(".,");
    if (separator == std::string::npos) return 0;
    int count = 0;
    for (std::size_t index = separator + 1;
         index < text.size() && std::isdigit(static_cast<unsigned char>(text[index]));
         ++index)
        ++count;
    return count;
}

std::size_t scan_value_size(const ce::ScanConfig& config) {
    switch (config.valueType) {
        case ce::ValueType::Byte: return 1;
        case ce::ValueType::Int16: return 2;
        case ce::ValueType::Int32:
        case ce::ValueType::Float: return 4;
        case ce::ValueType::Int64:
        case ce::ValueType::Double:
        case ce::ValueType::All: return 8;
        case ce::ValueType::Pointer: return sizeof(std::uintptr_t);
        case ce::ValueType::String: return config.stringValueSize();
        case ce::ValueType::UnicodeString: return config.stringValue.size() * 2;
        case ce::ValueType::ByteArray:
        case ce::ValueType::Binary: return config.byteArray.size();
        case ce::ValueType::Grouped: return config.groupedValueSize();
        case ce::ValueType::Custom: return config.customValueSize;
    }
    return 0;
}

void inherit_variable_shape(ce::ScanConfig& config, const ce::ScanConfig& baseline) {
    switch (config.valueType) {
        case ce::ValueType::String:
        case ce::ValueType::UnicodeString:
            config.stringValue = baseline.stringValue;
            config.stringEncoding = baseline.stringEncoding;
            break;
        case ce::ValueType::ByteArray:
            config.byteArray = baseline.byteArray;
            config.byteArrayMask = baseline.byteArrayMask;
            break;
        case ce::ValueType::Binary:
            config.byteArray = baseline.byteArray;
            config.byteMask = baseline.byteMask;
            break;
        case ce::ValueType::Grouped:
            config.groupedTerms = baseline.groupedTerms;
            config.groupedExpression = baseline.groupedExpression;
            break;
        case ce::ValueType::Custom:
            config.customValueSize = baseline.customValueSize;
            config.customFormula = baseline.customFormula;
            break;
        default:
            break;
    }
}

ParsedScanConfig parse_scan_request(const ScanRequest& request, bool first,
                                    const ce::ScanConfig* baseline) {
    const auto type = scan_value_type(request.value_type);
    if (!type)
        return scan_request_error("invalid_value_type", "The scan value type is not supported.");
    const auto comparison = scan_comparison(request.comparison);
    if (!comparison)
        return scan_request_error("invalid_comparison", "The scan comparison is not supported.");
    const auto writable = protection_match(request.writable_match);
    const auto executable = protection_match(request.executable_match);
    if (!writable || !executable)
        return scan_request_error("invalid_protection_filter", "A protection filter is invalid.");
    if (!comparison_allowed(*type, *comparison, first))
        return scan_request_error(
            "unsupported_comparison",
            "That comparison is not meaningful for the selected value type and scan stage.");
    if (!first && (!baseline || baseline->valueType != *type))
        return scan_request_error(
            "value_type_changed",
            "Next Scan must use the same value type as the current result set.");
    if (request.value.size() > kMaxScanTextSize || request.value2.size() > kMaxScanTextSize)
        return scan_request_error("value_too_large", "The scan value is too large.");
    if (request.alignment == 0 || request.alignment > 4096)
        return scan_request_error(
            "invalid_alignment", "Scan alignment must be between 1 and 4096 bytes.");
    if (first && request.start_address >= request.stop_address)
        return scan_request_error(
            "invalid_range", "The scan start address must be below the stop address.");
    if (first && !request.scan_private && !request.scan_image && !request.scan_mapped)
        return scan_request_error(
            "no_region_types", "Enable at least one memory region type to scan.");
    if (request.rounding_type < 0 || request.rounding_type > 3 ||
        request.float_decimals < -1 || request.float_decimals > 100 ||
        !std::isfinite(request.float_tolerance) || request.float_tolerance < 0.0)
        return scan_request_error("invalid_float_options", "The floating-point options are invalid.");
    if (request.value_size > kMaxScanValueSize)
        return scan_request_error("value_too_large", "The requested value width is too large.");

    ce::ScanConfig config;
    config.valueType = *type;
    config.compareType = *comparison;
    config.alignment = request.alignment;
    config.startAddress = static_cast<std::uintptr_t>(std::min<std::uint64_t>(
        request.start_address, std::numeric_limits<std::uintptr_t>::max()));
    config.stopAddress = static_cast<std::uintptr_t>(std::min<std::uint64_t>(
        request.stop_address, std::numeric_limits<std::uintptr_t>::max()));
    config.writableMatch = *writable;
    config.executableMatch = *executable;
    config.scanPrivate = request.scan_private;
    config.scanImage = request.scan_image;
    config.scanMapped = request.scan_mapped;
    config.roundingType = request.rounding_type;
    config.floatDecimals = request.float_decimals;
    config.floatTolerance = request.float_tolerance;
    config.percentageScan = request.percentage_scan;
    config.percentageValue = request.percentage_value;
    config.percentageValue2 = request.percentage_value2;
    config.caseSensitive = request.case_sensitive;
    config.stringEncoding = request.string_encoding.empty()
        ? "UTF-8" : std::string(request.string_encoding);
    config.customValueSize = request.value_size;

    const std::string value(request.value);
    const std::string value2(request.value2);
    const bool takes_value = comparison_takes_value(*comparison);
    if (!first && !takes_value && baseline) inherit_variable_shape(config, *baseline);

    auto parse_integer = [&](const std::string& text, std::int64_t& destination,
                             const char* label) -> std::optional<ParsedScanConfig> {
        bool ok = false;
        destination = ce::parseIntegerScalar(text, request.hexadecimal, ok);
        if (!ok)
            return scan_request_error("invalid_integer", std::string(label) +
                " must be a valid integer.");
        return std::nullopt;
    };
    auto parse_float = [&](const std::string& text, double& destination,
                           const char* label) -> std::optional<ParsedScanConfig> {
        if (!parse_double_value(text, destination))
            return scan_request_error("invalid_float", std::string(label) +
                " must be a valid floating-point number.");
        return std::nullopt;
    };

    if (takes_value && value.empty())
        return scan_request_error("value_required", "This comparison requires a scan value.");
    if (*comparison == ce::ScanCompare::Between && value2.empty())
        return scan_request_error("second_value_required", "Between requires a second value.");

    switch (*type) {
        case ce::ValueType::Byte:
        case ce::ValueType::Int16:
        case ce::ValueType::Int32:
        case ce::ValueType::Int64:
        case ce::ValueType::Pointer:
            if (takes_value) {
                if (auto error = parse_integer(value, config.intValue, "Value")) return *error;
                if (*comparison == ce::ScanCompare::Between)
                    if (auto error = parse_integer(value2, config.intValue2, "Second value"))
                        return *error;
            }
            break;
        case ce::ValueType::Float:
        case ce::ValueType::Double:
            if (takes_value) {
                if (auto error = parse_float(value, config.floatValue, "Value")) return *error;
                if (*comparison == ce::ScanCompare::Between)
                    if (auto error = parse_float(value2, config.floatValue2, "Second value"))
                        return *error;
                if (config.floatDecimals < 0) config.floatDecimals = decimal_places(value);
            }
            break;
        case ce::ValueType::All:
            if (takes_value) {
                bool integer_ok = false;
                config.intValue = ce::parseIntegerScalar(value, request.hexadecimal, integer_ok);
                if (request.hexadecimal) {
                    if (!integer_ok)
                        return scan_request_error(
                            "invalid_integer", "Value must be a valid hexadecimal integer.");
                    config.floatValue = static_cast<double>(config.intValue);
                } else {
                    if (auto error = parse_float(value, config.floatValue, "Value")) return *error;
                    if (!integer_ok) config.intValue = static_cast<std::int64_t>(config.floatValue);
                }
                if (*comparison == ce::ScanCompare::Between) {
                    config.intValue2 = ce::parseIntegerScalar(
                        value2, request.hexadecimal, integer_ok);
                    if (request.hexadecimal) {
                        if (!integer_ok)
                            return scan_request_error(
                                "invalid_integer",
                                "Second value must be a valid hexadecimal integer.");
                        config.floatValue2 = static_cast<double>(config.intValue2);
                    } else {
                        if (auto error = parse_float(value2, config.floatValue2, "Second value"))
                            return *error;
                        if (!integer_ok)
                            config.intValue2 = static_cast<std::int64_t>(config.floatValue2);
                    }
                }
            }
            break;
        case ce::ValueType::String:
            config.alignment = 1;
            if (takes_value) {
                if (value.empty())
                    return scan_request_error("value_required", "String scans require text.");
                config.stringValue = value;
            } else if (first) {
                const auto width = request.value_size != 0 ? request.value_size : value.size();
                if (width == 0)
                    return scan_request_error(
                        "value_size_required", "Unknown string scans require a byte width.");
                config.stringValue.assign(width, '\0');
            }
            break;
        case ce::ValueType::UnicodeString:
            config.alignment = 1;
            if (takes_value) {
                if (value.empty())
                    return scan_request_error("value_required", "Unicode scans require text.");
                config.stringValue = value;
            } else if (first) {
                const auto width = request.value_size != 0 ? request.value_size : value.size() * 2;
                if (width == 0 || width % 2 != 0)
                    return scan_request_error(
                        "invalid_value_size", "Unknown Unicode scans require an even byte width.");
                config.stringValue.assign(width / 2, '\0');
            }
            break;
        case ce::ValueType::ByteArray:
            config.alignment = 1;
            if (takes_value) {
                if (!config.parseAOB(value))
                    return scan_request_error(
                        "invalid_byte_array", "Enter bytes and wildcards such as '7F 45 ?? 46'.");
            } else if (first) {
                if (request.value_size == 0)
                    return scan_request_error(
                        "value_size_required", "Unknown byte-array scans require a byte width.");
                config.byteArray.assign(request.value_size, 0);
                config.byteArrayMask.assign(request.value_size, 0);
            }
            break;
        case ce::ValueType::Binary:
            config.alignment = 1;
            if (takes_value) {
                config.parseBinary(value);
                if (config.byteArray.empty())
                    return scan_request_error(
                        "invalid_binary", "Enter a binary pattern such as '0110??01'.");
            } else if (first) {
                if (request.value_size == 0)
                    return scan_request_error(
                        "value_size_required", "Unknown binary scans require a byte width.");
                config.byteArray.assign(request.value_size, 0);
                config.byteMask.assign(request.value_size, 0);
            }
            break;
        case ce::ValueType::Grouped: {
            config.alignment = 1;
            if (first || takes_value) {
                std::string error;
                if (!config.parseGrouped(value, &error))
                    return scan_request_error("invalid_grouped", error);
            }
            break;
        }
        case ce::ValueType::Custom:
            config.alignment = 1;
            if (config.customValueSize == 0 && baseline)
                config.customValueSize = baseline->customValueSize;
            if (config.customValueSize == 0)
                return scan_request_error(
                    "value_size_required", "Custom scans require a value width.");
            if (takes_value) {
                if (value.empty())
                    return scan_request_error(
                        "value_required", "Exact custom scans require a Lua formula.");
                config.customFormula = value;
            }
            break;
    }

    if (request.percentage_scan) {
        const bool supported = !first && is_numeric_type(*type) &&
            (*comparison == ce::ScanCompare::Greater || *comparison == ce::ScanCompare::Less ||
             *comparison == ce::ScanCompare::Between ||
             *comparison == ce::ScanCompare::Increased ||
             *comparison == ce::ScanCompare::Decreased);
        if (!supported || !std::isfinite(request.percentage_value) ||
            !std::isfinite(request.percentage_value2))
            return scan_request_error(
                "invalid_percentage_scan",
                "Percentage mode requires a supported numeric Next Scan comparison.");
    }

    std::size_t width = 0;
    try {
        width = scan_value_size(config);
    } catch (const std::exception& error) {
        return scan_request_error("invalid_string_encoding", error.what());
    }
    if (width == 0 || width > kMaxScanValueSize)
        return scan_request_error("invalid_value_size", "The scan value width is invalid.");
    if (!first && baseline && width != scan_value_size(*baseline))
        return scan_request_error(
            "value_size_changed", "Next Scan cannot change the persisted value width.");

    return {.config = std::move(config), .error_code = {}, .error_message = {}};
}

void append_utf8(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7f) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ff) {
        output.push_back(static_cast<char>(0xc0 | (codepoint >> 6)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else if (codepoint <= 0xffff) {
        output.push_back(static_cast<char>(0xe0 | (codepoint >> 12)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    } else {
        output.push_back(static_cast<char>(0xf0 | (codepoint >> 18)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 12) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | ((codepoint >> 6) & 0x3f)));
        output.push_back(static_cast<char>(0x80 | (codepoint & 0x3f)));
    }
}

std::string sanitize_utf8(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (std::size_t index = 0; index < input.size();) {
        const auto lead = static_cast<std::uint8_t>(input[index]);
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        std::uint32_t minimum = 0;
        if (lead < 0x80) {
            if (lead == 0)
                append_utf8(output, 0xfffd);
            else
                output.push_back(static_cast<char>(lead));
            ++index;
            continue;
        } else if ((lead & 0xe0) == 0xc0) {
            length = 2;
            codepoint = lead & 0x1f;
            minimum = 0x80;
        } else if ((lead & 0xf0) == 0xe0) {
            length = 3;
            codepoint = lead & 0x0f;
            minimum = 0x800;
        } else if ((lead & 0xf8) == 0xf0) {
            length = 4;
            codepoint = lead & 0x07;
            minimum = 0x10000;
        }

        bool valid = length != 0 && index + length <= input.size();
        for (std::size_t offset = 1; valid && offset < length; ++offset) {
            const auto continuation = static_cast<std::uint8_t>(input[index + offset]);
            valid = (continuation & 0xc0) == 0x80;
            if (valid) codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        valid = valid && codepoint >= minimum && codepoint <= 0x10ffff &&
                !(codepoint >= 0xd800 && codepoint <= 0xdfff);
        if (valid) {
            output.append(input, index, length);
            index += length;
        } else {
            append_utf8(output, 0xfffd);
            ++index;
        }
    }
    return output;
}

std::string bounded_utf8(std::string value, std::size_t limit,
                         bool* truncated = nullptr) {
    if (value.size() <= limit) return value;
    std::size_t prefix = limit;
    while (prefix > 0 && prefix < value.size() &&
           (static_cast<unsigned char>(value[prefix]) & 0xc0) == 0x80)
        --prefix;
    value.resize(prefix);
    if (truncated) *truncated = true;
    return value;
}

std::string format_utf16le(const std::uint8_t* bytes, std::size_t size) {
    std::string output;
    for (std::size_t offset = 0; offset + 1 < size; offset += 2) {
        const auto unit = static_cast<std::uint16_t>(bytes[offset]) |
                          (static_cast<std::uint16_t>(bytes[offset + 1]) << 8);
        if (unit == 0) break;
        std::uint32_t codepoint = unit;
        if (unit >= 0xd800 && unit <= 0xdbff && offset + 3 < size) {
            const auto low = static_cast<std::uint16_t>(bytes[offset + 2]) |
                             (static_cast<std::uint16_t>(bytes[offset + 3]) << 8);
            if (low >= 0xdc00 && low <= 0xdfff) {
                codepoint = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                offset += 2;
            } else {
                codepoint = 0xfffd;
            }
        } else if (unit >= 0xd800 && unit <= 0xdfff) {
            codepoint = 0xfffd;
        }
        append_utf8(output, codepoint);
    }
    return output;
}

std::string format_scan_value(const ce::ScanConfig& config, bool display_hex,
                              const std::uint8_t* bytes, std::size_t size) {
    switch (config.valueType) {
        case ce::ValueType::Byte:
        case ce::ValueType::Int16:
        case ce::ValueType::Int32:
        case ce::ValueType::Int64: {
            const auto width = static_cast<std::size_t>(ce::scalarWidth(config.valueType));
            if (size < width) return "?";
            std::uint64_t bits = 0;
            std::memcpy(&bits, bytes, width);
            return ce::formatIntegerScalar(bits, static_cast<int>(width), true, display_hex);
        }
        case ce::ValueType::Pointer: {
            if (size < sizeof(std::uintptr_t)) return "?";
            std::uintptr_t value = 0;
            std::memcpy(&value, bytes, sizeof value);
            return ce::formatIntegerScalar(value, sizeof value, false, true);
        }
        case ce::ValueType::Float: {
            if (size < sizeof(float)) return "?";
            float value = 0;
            std::memcpy(&value, bytes, sizeof value);
            return ce::formatFloatScalar(value, false);
        }
        case ce::ValueType::Double: {
            if (size < sizeof(double)) return "?";
            double value = 0;
            std::memcpy(&value, bytes, sizeof value);
            return ce::formatFloatScalar(value, true);
        }
        case ce::ValueType::String: {
            const auto length = strnlen(reinterpret_cast<const char*>(bytes), size);
            return sanitize_utf8(
                ce::decodeStringBytes(bytes, length, config.stringEncoding));
        }
        case ce::ValueType::UnicodeString:
            return format_utf16le(bytes, size);
        default: {
            static constexpr char digits[] = "0123456789ABCDEF";
            std::string output;
            output.reserve(size == 0 ? 0 : size * 3 - 1);
            for (std::size_t index = 0; index < size; ++index) {
                if (index != 0) output.push_back(' ');
                output.push_back(digits[bytes[index] >> 4]);
                output.push_back(digits[bytes[index] & 0x0f]);
            }
            return output;
        }
    }
}

rust::Vec<TableCompatibilityIssueRow> table_compatibility_rows(
    const std::vector<ce::TableCompatibilityIssue>& issues) {
    rust::Vec<TableCompatibilityIssueRow> rows;
    const auto limit = std::min(issues.size(), kMaxTableCompatibilityIssues);
    rows.reserve(limit);
    for (std::size_t index = 0; index < limit; ++index) {
        const auto& issue = issues[index];
        rows.push_back(TableCompatibilityIssueRow{
            .code = bounded_utf8(sanitize_utf8(issue.code),
                                 kMaxTableCompatibilityTextSize),
            .title = bounded_utf8(sanitize_utf8(issue.title),
                                  kMaxTableCompatibilityTextSize),
            .detail = bounded_utf8(sanitize_utf8(issue.detail),
                                   kMaxTableCompatibilityTextSize),
            .count = static_cast<std::uint64_t>(issue.count),
            .preserved = issue.preserved,
        });
    }
    return rows;
}

} // namespace

struct EngineFacade::ScriptRuntime {
    struct OutputBuffer {
        std::string text;
        bool truncated = false;

        void append(const std::string& line) {
            if (truncated) return;
            std::string safe = sanitize_utf8(line);
            if (!text.empty()) safe.insert(safe.begin(), '\n');
            const auto available = kMaxLuaOutputSize - text.size();
            if (safe.size() <= available) {
                text += safe;
                return;
            }
            text += bounded_utf8(std::move(safe), available);
            truncated = true;
        }
    };

    ce::AutoAssembler assembler;
    std::unordered_map<int, ce::DisableInfo> disableInfoById;
    std::vector<int> activationOrder;
    std::unique_ptr<ce::LuaEngine> lua;
    OutputBuffer* activeOutput = nullptr;
    OutputBuffer pendingOutput;
    std::uint64_t luaGeneration = 0;
    double lastFreezeMs = 0;
    double lastRefreshMs = 0;
    bool autoAssemblerTrusted = false;
    bool luaTrusted = false;

    void appendLuaOutput(const std::string& line) {
        (activeOutput ? *activeOutput : pendingOutput).append(line);
    }

    OutputBuffer takePendingOutput() {
        OutputBuffer output = std::move(pendingOutput);
        pendingOutput = {};
        return output;
    }

    void resetLua(ce::ProcessHandle* process,
                  ce::AddressListController* addressList) {
        activeOutput = nullptr;
        auto replacement = std::make_unique<ce::LuaEngine>();
        replacement->setProcess(process);
        replacement->setOutputCallback([this](const std::string& line) {
            appendLuaOutput(line);
        });

        // AddressListController stores one borrowed activation dispatcher. Detach
        // the previous owner before installing the replacement, but restore it if
        // the new callback allocation fails so a reset never leaves a null runtime.
        auto previous = std::move(lua);
        if (previous) previous->setAddressList(nullptr);
        try {
            replacement->setAddressList(addressList);
        } catch (...) {
            replacement->setAddressList(nullptr);
            lua = std::move(previous);
            if (lua) lua->setAddressList(addressList);
            throw;
        }
        lua = std::move(replacement);
        pendingOutput = {};
        ++luaGeneration;
    }
};

struct EngineFacade::DebugRuntime {
    struct SoftwareBreakpoint {
        int id = 0;
        std::uint8_t original_byte = 0;
    };

    std::unique_ptr<ce::DebugSession> session;
    std::unordered_map<std::uintptr_t, SoftwareBreakpoint> software_breakpoints;
    mutable std::mutex mutex;
    std::uint64_t event_serial = 0;
    std::uintptr_t event_address = 0;
    pid_t event_tid = 0;
    int event_signal = 0;
    std::uint8_t event_type = 0;
    bool exited = false;
};

EngineFacade::EngineFacade()
    : address_list_(std::make_unique<ce::AddressListController>()),
      script_runtime_(std::make_unique<ScriptRuntime>()),
      debug_runtime_(std::make_unique<DebugRuntime>()) {
    script_runtime_->resetLua(nullptr, address_list_.get());
}

EngineFacade::~EngineFacade() {
    cancel_scan();
    join_scan_worker();
    stop_debug_session();
    std::string ignoredCode;
    std::string ignoredMessage;
    deactivate_all_scripts(ignoredCode, ignoredMessage);
    address_list_->setProcess(nullptr);
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
            std::string scriptErrorCode;
            std::string scriptErrorMessage;
            if (!deactivate_all_scripts(scriptErrorCode, scriptErrorMessage)) {
                result.error_code = scriptErrorCode;
                result.error_message = scriptErrorMessage;
                return result;
            }
            stop_debug_session();
            script_runtime_->resetLua(nullptr, address_list_.get());
            clear_scan_state();
            process_ = std::move(candidate);
            address_list_->setProcess(process_.get());
            script_runtime_->lua->setProcess(process_.get());
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

AddressActionResult EngineFacade::detach() {
    cancel_scan();
    join_scan_worker();
    clear_scan_state();
    stop_debug_session();
    std::string scriptErrorCode;
    std::string scriptErrorMessage;
    if (!deactivate_all_scripts(scriptErrorCode, scriptErrorMessage)) {
        return AddressActionResult{
            .accepted = false,
            .id = 0,
            .error_code = scriptErrorCode,
            .error_message = scriptErrorMessage,
        };
    }
    script_runtime_->resetLua(nullptr, address_list_.get());
    address_list_->setProcess(nullptr);
    process_.reset();
    script_runtime_->disableInfoById.clear();
    script_runtime_->activationOrder.clear();
    return AddressActionResult{
        .accepted = true, .id = 0, .error_code = {}, .error_message = {}};
}

bool EngineFacade::is_attached() const noexcept {
    return process_ != nullptr;
}

std::int32_t EngineFacade::attached_pid() const noexcept {
    return process_ ? static_cast<std::int32_t>(process_->pid()) : 0;
}

ScanStartResult EngineFacade::start_first_scan(const ScanRequest& request) {
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
    auto parsed = parse_scan_request(request, true, nullptr);
    if (!parsed.config) {
        response.error_code = parsed.error_code;
        response.error_message = parsed.error_message;
        return response;
    }

    join_scan_worker();
    {
        std::lock_guard lock(scan_mutex_);
        scan_result_.reset();
        undo_scan_result_.reset();
        scan_config_.reset();
        undo_scan_config_.reset();
        scan_error_.clear();
        scan_generation_.fetch_add(1, std::memory_order_acq_rel);
    }
    scanner_ = std::make_unique<ce::MemoryScanner>();
    scan_cancel_requested_.store(false, std::memory_order_release);
    scan_started_.store(true, std::memory_order_release);
    scan_running_.store(true, std::memory_order_release);

    auto config = std::move(*parsed.config);
    const bool display_hex = request.hexadecimal;

    auto* const target = process_.get();
    scan_worker_ = std::thread([this, target, config = std::move(config), display_hex] {
        try {
            auto result = std::make_unique<ce::ScanResult>(scanner_->firstScan(*target, config));
            std::lock_guard lock(scan_mutex_);
            if (!scan_cancel_requested_.load(std::memory_order_acquire)) {
                scan_result_ = std::move(result);
                scan_config_ = std::make_unique<ce::ScanConfig>(config);
                scan_display_hex_ = display_hex;
            }
            scan_running_.store(false, std::memory_order_release);
        } catch (const std::exception& error) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = error.what();
            scan_running_.store(false, std::memory_order_release);
        } catch (...) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = "Unknown scanner failure.";
            scan_running_.store(false, std::memory_order_release);
        }
    });

    // firstScan() resets its reusable cancellation flag on entry. Do not return
    // control (and expose Cancel in GTK) until that reset has happened, otherwise
    // an immediate cancel could be overwritten by the worker a moment later.
    while (scan_running_.load(std::memory_order_acquire) && !scanner_->running())
        std::this_thread::yield();

    response.accepted = true;
    return response;
}

ScanStartResult EngineFacade::start_next_scan(const ScanRequest& request) {
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
    join_scan_worker();

    ce::ScanResult* previous = nullptr;
    ce::ScanConfig baseline;
    {
        std::lock_guard lock(scan_mutex_);
        if (!scan_result_ || !scan_config_) {
            response.error_code = "no_scan_result";
            response.error_message = "Run a First Scan before a Next Scan.";
            return response;
        }
        previous = scan_result_.get();
        baseline = *scan_config_;
    }

    auto parsed = parse_scan_request(request, false, &baseline);
    if (!parsed.config) {
        response.error_code = parsed.error_code;
        response.error_message = parsed.error_message;
        return response;
    }
    {
        std::lock_guard lock(scan_mutex_);
        scan_error_.clear();
        scan_generation_.fetch_add(1, std::memory_order_acq_rel);
    }

    scanner_ = std::make_unique<ce::MemoryScanner>();
    scan_cancel_requested_.store(false, std::memory_order_release);
    scan_started_.store(true, std::memory_order_release);
    scan_running_.store(true, std::memory_order_release);

    auto config = std::move(*parsed.config);
    const bool display_hex = request.hexadecimal;

    auto* const target = process_.get();
    scan_worker_ = std::thread(
        [this, target, previous, config = std::move(config), display_hex] {
        try {
            auto result = std::make_unique<ce::ScanResult>(
                scanner_->nextScan(*target, config, *previous));
            std::lock_guard lock(scan_mutex_);
            if (!scan_cancel_requested_.load(std::memory_order_acquire)) {
                undo_scan_result_ = std::move(scan_result_);
                scan_result_ = std::move(result);
                undo_scan_config_ = std::move(scan_config_);
                scan_config_ = std::make_unique<ce::ScanConfig>(config);
                undo_scan_display_hex_ = scan_display_hex_;
                scan_display_hex_ = display_hex;
            }
            scan_running_.store(false, std::memory_order_release);
        } catch (const std::exception& error) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = error.what();
            scan_running_.store(false, std::memory_order_release);
        } catch (...) {
            std::lock_guard lock(scan_mutex_);
            scan_error_ = "Unknown scanner failure.";
            scan_running_.store(false, std::memory_order_release);
        }
    });

    while (scan_running_.load(std::memory_order_acquire) && !scanner_->running())
        std::this_thread::yield();

    response.accepted = true;
    return response;
}

ScanActionResult EngineFacade::undo_scan() {
    ScanActionResult response;
    response.accepted = false;
    response.generation = scan_generation_.load(std::memory_order_acquire);
    response.result_count = 0;
    response.undo_available = false;
    response.error_code = "";
    response.error_message = "";

    if (scan_running_.load(std::memory_order_acquire)) {
        response.error_code = "scan_in_progress";
        response.error_message = "Cancel or finish the current scan before undoing it.";
        return response;
    }
    join_scan_worker();

    std::lock_guard lock(scan_mutex_);
    if (!undo_scan_result_ || !undo_scan_config_) {
        response.error_code = "nothing_to_undo";
        response.error_message = "There is no previous scan result to restore.";
        return response;
    }
    std::swap(scan_result_, undo_scan_result_);
    std::swap(scan_config_, undo_scan_config_);
    std::swap(scan_display_hex_, undo_scan_display_hex_);
    scan_error_.clear();
    response.generation = scan_generation_.fetch_add(1, std::memory_order_acq_rel) + 1;
    response.result_count = static_cast<std::uint64_t>(scan_result_->count());
    response.undo_available = undo_scan_result_ != nullptr;
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
    status.result_available = false;
    status.undo_available = false;
    status.error_message = "";

    std::lock_guard lock(scan_mutex_);
    status.error_message = scan_error_;
    status.cancelled = status.started && !status.running && status.cancel_requested;
    status.completed = status.started && !status.running && !status.cancelled &&
                       scan_error_.empty() && scan_result_ != nullptr &&
                       scan_config_ != nullptr;
    status.result_available = scan_result_ != nullptr && scan_config_ != nullptr;
    status.undo_available = undo_scan_result_ != nullptr && undo_scan_config_ != nullptr;
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
    if (!scan_result_ || !scan_config_) {
        page.error_message = "No completed scan result is available.";
        return page;
    }

    page.total_count = static_cast<std::uint64_t>(scan_result_->count());
    page.start = std::min<std::uint64_t>(start, page.total_count);
    const auto bounded_start = static_cast<std::size_t>(std::min<std::uint64_t>(
        page.start, std::numeric_limits<std::size_t>::max()));
    const auto bounded_limit = static_cast<std::size_t>(std::min(limit, kMaxScanPageSize));
    const auto value_size = scan_value_size(*scan_config_);
    scan_result_->forRange(
        bounded_start, bounded_limit,
        [this, &page](std::uintptr_t address, const void* bytes, std::size_t size) {
            page.rows.push_back(ScanHit{
                .address = static_cast<std::uint64_t>(address),
                .value = format_scan_value(
                    *scan_config_, scan_display_hex_,
                    static_cast<const std::uint8_t*>(bytes), size),
            });
        },
        value_size);
    return page;
}

MemoryViewResult EngineFacade::memory_view(std::uint64_t address,
                                           std::uint32_t byte_count,
                                           std::uint32_t instruction_limit) const {
    MemoryViewResult result;
    result.accepted = false;
    result.address = address;
    result.next_address = address;
    result.arch = "unknown";
    result.region = "";
    result.error_code = "";
    result.error_message = "";

    if (!process_) {
        result.error_code = "no_session";
        result.error_message = "Attach to a process before opening Memory View.";
        return result;
    }
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (address > std::numeric_limits<std::uintptr_t>::max()) {
            result.error_code = "address_out_of_range";
            result.error_message = "The requested address does not fit this host architecture.";
            return result;
        }
    }

    auto target = static_cast<std::uintptr_t>(address);
    if (address == 0) {
        const auto regions = process_->queryRegions();
        const auto usable = [](const ce::MemoryRegion& candidate) {
            return candidate.size > 0 && (candidate.protection & ce::MemProt::Read);
        };
        auto selected = std::find_if(regions.begin(), regions.end(), [&](const auto& candidate) {
            return usable(candidate) && (candidate.protection & ce::MemProt::Exec);
        });
        if (selected == regions.end())
            selected = std::find_if(regions.begin(), regions.end(), usable);
        if (selected == regions.end()) {
            result.error_code = "no_readable_memory";
            result.error_message = "The attached process has no readable memory regions.";
            return result;
        }
        target = selected->base;
        result.address = static_cast<std::uint64_t>(target);
    }
    const auto region = process_->queryRegion(target);
    if (!region || target < region->base || region->size == 0) {
        result.error_code = "address_unmapped";
        result.error_message = "The requested address is not inside a mapped memory region.";
        return result;
    }
    if (!(region->protection & ce::MemProt::Read)) {
        result.error_code = "region_unreadable";
        result.error_message = "The requested memory region is not readable.";
        return result;
    }

    const auto offset = target - region->base;
    if (offset >= region->size) {
        result.error_code = "address_unmapped";
        result.error_message = "The requested address is outside the mapped memory region.";
        return result;
    }
    const auto requested = static_cast<std::size_t>(std::min(
        byte_count == 0 ? kDefaultMemoryViewBytes : byte_count,
        kMaxMemoryViewBytes));
    const auto readable = std::min<std::size_t>(requested, region->size - offset);
    if (readable == 0) {
        result.error_code = "empty_region";
        result.error_message = "There are no readable bytes at the requested address.";
        return result;
    }

    std::vector<std::uint8_t> bytes(readable);
    const auto read = process_->read(target, bytes.data(), bytes.size());
    if (!read || *read == 0) {
        result.error_code = "memory_read_failed";
        result.error_message = read
            ? "The process returned an empty memory read."
            : "Could not read process memory: " + read.error().message() + ".";
        return result;
    }
    bytes.resize(*read);

    // Keep the viewer faithful to the target's real instruction stream. ptrace
    // software breakpoints replace one byte with INT3; expose the captured
    // original byte to disassembly/hex while marking the row separately.
    std::unordered_map<std::uintptr_t, std::uint8_t> activeBreakpoints;
    if (debug_runtime_) {
        std::lock_guard lock(debug_runtime_->mutex);
        for (const auto& [breakpointAddress, breakpoint] :
             debug_runtime_->software_breakpoints) {
            activeBreakpoints.emplace(
                breakpointAddress, breakpoint.original_byte);
        }
    }
    for (const auto& [breakpointAddress, originalByte] : activeBreakpoints) {
        if (breakpointAddress >= target &&
            breakpointAddress - target < bytes.size()) {
            bytes[breakpointAddress - target] = originalByte;
        }
    }

    const bool code32 = process_->runs32BitCode();
    result.arch = code32 ? "x86-32" : "x86-64";
    result.region = sanitize_utf8(memory_region_description(*region));
    for (const auto byte : bytes) result.bytes.push_back(byte);

    const auto maxRows = static_cast<std::size_t>(std::min(
        instruction_limit == 0 ? kDefaultDisassemblyRows : instruction_limit,
        kMaxDisassemblyRows));
    try {
        ce::Disassembler disassembler(code32 ? ce::Arch::X86_32 : ce::Arch::X86_64);
        for (const auto& instruction : disassembler.disassemble(
                 target, {bytes.data(), bytes.size()}, maxRows, true)) {
            result.instructions.push_back(DisassemblyRow{
                .address = static_cast<std::uint64_t>(instruction.address),
                .bytes = instruction_bytes(instruction.bytes),
                .mnemonic = instruction.mnemonic,
                .operands = instruction.operands,
                .size = instruction.size,
                .follow_target = instruction_follow_target(instruction),
                .breakpoint = activeBreakpoints.contains(instruction.address),
            });
        }
    } catch (const std::exception& error) {
        result.error_code = "disassembly_failed";
        result.error_message = "Could not initialize the disassembler: " +
            std::string(error.what());
        return result;
    }

    result.next_address = bytes.size() >
            std::numeric_limits<std::uint64_t>::max() - result.address
        ? std::numeric_limits<std::uint64_t>::max()
        : result.address + static_cast<std::uint64_t>(bytes.size());
    result.accepted = true;
    return result;
}

MemorySearchResult EngineFacade::memory_search(
        rust::Slice<const std::uint8_t> pattern,
        rust::Slice<const std::uint8_t> mask,
        std::uint64_t start,
        bool backward,
        std::uint32_t page_bytes) const {
    MemorySearchResult result;
    result.accepted = false;
    result.found = false;
    result.complete = false;
    result.address = 0;
    result.next_address = 0;
    result.scanned_bytes = 0;
    result.error_code = "";
    result.error_message = "";

    if (!process_) {
        result.error_code = "no_session";
        result.error_message = "Attach to a process before searching memory.";
        return result;
    }
    if (pattern.empty()) {
        result.error_code = "empty_pattern";
        result.error_message = "The memory search pattern cannot be empty.";
        return result;
    }
    if (pattern.size() > kMaxMemoryPatternSize) {
        result.error_code = "pattern_too_large";
        result.error_message = "Memory search patterns are limited to 4096 bytes.";
        return result;
    }
    if (!mask.empty() && mask.size() != pattern.size()) {
        result.error_code = "invalid_mask";
        result.error_message = "The wildcard mask must match the pattern length.";
        return result;
    }
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (start > std::numeric_limits<std::uintptr_t>::max()) {
            result.error_code = "address_out_of_range";
            result.error_message = "The search address does not fit this host architecture.";
            return result;
        }
    }

    const auto pageSize = std::max<std::size_t>(pattern.size(), std::min<std::uint32_t>(
        page_bytes == 0 ? kDefaultMemorySearchPageBytes : page_bytes,
        kMaxMemorySearchPageBytes));
    const auto overlap = pattern.size() - 1;
    auto regions = process_->queryRegions();
    std::sort(regions.begin(), regions.end(), [](const auto& left, const auto& right) {
        return left.base < right.base;
    });
    const auto usable = [&](const ce::MemoryRegion& region) {
        return region.size >= pattern.size() && (region.protection & ce::MemProt::Read);
    };
    const auto matches = [&](const std::uint8_t* bytes) {
        for (std::size_t index = 0; index < pattern.size(); ++index) {
            if ((mask.empty() || mask[index] != 0) && bytes[index] != pattern[index])
                return false;
        }
        return true;
    };
    const auto next_forward_region = [&](std::size_t index) -> std::optional<std::uintptr_t> {
        for (std::size_t next = index + 1; next < regions.size(); ++next)
            if (usable(regions[next])) return regions[next].base;
        return std::nullopt;
    };
    const auto next_backward_region = [&](std::size_t index) -> std::optional<std::uintptr_t> {
        while (index > 0) {
            --index;
            if (!usable(regions[index])) continue;
            const auto end = memory_region_end(regions[index]);
            if (end > regions[index].base) return end - 1;
        }
        return std::nullopt;
    };

    const auto target = static_cast<std::uintptr_t>(start);
    if (!backward) {
        for (std::size_t index = 0; index < regions.size(); ++index) {
            const auto& region = regions[index];
            if (!usable(region)) continue;
            const auto end = memory_region_end(region);
            if (end <= target) continue;
            const auto position = std::max(region.base, target);
            if (end - position < pattern.size()) continue;
            const auto wanted = std::min<std::size_t>(pageSize, end - position);
            std::vector<std::uint8_t> buffer(wanted);
            const auto read = process_->read(position, buffer.data(), buffer.size());
            const auto received = read ? *read : 0;
            result.scanned_bytes = static_cast<std::uint64_t>(received);
            if (received >= pattern.size()) {
                for (std::size_t offset = 0; offset + pattern.size() <= received; ++offset) {
                    if (!matches(buffer.data() + offset)) continue;
                    result.accepted = true;
                    result.found = true;
                    result.complete = true;
                    result.address = static_cast<std::uint64_t>(position + offset);
                    return result;
                }
            }
            if (read && received == wanted && position + received < end && received > overlap) {
                result.accepted = true;
                result.next_address = static_cast<std::uint64_t>(position + received - overlap);
                return result;
            }
            if (const auto next = next_forward_region(index)) {
                result.accepted = true;
                result.next_address = static_cast<std::uint64_t>(*next);
                return result;
            }
            result.accepted = true;
            result.complete = true;
            return result;
        }
        result.accepted = true;
        result.complete = true;
        return result;
    }

    for (std::size_t reverse = regions.size(); reverse > 0; --reverse) {
        const auto index = reverse - 1;
        const auto& region = regions[index];
        if (!usable(region) || region.base > target) continue;
        const auto end = memory_region_end(region);
        const auto upper = target == std::numeric_limits<std::uintptr_t>::max()
            ? end
            : std::min(end, target + 1);
        if (upper <= region.base || upper - region.base < pattern.size()) continue;
        const auto wanted = std::min<std::size_t>(pageSize, upper - region.base);
        const auto position = upper - wanted;
        std::vector<std::uint8_t> buffer(wanted);
        const auto read = process_->read(position, buffer.data(), buffer.size());
        const auto received = read ? *read : 0;
        result.scanned_bytes = static_cast<std::uint64_t>(received);
        if (received >= pattern.size()) {
            for (std::size_t candidate = received - pattern.size() + 1; candidate > 0;) {
                --candidate;
                if (!matches(buffer.data() + candidate)) continue;
                result.accepted = true;
                result.found = true;
                result.complete = true;
                result.address = static_cast<std::uint64_t>(position + candidate);
                return result;
            }
        }
        if (read && received == wanted && position > region.base && received > overlap) {
            const auto nextUpper = position + overlap;
            result.accepted = true;
            result.next_address = static_cast<std::uint64_t>(nextUpper - 1);
            return result;
        }
        if (const auto next = next_backward_region(index)) {
            result.accepted = true;
            result.next_address = static_cast<std::uint64_t>(*next);
            return result;
        }
        result.accepted = true;
        result.complete = true;
        return result;
    }
    result.accepted = true;
    result.complete = true;
    return result;
}

MemoryWriteResult EngineFacade::memory_write(
        std::uint64_t address,
        rust::Slice<const std::uint8_t> bytes,
        bool allow_protection_change) {
    MemoryWriteResult result;
    result.accepted = false;
    result.written = 0;
    result.protection_changed = false;
    result.protection_restored = true;
    result.warning = "";
    result.error_code = "";
    result.error_message = "";

    if (!process_) {
        result.error_code = "no_session";
        result.error_message = "Attach to a process before writing memory.";
        return result;
    }
    if (bytes.empty()) {
        result.error_code = "empty_write";
        result.error_message = "Enter at least one byte to write.";
        return result;
    }
    if (bytes.size() > kMaxMemoryWriteSize) {
        result.error_code = "write_too_large";
        result.error_message = "A single Memory View edit is limited to 4096 bytes.";
        return result;
    }
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (address > std::numeric_limits<std::uintptr_t>::max()) {
            result.error_code = "address_out_of_range";
            result.error_message = "The write address does not fit this host architecture.";
            return result;
        }
    }
    const auto target = static_cast<std::uintptr_t>(address);
    const auto region = process_->queryRegion(target);
    if (!region || target < region->base || region->size == 0) {
        result.error_code = "address_unmapped";
        result.error_message = "The write address is not inside a mapped memory region.";
        return result;
    }
    const auto offset = target - region->base;
    if (offset >= region->size || bytes.size() > region->size - offset) {
        result.error_code = "write_crosses_region";
        result.error_message = "The edit would cross the current memory-region boundary.";
        return result;
    }
    if (!(region->protection & ce::MemProt::Read)) {
        result.error_code = "region_unreadable";
        result.error_message = "The target region is not readable, so the edit cannot be verified.";
        return result;
    }

    const bool originallyWritable = region->protection & ce::MemProt::Write;
    if (!originallyWritable) {
        if (!allow_protection_change) {
            result.error_code = "region_not_writable";
            result.error_message = "The target region is read-only.";
            return result;
        }
        const auto changed = process_->protect(
            target, bytes.size(), region->protection | ce::MemProt::Write);
        if (!changed) {
            result.error_code = "protection_change_failed";
            result.error_message = "Could not temporarily make the target region writable.";
            return result;
        }
        result.protection_changed = true;
    }

    const auto write = process_->write(target, bytes.data(), bytes.size());
    if (write) result.written = static_cast<std::uint32_t>(*write);
    if (result.protection_changed) {
        const auto restored = process_->protect(target, bytes.size(), region->protection);
        result.protection_restored = restored.has_value();
        if (!result.protection_restored) {
            result.warning = "The bytes were written, but the original page protection could not be restored.";
        }
    }
    if (!write || *write != bytes.size()) {
        result.error_code = "memory_write_failed";
        std::string message = write
            ? "The target accepted only part of the requested memory edit."
            : "Could not write process memory: " + write.error().message() + ".";
        if (!result.protection_restored)
            message += " The original page protection could not be restored.";
        result.error_message = message;
        return result;
    }

    std::vector<std::uint8_t> verification(bytes.size());
    const auto read = process_->read(target, verification.data(), verification.size());
    if (!read || *read != verification.size() ||
        !std::equal(verification.begin(), verification.end(), bytes.begin())) {
        result.error_code = "memory_write_verification_failed";
        std::string message = "The edit was written but could not be verified by reading it back.";
        if (!result.protection_restored)
            message += " The original page protection could not be restored.";
        result.error_message = message;
        return result;
    }

    result.accepted = true;
    return result;
}

AssembleResult EngineFacade::assemble_preview(std::uint64_t address, rust::Str source) const {
    AssembleResult result;
    result.accepted = false;
    result.arch = "unknown";
    result.statements = 0;
    result.error_code = "";
    result.error_message = "";

    if (!process_) {
        result.error_code = "no_session";
        result.error_message = "Attach to a process before assembling instructions.";
        return result;
    }
    if (source.empty()) {
        result.error_code = "empty_assembly";
        result.error_message = "Enter an instruction to assemble.";
        return result;
    }
    if (source.size() > kMaxAssemblySourceSize) {
        result.error_code = "assembly_source_too_large";
        result.error_message = "Assembly input is limited to 4096 bytes.";
        return result;
    }
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (address > std::numeric_limits<std::uintptr_t>::max()) {
            result.error_code = "address_out_of_range";
            result.error_message = "The assembly address does not fit this host architecture.";
            return result;
        }
    }

    const bool code32 = process_->runs32BitCode();
    result.arch = code32 ? "x86-32" : "x86-64";
    try {
        ce::Assembler assembler(code32 ? ce::AsmArch::X86_32 : ce::AsmArch::X86_64);
        std::size_t statements = 0;
        const auto assembled = assembler.assembleEx(
            std::string(source), static_cast<std::uintptr_t>(address), statements);
        if (!assembled) {
            result.error_code = "assembly_failed";
            result.error_message = sanitize_utf8(assembled.error());
            return result;
        }
        if (assembled->empty()) {
            result.error_code = "assembly_empty_output";
            result.error_message = "The instruction assembled to no bytes.";
            return result;
        }
        if (assembled->size() > kMaxAssemblyOutputSize) {
            result.error_code = "assembly_output_too_large";
            result.error_message = "Assembled output is limited to 4096 bytes.";
            return result;
        }
        for (const auto byte : *assembled) result.bytes.push_back(byte);
        result.statements = static_cast<std::uint32_t>(std::min<std::size_t>(
            statements, std::numeric_limits<std::uint32_t>::max()));
        result.accepted = true;
        return result;
    } catch (const std::exception& error) {
        result.error_code = "assembler_initialization_failed";
        result.error_message = "Could not initialize the assembler: " +
            std::string(error.what());
        return result;
    }
}

DebugStateResult EngineFacade::debug_state() const {
    DebugStateResult result;
    result.accepted = true;
    result.attached = false;
    result.stopped = false;
    result.exited = false;
    result.active_tid = 0;
    result.rip = 0;
    result.signal = 0;
    result.event_type = 0;
    result.event_serial = 0;
    result.breakpoint_count = 0;
    result.error_code = "";
    result.error_message = "";

    if (!debug_runtime_) return result;
    auto* session = debug_runtime_->session.get();
    if (session) {
        result.attached = session->isAttached();
        result.stopped = result.attached && session->isStopped();
        result.active_tid = result.attached
            ? static_cast<std::int32_t>(session->activeThread()) : 0;
        if (result.stopped)
            result.rip = static_cast<std::uint64_t>(session->getStopContext().rip);
    }
    {
        std::lock_guard lock(debug_runtime_->mutex);
        result.exited = debug_runtime_->exited;
        result.signal = debug_runtime_->event_signal;
        result.event_type = debug_runtime_->event_type;
        result.event_serial = debug_runtime_->event_serial;
        result.breakpoint_count = static_cast<std::uint32_t>(std::min<std::size_t>(
            debug_runtime_->software_breakpoints.size(),
            std::numeric_limits<std::uint32_t>::max()));
        if (result.rip == 0)
            result.rip = static_cast<std::uint64_t>(debug_runtime_->event_address);
        if (result.active_tid == 0)
            result.active_tid = static_cast<std::int32_t>(debug_runtime_->event_tid);
    }
    return result;
}

DebugStateResult EngineFacade::debug_start() {
    if (!process_) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "no_session";
        result.error_message = "Attach to a process before starting the debugger.";
        return result;
    }
    if (debug_runtime_->session && debug_runtime_->session->isAttached())
        return debug_state();

    stop_debug_session();
    auto candidate = std::make_unique<ce::DebugSession>();
    candidate->setEventCallback([this](const ce::DebugEvent& event) {
        if (!debug_runtime_) return;
        std::lock_guard lock(debug_runtime_->mutex);
        ++debug_runtime_->event_serial;
        debug_runtime_->event_address = event.address != 0
            ? event.address : event.context.rip;
        debug_runtime_->event_tid = event.tid;
        debug_runtime_->event_signal = event.signal;
        debug_runtime_->exited = event.type == ce::DebugEventType::ProcessExited;
        if (debug_runtime_->exited)
            debug_runtime_->software_breakpoints.clear();
        switch (event.type) {
            case ce::DebugEventType::BreakpointHit:
                debug_runtime_->event_type = 1;
                break;
            case ce::DebugEventType::ExceptionBreakpointHit:
                debug_runtime_->event_type = 2;
                break;
            case ce::DebugEventType::SingleStep:
                debug_runtime_->event_type = 3;
                break;
            case ce::DebugEventType::ProcessExited:
                debug_runtime_->event_type = 4;
                break;
            case ce::DebugEventType::SignalReceived:
                debug_runtime_->event_type = 5;
                break;
        }
    });
    if (!candidate->attach(process_->pid(), process_.get())) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "debug_attach_failed";
        result.error_message =
            "Linux denied the ptrace debugger attach, or the process exited.";
        return result;
    }
    debug_runtime_->session = std::move(candidate);
    {
        std::lock_guard lock(debug_runtime_->mutex);
        ++debug_runtime_->event_serial;
        debug_runtime_->event_address =
            debug_runtime_->session->getStopContext().rip;
        debug_runtime_->event_tid = debug_runtime_->session->activeThread();
        debug_runtime_->event_signal = 0;
        debug_runtime_->event_type = 0;
        debug_runtime_->exited = false;
    }
    return debug_state();
}

DebugStateResult EngineFacade::debug_continue() {
    if (!debug_runtime_->session || !debug_runtime_->session->isAttached()) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "debug_not_attached";
        result.error_message = "Start the debugger before continuing the target.";
        return result;
    }
    if (!debug_runtime_->session->isStopped()) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "debug_not_stopped";
        result.error_message = "The debugged process is already running.";
        return result;
    }
    debug_runtime_->session->continueExecution();
    return debug_state();
}

DebugStateResult EngineFacade::debug_step(std::uint8_t mode,
                                           std::uint64_t target_address) {
    if (!debug_runtime_->session || !debug_runtime_->session->isAttached()) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "debug_not_attached";
        result.error_message = "Start the debugger before stepping the target.";
        return result;
    }
    if (!debug_runtime_->session->isStopped()) {
        auto result = debug_state();
        result.accepted = false;
        result.error_code = "debug_not_stopped";
        result.error_message = "Wait for the target to stop before stepping.";
        return result;
    }
    ce::StepMode stepMode;
    switch (mode) {
        case 0: stepMode = ce::StepMode::Into; break;
        case 1: stepMode = ce::StepMode::Over; break;
        case 2: stepMode = ce::StepMode::Out; break;
        case 3:
            if (target_address == 0) {
                auto result = debug_state();
                result.accepted = false;
                result.error_code = "invalid_step_target";
                result.error_message = "Run to cursor needs a non-zero target address.";
                return result;
            }
            if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
                if (target_address > std::numeric_limits<std::uintptr_t>::max()) {
                    auto result = debug_state();
                    result.accepted = false;
                    result.error_code = "address_out_of_range";
                    result.error_message =
                        "The run-to-cursor address does not fit this host architecture.";
                    return result;
                }
            }
            stepMode = ce::StepMode::RunToCursor;
            break;
        default: {
            auto result = debug_state();
            result.accepted = false;
            result.error_code = "invalid_step_mode";
            result.error_message = "The requested debugger step mode is not supported.";
            return result;
        }
    }
    debug_runtime_->session->step(
        stepMode, static_cast<std::uintptr_t>(target_address));
    return debug_state();
}

DebugStateResult EngineFacade::debug_detach() {
    stop_debug_session();
    return debug_state();
}

BreakpointActionResult EngineFacade::debug_toggle_breakpoint(std::uint64_t address) {
    BreakpointActionResult result;
    result.accepted = false;
    result.address = address;
    result.enabled = false;
    result.breakpoint_count = 0;
    result.error_code = "";
    result.error_message = "";

    if (!process_) {
        result.error_code = "no_session";
        result.error_message = "Attach to a process before setting a breakpoint.";
        return result;
    }
    if (!debug_runtime_->session || !debug_runtime_->session->isAttached()) {
        result.error_code = "debug_not_attached";
        result.error_message = "Start the debugger before setting a breakpoint.";
        return result;
    }
    if (!debug_runtime_->session->isStopped()) {
        result.error_code = "debug_not_stopped";
        result.error_message = "Stop the debugged process before changing breakpoints.";
        return result;
    }
    if constexpr (sizeof(std::uintptr_t) < sizeof(std::uint64_t)) {
        if (address > std::numeric_limits<std::uintptr_t>::max()) {
            result.error_code = "address_out_of_range";
            result.error_message = "The breakpoint address does not fit this host architecture.";
            return result;
        }
    }
    const auto target = static_cast<std::uintptr_t>(address);
    const auto region = process_->queryRegion(target);
    if (!region || !(region->protection & ce::MemProt::Read) ||
        !(region->protection & ce::MemProt::Exec)) {
        result.error_code = "breakpoint_address_not_executable";
        result.error_message = "Software execute breakpoints require a readable executable page.";
        return result;
    }

    int existingId = 0;
    {
        std::lock_guard lock(debug_runtime_->mutex);
        const auto existing = debug_runtime_->software_breakpoints.find(target);
        if (existing != debug_runtime_->software_breakpoints.end())
            existingId = existing->second.id;
    }
    if (existingId > 0) {
        debug_runtime_->session->removeSoftwareBreakpoint(existingId);
        std::lock_guard lock(debug_runtime_->mutex);
        debug_runtime_->software_breakpoints.erase(target);
        result.accepted = true;
        result.breakpoint_count = static_cast<std::uint32_t>(
            debug_runtime_->software_breakpoints.size());
        return result;
    }

    {
        std::lock_guard lock(debug_runtime_->mutex);
        if (debug_runtime_->software_breakpoints.size() >= kMaxSoftwareBreakpoints) {
            result.error_code = "breakpoint_limit";
            result.error_message = "Software breakpoints are limited to 4096 per session.";
            return result;
        }
    }
    std::uint8_t originalByte = 0;
    const auto read = process_->read(target, &originalByte, sizeof originalByte);
    if (!read || *read != sizeof originalByte) {
        result.error_code = "breakpoint_read_failed";
        result.error_message = "Could not capture the original instruction byte.";
        return result;
    }
    const int id = debug_runtime_->session->setSoftwareBreakpoint(target);
    if (id <= 0) {
        result.error_code = "breakpoint_set_failed";
        result.error_message = "ptrace could not plant the software breakpoint.";
        return result;
    }
    {
        std::lock_guard lock(debug_runtime_->mutex);
        debug_runtime_->software_breakpoints[target] = {id, originalByte};
        result.breakpoint_count = static_cast<std::uint32_t>(
            debug_runtime_->software_breakpoints.size());
    }
    result.accepted = true;
    result.enabled = true;
    return result;
}

void EngineFacade::cancel_scan() noexcept {
    std::lock_guard lock(scan_mutex_);
    if (!scan_running_.load(std::memory_order_acquire) || !scanner_) return;
    scan_cancel_requested_.store(true, std::memory_order_release);
    scanner_->cancel();
}

AddressPage EngineFacade::address_rows(std::uint64_t start, std::uint32_t limit,
                                       bool refresh_values) {
    AddressPage page;
    page.generation = address_list_->generation();
    page.start = start;
    page.total_count = static_cast<std::uint64_t>(address_list_->count());
    page.raw_total_count = page.total_count;
    page.error_message = "";
    page.start = std::min(page.start, page.total_count);
    const auto bounded_start = static_cast<std::size_t>(std::min<std::uint64_t>(
        page.start, std::numeric_limits<std::size_t>::max()));
    const auto bounded_limit = static_cast<std::size_t>(
        std::min(limit, kMaxAddressPageSize));
    for (const auto& record :
         address_list_->records(bounded_start, bounded_limit, refresh_values)) {
        page.rows.push_back(AddressRow{
            .id = record.id,
            .description = sanitize_utf8(record.description),
            .address = static_cast<std::uint64_t>(record.address),
            .address_expression = sanitize_utf8(record.addressExpression),
            .value_type = bridge_value_type(record.type),
            .type_name = ce::valueTypeName(record.type),
            .value = sanitize_utf8(record.value),
            .error_message = sanitize_utf8(record.error),
            .readable = record.readable,
            .active = record.active,
            .freeze_mode = static_cast<std::uint8_t>(record.freezeMode),
            .show_as_hex = record.showAsHex,
            .byte_count = static_cast<std::uint32_t>(std::min<std::size_t>(
                record.byteCount, std::numeric_limits<std::uint32_t>::max())),
            .is_group = record.isGroup,
            .collapsed = record.collapsed,
            .has_script = record.hasScript,
            .has_auto_assembler = record.hasAutoAssembler,
            .has_lua = record.hasLua,
            .indent = record.indent,
        });
    }
    return page;
}

AddressPage EngineFacade::visible_address_rows(std::uint64_t start, std::uint32_t limit,
                                               bool refresh_values) {
    AddressPage page;
    page.generation = address_list_->generation();
    page.start = start;
    page.error_message = "";
    const auto bounded_start = static_cast<std::size_t>(std::min<std::uint64_t>(
        page.start, std::numeric_limits<std::size_t>::max()));
    const auto bounded_limit = static_cast<std::size_t>(
        std::min(limit, kMaxAddressPageSize));
    auto visible =
        address_list_->visibleRecords(bounded_start, bounded_limit, refresh_values);
    page.total_count = visible.totalCount;
    page.raw_total_count = visible.rawTotalCount;
    page.start = std::min(page.start, page.total_count);
    for (const auto& record : visible.records) {
        page.rows.push_back(AddressRow{
            .id = record.id,
            .description = sanitize_utf8(record.description),
            .address = static_cast<std::uint64_t>(record.address),
            .address_expression = sanitize_utf8(record.addressExpression),
            .value_type = bridge_value_type(record.type),
            .type_name = ce::valueTypeName(record.type),
            .value = sanitize_utf8(record.value),
            .error_message = sanitize_utf8(record.error),
            .readable = record.readable,
            .active = record.active,
            .freeze_mode = static_cast<std::uint8_t>(record.freezeMode),
            .show_as_hex = record.showAsHex,
            .byte_count = static_cast<std::uint32_t>(std::min<std::size_t>(
                record.byteCount, std::numeric_limits<std::uint32_t>::max())),
            .is_group = record.isGroup,
            .collapsed = record.collapsed,
            .has_script = record.hasScript,
            .has_auto_assembler = record.hasAutoAssembler,
            .has_lua = record.hasLua,
            .indent = record.indent,
        });
    }
    return page;
}

AddressActionResult EngineFacade::add_scan_result(std::uint64_t generation,
                                                   std::uint64_t scan_index,
                                                   rust::Str description) {
    AddressActionResult response;
    response.accepted = false;
    response.id = 0;
    response.error_code = "";
    response.error_message = "";
    std::string label(description);
    if (label.size() > kMaxAddressDescriptionSize) label.resize(kMaxAddressDescriptionSize);

    std::lock_guard lock(scan_mutex_);
    const auto current_generation = scan_generation_.load(std::memory_order_acquire);
    if (generation != current_generation) {
        response.error_code = "stale_scan_result";
        response.error_message = "The scan result changed before it could be added.";
        return response;
    }
    if (scan_running_.load(std::memory_order_acquire)) {
        response.error_code = "scan_in_progress";
        response.error_message = "Wait for the current scan to finish before adding a result.";
        return response;
    }
    if (!scan_result_ || !scan_config_) {
        response.error_code = "no_scan_result";
        response.error_message = "No completed scan result is available.";
        return response;
    }
    if (scan_index >= static_cast<std::uint64_t>(scan_result_->count()) ||
        scan_index > std::numeric_limits<std::size_t>::max()) {
        response.error_code = "scan_result_not_found";
        response.error_message = "The selected scan result no longer exists.";
        return response;
    }

    try {
        const auto address = scan_result_->address(static_cast<std::size_t>(scan_index));
        const auto result = address_list_->addRecord(
            address, scan_config_->valueType, label, scan_value_size(*scan_config_),
            scan_display_hex_);
        response.accepted = result.success;
        response.id = result.id;
        response.error_code = result.errorCode;
        response.error_message = result.errorMessage;
    } catch (const std::exception& error) {
        response.error_code = "scan_result_unavailable";
        response.error_message = error.what();
    }
    return response;
}

AddressActionResult EngineFacade::add_address(std::uint64_t address,
                                              std::uint8_t value_type,
                                              rust::Str description,
                                              std::uint32_t byte_count,
                                              bool show_as_hex) {
    AddressActionResult response;
    response.accepted = false;
    response.id = 0;
    response.error_code = "";
    response.error_message = "";
    const auto type = scan_value_type(value_type);
    if (!type) {
        response.error_code = "invalid_value_type";
        response.error_message = "The address-list value type is not supported.";
        return response;
    }
    if (address > std::numeric_limits<std::uintptr_t>::max()) {
        response.error_code = "invalid_address";
        response.error_message = "The address does not fit this platform.";
        return response;
    }
    std::string label(description);
    if (label.size() > kMaxAddressDescriptionSize) label.resize(kMaxAddressDescriptionSize);
    const auto result = address_list_->addRecord(
        static_cast<std::uintptr_t>(address), *type, label, byte_count, show_as_hex);
    response.accepted = result.success;
    response.id = result.id;
    response.error_code = result.errorCode;
    response.error_message = result.errorMessage;
    return response;
}

AddressActionResult EngineFacade::set_address_value(std::int32_t id, rust::Str value) {
    AddressActionResult response;
    std::string text(value);
    if (text.size() > kMaxAddressTextSize) {
        response.accepted = false;
        response.id = id;
        response.error_code = "value_too_large";
        response.error_message = "The address-list value is too large.";
        return response;
    }
    const auto result = address_list_->writeRecordValue(id, text);
    response.accepted = result.success;
    response.id = result.id;
    response.error_code = result.errorCode;
    response.error_message = result.errorMessage;
    return response;
}

bool EngineFacade::deactivate_scripts(const std::vector<int>& ids,
                                      std::string& errorCode,
                                      std::string& errorMessage) noexcept {
    errorCode.clear();
    errorMessage.clear();
    try {
        if (ids.empty()) return true;

        const std::unordered_set<int> requested(ids.begin(), ids.end());
        std::vector<int> ordered;
        ordered.reserve(requested.size());
        for (auto iterator = script_runtime_->activationOrder.rbegin();
             iterator != script_runtime_->activationOrder.rend(); ++iterator) {
            if (requested.contains(*iterator)) ordered.push_back(*iterator);
        }
        for (const int id : requested) {
            if (script_runtime_->disableInfoById.contains(id) &&
                std::find(ordered.begin(), ordered.end(), id) == ordered.end())
                ordered.push_back(id);
        }
        if (ordered.empty()) return true;
        if (!process_) {
            errorCode = "script_target_unavailable";
            errorMessage =
                "The original target is unavailable, so active Auto Assembler records "
                "cannot be disabled safely.";
            return false;
        }

        const auto records = address_list_->exportRecords();
        for (const int id : ordered) {
            const auto record = std::find_if(
                records.begin(), records.end(), [id](const auto& item) { return item.id == id; });
            const auto disableInfo = script_runtime_->disableInfoById.find(id);
            if (record == records.end() || record->script.empty() ||
                disableInfo == script_runtime_->disableInfoById.end()) {
                errorCode = "script_disable_state_missing";
                errorMessage =
                    "Runtime state needed to disable an Auto Assembler record is missing.";
                return false;
            }

            ce::AutoAsmResult disabled;
            try {
                disabled = script_runtime_->assembler.disable(
                    *process_, record->script, disableInfo->second);
            } catch (const std::exception& error) {
                disabled.success = false;
                disabled.error = error.what();
            } catch (...) {
                disabled.success = false;
                disabled.error = "The Auto Assembler raised an unknown native error.";
            }
            if (disabled.success) {
                for (const auto& original : disableInfo->second.originals) {
                    const bool belongedToFreedAllocation = std::any_of(
                        disableInfo->second.allocs.begin(),
                        disableInfo->second.allocs.end(),
                        [&original](const ce::DisableInfo::AllocEntry& allocation) {
                            return original.address >= allocation.address &&
                                   original.address - allocation.address < allocation.size;
                        });
                    if (belongedToFreedAllocation) continue;
                    std::vector<std::uint8_t> restored(original.bytes.size());
                    const auto read = process_->read(
                        original.address, restored.data(), restored.size());
                    if (!read || *read != restored.size() || restored != original.bytes) {
                        disabled.success = false;
                        disabled.error =
                            "The target did not confirm restoration of the original bytes.";
                        break;
                    }
                }
            }
            if (!disabled.success) {
                errorCode = "auto_assembler_disable_failed";
                errorMessage = disabled.error.empty()
                    ? "The Auto Assembler record could not be disabled."
                    : disabled.error;
                return false;
            }

            const auto committed = address_list_->commitExecutedScriptState(
                id, false, record->luaScript.empty()
                               ? "(Auto Assembler script disabled)"
                               : "(Auto Assembler disabled; record Lua requires separate Run)");
            script_runtime_->disableInfoById.erase(id);
            std::erase(script_runtime_->activationOrder, id);
            if (!committed.success) {
                errorCode = "script_state_update_failed";
                errorMessage = committed.errorMessage;
                return false;
            }
        }
        return true;
    } catch (const std::exception& error) {
        errorCode = "script_cleanup_failed";
        errorMessage = error.what();
        return false;
    } catch (...) {
        errorCode = "script_cleanup_failed";
        errorMessage = "An unknown native error interrupted script cleanup.";
        return false;
    }
}

bool EngineFacade::deactivate_all_scripts(std::string& errorCode,
                                          std::string& errorMessage) noexcept {
    try {
        std::vector<int> ids;
        ids.reserve(script_runtime_->disableInfoById.size());
        for (const auto& [id, _] : script_runtime_->disableInfoById) ids.push_back(id);
        return deactivate_scripts(ids, errorCode, errorMessage);
    } catch (const std::exception& error) {
        errorCode = "script_cleanup_failed";
        errorMessage = error.what();
        return false;
    } catch (...) {
        errorCode = "script_cleanup_failed";
        errorMessage = "An unknown native error interrupted script cleanup.";
        return false;
    }
}

AddressActionResult EngineFacade::set_address_active(std::int32_t id, bool active) {
    const auto records = address_list_->exportRecords();
    const auto found = std::find_if(records.begin(), records.end(), [id](const auto& record) {
        return record.id == id;
    });
    if (found == records.end()) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "record_not_found",
            .error_message = "The address-list record no longer exists.",
        };
    }
    if (found->script.empty() && found->luaScript.empty()) {
        const auto result = address_list_->activateRecord(id, active);
        return AddressActionResult{
            .accepted = result.success,
            .id = result.id,
            .error_code = result.errorCode,
            .error_message = result.errorMessage,
        };
    }
    if (found->script.empty()) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "lua_requires_explicit_run",
            .error_message =
                "Run reviewed Lua from the script-review window; address-list toggles never execute it.",
        };
    }
    if (found->active == active) {
        return AddressActionResult{
            .accepted = true, .id = id, .error_code = {}, .error_message = {}};
    }
    if (!active) {
        std::string errorCode;
        std::string errorMessage;
        const bool disabled = deactivate_scripts({id}, errorCode, errorMessage);
        return AddressActionResult{
            .accepted = disabled,
            .id = id,
            .error_code = errorCode,
            .error_message = errorMessage,
        };
    }
    if (!script_runtime_->autoAssemblerTrusted) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "table_not_trusted",
            .error_message =
                "Trust this loaded table before enabling its Auto Assembler records.",
        };
    }
    if (!process_) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "no_session",
            .error_message = "Attach to a process before enabling an Auto Assembler record.",
        };
    }

    ce::AutoAsmResult execution;
    try {
        execution = script_runtime_->assembler.execute(*process_, found->script);
    } catch (const std::exception& error) {
        execution.success = false;
        execution.error = error.what();
    } catch (...) {
        execution.success = false;
        execution.error = "The Auto Assembler raised an unknown native error.";
    }
    if (!execution.success) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "auto_assembler_failed",
            .error_message = execution.error.empty()
                ? "The Auto Assembler record could not be enabled."
                : execution.error,
        };
    }

    const auto committed = address_list_->commitExecutedScriptState(
        id, true, found->luaScript.empty()
                      ? "(Auto Assembler script enabled)"
                      : "(Auto Assembler enabled; record Lua requires separate Run)");
    if (!committed.success) {
        try {
            script_runtime_->assembler.disable(*process_, found->script,
                                                execution.disableInfo);
        } catch (...) {
        }
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "script_state_update_failed",
            .error_message = committed.errorMessage,
        };
    }
    script_runtime_->disableInfoById[id] = std::move(execution.disableInfo);
    script_runtime_->activationOrder.push_back(id);
    return AddressActionResult{
        .accepted = true, .id = id, .error_code = {}, .error_message = {}};
}

AddressActionResult EngineFacade::set_address_freeze_mode(std::int32_t id,
                                                          std::uint8_t mode) {
    if (mode > static_cast<std::uint8_t>(ce::FreezeMode::NeverDecrease)) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = "invalid_freeze_mode",
            .error_message = "The freeze mode is not supported.",
        };
    }
    const auto result = address_list_->changeFreezeMode(
        id, static_cast<ce::FreezeMode>(mode));
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

AddressActionResult EngineFacade::delete_address(std::int32_t id) {
    const auto records = address_list_->exportRecords();
    const auto found = std::find_if(records.begin(), records.end(), [id](const auto& record) {
        return record.id == id;
    });
    std::vector<int> removedIds;
    if (found != records.end()) {
        const auto row = static_cast<std::size_t>(std::distance(records.begin(), found));
        removedIds.push_back(id);
        if (found->isGroup) {
            for (std::size_t child = row + 1; child < records.size(); ++child) {
                if (records[child].indent <= found->indent) break;
                removedIds.push_back(records[child].id);
            }
        }
    }
    std::string scriptErrorCode;
    std::string scriptErrorMessage;
    if (!deactivate_scripts(removedIds, scriptErrorCode, scriptErrorMessage)) {
        return AddressActionResult{
            .accepted = false,
            .id = id,
            .error_code = scriptErrorCode,
            .error_message = scriptErrorMessage,
        };
    }
    const auto result = address_list_->removeRecord(id);
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

AddressActionResult EngineFacade::add_address_group(rust::Str description) {
    std::string label(description);
    if (label.size() > kMaxAddressDescriptionSize) label.resize(kMaxAddressDescriptionSize);
    const int id = address_list_->createGroup(label);
    return AddressActionResult{
        .accepted = id > 0,
        .id = id,
        .error_code = id > 0 ? "" : "group_create_failed",
        .error_message = id > 0 ? "" : "The address-list group could not be created.",
    };
}

AddressActionResult EngineFacade::group_addresses(
    rust::Slice<const std::int32_t> ids, rust::Str description) {
    if (ids.size() > kMaxAddressGroupSelection) {
        return AddressActionResult{
            .accepted = false,
            .id = 0,
            .error_code = "selection_too_large",
            .error_message = "Too many address-list records were selected.",
        };
    }
    std::string label(description);
    if (label.size() > kMaxAddressDescriptionSize) label.resize(kMaxAddressDescriptionSize);
    std::vector<int> selected(ids.begin(), ids.end());
    const auto result = address_list_->groupRecords(selected, label);
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

AddressActionResult EngineFacade::move_address(std::int32_t id,
                                                std::int32_t direction) {
    const auto result = address_list_->moveRecord(id, direction);
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

AddressActionResult EngineFacade::set_address_collapsed(std::int32_t id,
                                                         bool collapsed) {
    const auto result = address_list_->setRecordCollapsed(id, collapsed);
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

TableActionResult EngineFacade::load_table(rust::Str path) {
    std::string file(path);
    if (file.size() > kMaxTablePathSize || file.find('\0') != std::string::npos) {
        return TableActionResult{
            .accepted = false,
            .record_count = 0,
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "invalid_path",
            .error_message = "The cheat-table path is invalid or too long.",
            .compatibility_issues = {},
        };
    }
    if (ce::detectTableFormat(file) == ce::TableFormat::Protected) {
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "protected_table",
            .error_message = "This CETRAINER file requires its password.",
            .compatibility_issues = {},
        };
    }
    std::string scriptErrorCode;
    std::string scriptErrorMessage;
    if (!deactivate_all_scripts(scriptErrorCode, scriptErrorMessage)) {
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = true,
            .contains_auto_assembler = true,
            .contains_lua = false,
            .error_code = scriptErrorCode,
            .error_message = scriptErrorMessage,
            .compatibility_issues = {},
        };
    }
    const auto result = address_list_->loadTable(file);
    if (result.success) {
        script_runtime_->autoAssemblerTrusted = false;
        script_runtime_->luaTrusted = false;
        script_runtime_->resetLua(process_.get(), address_list_.get());
        script_runtime_->disableInfoById.clear();
        script_runtime_->activationOrder.clear();
    }
    return TableActionResult{
        .accepted = result.success,
        .record_count = static_cast<std::uint64_t>(result.recordCount),
        .contains_scripts = result.containsScripts,
        .contains_auto_assembler = result.containsAutoAssembler,
        .contains_lua = result.containsLua,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
        .compatibility_issues = table_compatibility_rows(
            result.compatibilityIssues),
    };
}

TableActionResult EngineFacade::load_protected_table(rust::Str path,
                                                       rust::Str requestedPassword) {
    std::string file(path);
    std::string password(requestedPassword);
    if (file.size() > kMaxTablePathSize || file.find('\0') != std::string::npos) {
        std::fill(password.begin(), password.end(), '\0');
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "invalid_path",
            .error_message = "The cheat-table path is invalid or too long.",
            .compatibility_issues = {},
        };
    }
    if (password.size() > kMaxTablePasswordSize ||
        password.find('\0') != std::string::npos) {
        std::fill(password.begin(), password.end(), '\0');
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "invalid_password",
            .error_message = "The table password is invalid or too long.",
            .compatibility_issues = {},
        };
    }
    if (ce::detectTableFormat(file) != ce::TableFormat::Protected) {
        std::fill(password.begin(), password.end(), '\0');
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "protected_table_invalid",
            .error_message = "The selected file is not a supported protected CETRAINER table.",
            .compatibility_issues = {},
        };
    }

    ce::CheatTable parsed;
    bool decrypted = false;
    try {
        decrypted = parsed.loadProtected(file, password);
    } catch (...) {
        decrypted = false;
    }
    std::fill(password.begin(), password.end(), '\0');
    if (!decrypted) {
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "protected_table_decrypt_failed",
            .error_message = "The table could not be decrypted. Check the password or file integrity.",
            .compatibility_issues = {},
        };
    }

    // Decryption and parsing are complete before touching the old table.  A bad
    // password therefore cannot disable its active Auto Assembler records.
    std::string scriptErrorCode;
    std::string scriptErrorMessage;
    if (!deactivate_all_scripts(scriptErrorCode, scriptErrorMessage)) {
        return TableActionResult{
            .accepted = false,
            .record_count = static_cast<std::uint64_t>(address_list_->count()),
            .contains_scripts = true,
            .contains_auto_assembler = true,
            .contains_lua = false,
            .error_code = scriptErrorCode,
            .error_message = scriptErrorMessage,
            .compatibility_issues = {},
        };
    }

    const auto result = address_list_->loadTableData(std::move(parsed));
    if (result.success) {
        script_runtime_->autoAssemblerTrusted = false;
        script_runtime_->luaTrusted = false;
        script_runtime_->resetLua(process_.get(), address_list_.get());
        script_runtime_->disableInfoById.clear();
        script_runtime_->activationOrder.clear();
    }
    return TableActionResult{
        .accepted = result.success,
        .record_count = static_cast<std::uint64_t>(result.recordCount),
        .contains_scripts = result.containsScripts,
        .contains_auto_assembler = result.containsAutoAssembler,
        .contains_lua = result.containsLua,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
        .compatibility_issues = table_compatibility_rows(
            result.compatibilityIssues),
    };
}

rust::Vec<TableCompatibilityIssueRow> EngineFacade::table_compatibility_issues(
    bool jsonDestination) const {
    return table_compatibility_rows(
        address_list_->tableCompatibilityIssues(jsonDestination));
}

TableActionResult EngineFacade::save_table(rust::Str path, bool json) const {
    std::string file(path);
    if (file.size() > kMaxTablePathSize || file.find('\0') != std::string::npos) {
        return TableActionResult{
            .accepted = false,
            .record_count = 0,
            .contains_scripts = false,
            .contains_auto_assembler = false,
            .contains_lua = false,
            .error_code = "invalid_path",
            .error_message = "The cheat-table path is invalid or too long.",
            .compatibility_issues = {},
        };
    }
    const auto result = address_list_->saveTable(file, json);
    return TableActionResult{
        .accepted = result.success,
        .record_count = static_cast<std::uint64_t>(result.recordCount),
        .contains_scripts = result.containsScripts,
        .contains_auto_assembler = result.containsAutoAssembler,
        .contains_lua = result.containsLua,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
        .compatibility_issues = table_compatibility_rows(
            result.compatibilityIssues),
    };
}

TableScriptPage EngineFacade::table_scripts(std::uint64_t start,
                                             std::uint32_t limit) const {
    const auto total = static_cast<std::uint64_t>(address_list_->scriptPayloadCount());
    start = std::min(start, total);
    const auto boundedStart = static_cast<std::size_t>(std::min<std::uint64_t>(
        start, std::numeric_limits<std::size_t>::max()));
    const auto boundedLimit = static_cast<std::size_t>(
        std::min(limit, kMaxTableScriptPageSize));

    TableScriptPage page{
        .start = start,
        .next_start = start,
        .total_count = total,
        .truncated = start < total,
        .rows = {},
    };
    for (const auto& script :
         address_list_->scriptPayloads(boundedStart, boundedLimit)) {
        const auto descriptionBytes = std::min(
            script.description.size(), kMaxTableScriptDescriptionSize);
        page.rows.push_back(TableScriptRow{
            .record_id = script.recordId,
            .kind = static_cast<std::uint8_t>(script.kind),
            .description = sanitize_utf8(
                script.description.substr(0, descriptionBytes)),
            .byte_count = static_cast<std::uint64_t>(script.byteCount),
        });
    }
    page.next_start = std::min(
        total, start + static_cast<std::uint64_t>(page.rows.size()));
    page.truncated = page.next_start < total;
    return page;
}

TableScriptTextPage EngineFacade::table_script_text(
    std::int32_t record_id, std::uint8_t kind, std::uint64_t offset,
    std::uint32_t limit) const {
    if (kind > static_cast<std::uint8_t>(ce::TableScriptKind::RecordLua)) {
        return TableScriptTextPage{
            .accepted = false,
            .record_id = record_id,
            .kind = kind,
            .offset = offset,
            .next_offset = offset,
            .total_bytes = 0,
            .truncated = false,
            .text = {},
            .error_code = "invalid_script_kind",
            .error_message = "The requested table script kind is invalid.",
        };
    }
    const auto boundedOffset = static_cast<std::size_t>(std::min<std::uint64_t>(
        offset, std::numeric_limits<std::size_t>::max()));
    const auto boundedLimit = static_cast<std::size_t>(
        std::min(limit, kMaxTableScriptTextSize));
    const auto page = address_list_->scriptPayloadText(
        record_id, static_cast<ce::TableScriptKind>(kind), boundedOffset,
        boundedLimit);
    if (!page) {
        return TableScriptTextPage{
            .accepted = false,
            .record_id = record_id,
            .kind = kind,
            .offset = offset,
            .next_offset = offset,
            .total_bytes = 0,
            .truncated = false,
            .text = {},
            .error_code = "script_not_found",
            .error_message = "The requested table script no longer exists.",
        };
    }
    return TableScriptTextPage{
        .accepted = true,
        .record_id = page->recordId,
        .kind = static_cast<std::uint8_t>(page->kind),
        .offset = static_cast<std::uint64_t>(page->offset),
        .next_offset = static_cast<std::uint64_t>(page->nextOffset),
        .total_bytes = static_cast<std::uint64_t>(page->totalBytes),
        .truncated = page->truncated,
        .text = sanitize_utf8(page->text),
        .error_code = {},
        .error_message = {},
    };
}

AddressActionResult EngineFacade::set_table_scripts_trusted(bool trusted) {
    if (!trusted) {
        std::string errorCode;
        std::string errorMessage;
        if (!deactivate_all_scripts(errorCode, errorMessage)) {
            return AddressActionResult{
                .accepted = false,
                .id = 0,
                .error_code = errorCode,
                .error_message = errorMessage,
            };
        }
    }
    script_runtime_->autoAssemblerTrusted = trusted;
    return AddressActionResult{
        .accepted = true, .id = 0, .error_code = {}, .error_message = {}};
}

bool EngineFacade::table_scripts_trusted() const noexcept {
    return script_runtime_->autoAssemblerTrusted;
}

AddressActionResult EngineFacade::set_table_lua_trusted(bool trusted) {
    if (!trusted) {
        try {
            script_runtime_->resetLua(process_.get(), address_list_.get());
        } catch (const std::exception& error) {
            return AddressActionResult{
                .accepted = false,
                .id = 0,
                .error_code = "lua_state_reset_failed",
                .error_message = error.what(),
            };
        } catch (...) {
            return AddressActionResult{
                .accepted = false,
                .id = 0,
                .error_code = "lua_state_reset_failed",
                .error_message = "The Lua runtime could not be reset safely.",
            };
        }
    }
    script_runtime_->luaTrusted = trusted;
    return AddressActionResult{
        .accepted = true, .id = 0, .error_code = {}, .error_message = {}};
}

bool EngineFacade::table_lua_trusted() const noexcept {
    return script_runtime_->luaTrusted;
}

LuaExecutionResult EngineFacade::execute_table_lua(std::int32_t record_id,
                                                    std::uint8_t kind) {
    const auto failure = [record_id, kind](std::string code,
                                           std::string message) {
        return LuaExecutionResult{
            .accepted = false,
            .record_id = record_id,
            .kind = kind,
            .output = {},
            .output_truncated = false,
            .runtime_error = {},
            .error_code = std::move(code),
            .error_message = bounded_utf8(sanitize_utf8(message),
                                          kMaxLuaOutputSize),
        };
    };
    if (kind != static_cast<std::uint8_t>(ce::TableScriptKind::TableLua) &&
        kind != static_cast<std::uint8_t>(ce::TableScriptKind::RecordLua)) {
        return failure("invalid_lua_script_kind",
                       "Only table-level or record Lua payloads can be run here.");
    }
    if (!script_runtime_->luaTrusted) {
        return failure("table_lua_not_trusted",
                       "Review and trust Lua for this loaded table before running it.");
    }

    const auto scriptKind = static_cast<ce::TableScriptKind>(kind);
    auto page = address_list_->scriptPayloadText(
        record_id, scriptKind, 0, kMaxTableScriptTextSize);
    if (!page)
        return failure("script_not_found",
                       "The requested Lua payload no longer exists.");
    if (page->totalBytes > kMaxLuaScriptSize)
        return failure("lua_script_too_large",
                       "Lua payloads larger than 1 MiB are not executed.");

    std::string source;
    source.reserve(page->totalBytes);
    for (;;) {
        source += page->text;
        if (!page->truncated) break;
        if (page->nextOffset <= page->offset)
            return failure("lua_script_paging_failed",
                           "The Lua payload could not be reconstructed safely.");
        page = address_list_->scriptPayloadText(
            record_id, scriptKind, page->nextOffset, kMaxTableScriptTextSize);
        if (!page)
            return failure("script_not_found",
                           "The Lua payload changed while it was being prepared.");
    }
    if (source.find('\0') != std::string::npos)
        return failure("lua_script_contains_nul",
                       "Lua payloads containing NUL bytes are not executed.");
    if (sanitize_utf8(source) != source)
        return failure("lua_script_invalid_utf8",
                       "Lua payloads must be valid UTF-8 before they can be reviewed and run.");

    ScriptRuntime::OutputBuffer output;
    std::string runtimeError;
    try {
        script_runtime_->activeOutput = &output;
        runtimeError = script_runtime_->lua->executeBounded(
            source, kLuaInstructionLimit);
        script_runtime_->activeOutput = nullptr;
    } catch (const std::exception& error) {
        script_runtime_->activeOutput = nullptr;
        return failure("lua_execution_failed", error.what());
    } catch (...) {
        script_runtime_->activeOutput = nullptr;
        return failure("lua_execution_failed",
                       "The Lua runtime raised an unknown native error.");
    }

    return LuaExecutionResult{
        .accepted = true,
        .record_id = record_id,
        .kind = kind,
        .output = std::move(output.text),
        .output_truncated = output.truncated,
        .runtime_error = bounded_utf8(sanitize_utf8(runtimeError),
                                      kMaxLuaOutputSize),
        .error_code = {},
        .error_message = {},
    };
}

LuaConsoleResult EngineFacade::execute_lua_console(rust::Str requestedSource) {
    const auto failure = [this](std::string code, std::string message) {
        return LuaConsoleResult{
            .accepted = false,
            .runtime_generation = script_runtime_->luaGeneration,
            .output = {},
            .output_truncated = false,
            .runtime_error = {},
            .error_code = std::move(code),
            .error_message = bounded_utf8(sanitize_utf8(message),
                                          kMaxLuaOutputSize),
        };
    };

    std::string source(requestedSource);
    if (source.size() > kMaxLuaScriptSize) {
        return failure("lua_console_source_too_large",
                       "Lua console input larger than 1 MiB is not executed.");
    }
    if (source.find('\0') != std::string::npos) {
        return failure("lua_console_source_contains_nul",
                       "Lua console input containing NUL bytes is not executed.");
    }
    if (sanitize_utf8(source) != source) {
        return failure("lua_console_source_invalid_utf8",
                       "Lua console input must be valid UTF-8.");
    }

    ScriptRuntime::OutputBuffer output;
    std::string runtimeError;
    try {
        script_runtime_->activeOutput = &output;
        runtimeError = script_runtime_->lua->executeBounded(
            source, kLuaInstructionLimit);
        script_runtime_->activeOutput = nullptr;
    } catch (const std::exception& error) {
        script_runtime_->activeOutput = nullptr;
        return failure("lua_console_execution_failed", error.what());
    } catch (...) {
        script_runtime_->activeOutput = nullptr;
        return failure("lua_console_execution_failed",
                       "The Lua runtime raised an unknown native error.");
    }

    return LuaConsoleResult{
        .accepted = true,
        .runtime_generation = script_runtime_->luaGeneration,
        .output = std::move(output.text),
        .output_truncated = output.truncated,
        .runtime_error = bounded_utf8(sanitize_utf8(runtimeError),
                                      kMaxLuaOutputSize),
        .error_code = {},
        .error_message = {},
    };
}

std::uint64_t EngineFacade::lua_runtime_generation() const noexcept {
    return script_runtime_->luaGeneration;
}

RuntimeTickResult EngineFacade::periodic_tick() {
    using namespace std::chrono;
    const double now = duration<double, std::milli>(
        steady_clock::now().time_since_epoch()).count();

    if (script_runtime_->lastFreezeMs == 0 ||
        now - script_runtime_->lastFreezeMs >= kAddressFreezeIntervalMs) {
        address_list_->freezeTick();
        script_runtime_->lastFreezeMs = now;
    }

    bool refreshDue = false;
    if (script_runtime_->lastRefreshMs == 0) {
        script_runtime_->lastRefreshMs = now;
    } else if (now - script_runtime_->lastRefreshMs >= kAddressRefreshIntervalMs) {
        script_runtime_->lastRefreshMs = now;
        refreshDue = true;
    }

    ce::LuaEngine::TimerPumpResult timerResult;
    try {
        timerResult = script_runtime_->lua->pumpTimersBounded(
            kLuaTimerInstructionLimit, kMaxLuaTimerCallbacksPerTick);
    } catch (const std::exception& error) {
        script_runtime_->appendLuaOutput(
            std::string("Lua timer pump error: ") + error.what());
        timerResult.callbacksFailed = 1;
    } catch (...) {
        script_runtime_->appendLuaOutput(
            "Lua timer pump error: unknown native failure");
        timerResult.callbacksFailed = 1;
    }
    auto output = script_runtime_->takePendingOutput();
    const auto toU32 = [](std::size_t value) {
        return static_cast<std::uint32_t>(std::min<std::size_t>(
            value, std::numeric_limits<std::uint32_t>::max()));
    };
    return RuntimeTickResult{
        .runtime_generation = script_runtime_->luaGeneration,
        .address_generation = address_list_->generation(),
        .address_refresh_due = refreshDue,
        .timer_count = toU32(script_runtime_->lua->timerCount()),
        .timers_fired = toU32(timerResult.callbacksFired),
        .timer_errors = toU32(timerResult.callbacksFailed),
        .timers_deferred = toU32(timerResult.callbacksDeferred),
        .output = std::move(output.text),
        .output_truncated = output.truncated,
    };
}

void EngineFacade::join_scan_worker() noexcept {
    if (scan_worker_.joinable()) scan_worker_.join();
}

void EngineFacade::clear_scan_state() noexcept {
    std::lock_guard lock(scan_mutex_);
    scan_result_.reset();
    undo_scan_result_.reset();
    scan_config_.reset();
    undo_scan_config_.reset();
    scan_display_hex_ = false;
    undo_scan_display_hex_ = false;
    scanner_.reset();
    scan_error_.clear();
    scan_started_.store(false, std::memory_order_release);
    scan_running_.store(false, std::memory_order_release);
    scan_cancel_requested_.store(false, std::memory_order_release);
    scan_generation_.fetch_add(1, std::memory_order_acq_rel);
}

void EngineFacade::stop_debug_session() noexcept {
    if (!debug_runtime_) return;
    try {
        auto session = std::move(debug_runtime_->session);
        if (session && session->isAttached()) session->detach();
        session.reset();
    } catch (...) {
        // Destruction and target replacement must still clear borrowed state;
        // DebugSession's own destructor performs the same best-effort cleanup.
    }
    std::lock_guard lock(debug_runtime_->mutex);
    debug_runtime_->software_breakpoints.clear();
    ++debug_runtime_->event_serial;
    debug_runtime_->event_address = 0;
    debug_runtime_->event_tid = 0;
    debug_runtime_->event_signal = 0;
    debug_runtime_->event_type = 0;
    debug_runtime_->exited = false;
}

std::unique_ptr<EngineFacade> create_engine_facade() {
    return std::make_unique<EngineFacade>();
}

} // namespace ce::bridge
