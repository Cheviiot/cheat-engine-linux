#include "bridge/engine_facade.hpp"

#include "ce-gtk/src/bridge.rs.h"
#include "core/address_list_controller.hpp"
#include "core/target_profile.hpp"
#include "core/value_transform.hpp"
#include "core/version.hpp"
#include "platform/linux/linux_process.hpp"
#include "scanner/memory_scanner.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <limits>
#include <optional>
#include <sstream>
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
constexpr std::uint32_t kMaxAddressPageSize = 256;
constexpr std::size_t kMaxScanValueSize = 1u << 20;
constexpr std::size_t kMaxScanTextSize = 1u << 20;
constexpr std::size_t kMaxAddressTextSize = 1u << 20;
constexpr std::size_t kMaxAddressDescriptionSize = 1024;
constexpr std::size_t kMaxAddressGroupSelection = 4096;
constexpr std::size_t kMaxTablePathSize = 4096;

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

} // namespace

EngineFacade::EngineFacade()
    : address_list_(std::make_unique<ce::AddressListController>()) {}

EngineFacade::~EngineFacade() {
    cancel_scan();
    join_scan_worker();
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
            clear_scan_state();
            process_ = std::move(candidate);
            address_list_->setProcess(process_.get());
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
    address_list_->setProcess(nullptr);
    process_.reset();
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

AddressActionResult EngineFacade::set_address_active(std::int32_t id, bool active) {
    const auto result = address_list_->activateRecord(id, active);
    return AddressActionResult{
        .accepted = result.success,
        .id = result.id,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
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
            .error_code = "invalid_path",
            .error_message = "The cheat-table path is invalid or too long.",
        };
    }
    const auto result = address_list_->loadTable(file);
    return TableActionResult{
        .accepted = result.success,
        .record_count = static_cast<std::uint64_t>(result.recordCount),
        .contains_scripts = result.containsScripts,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

TableActionResult EngineFacade::save_table(rust::Str path, bool json) const {
    std::string file(path);
    if (file.size() > kMaxTablePathSize || file.find('\0') != std::string::npos) {
        return TableActionResult{
            .accepted = false,
            .record_count = 0,
            .contains_scripts = false,
            .error_code = "invalid_path",
            .error_message = "The cheat-table path is invalid or too long.",
        };
    }
    const auto result = address_list_->saveTable(file, json);
    return TableActionResult{
        .accepted = result.success,
        .record_count = static_cast<std::uint64_t>(result.recordCount),
        .contains_scripts = result.containsScripts,
        .error_code = result.errorCode,
        .error_message = result.errorMessage,
    };
}

void EngineFacade::freeze_addresses() noexcept {
    address_list_->freezeTick();
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

std::unique_ptr<EngineFacade> create_engine_facade() {
    return std::make_unique<EngineFacade>();
}

} // namespace ce::bridge
