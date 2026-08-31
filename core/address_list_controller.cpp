#include "core/address_list_controller.hpp"

#include "core/expression.hpp"
#include "core/value_transform.hpp"
#include "platform/process_api.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace ce {
namespace {

constexpr std::size_t kDefaultTextReadSize = 64;
constexpr std::size_t kDefaultByteArrayReadSize = 16;
constexpr std::size_t kMaxRecordValueSize = 1u << 20;

std::string trim(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

void appendUtf8(std::string& output, std::uint32_t codepoint) {
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

std::string sanitizeUtf8(const std::uint8_t* bytes, std::size_t size) {
    std::string output;
    output.reserve(size);
    for (std::size_t index = 0; index < size;) {
        const auto lead = bytes[index];
        if (lead == 0) break;
        std::size_t length = 0;
        std::uint32_t codepoint = 0;
        std::uint32_t minimum = 0;
        if (lead < 0x80) {
            output.push_back(static_cast<char>(lead));
            ++index;
            continue;
        }
        if ((lead & 0xe0) == 0xc0) {
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

        bool valid = length != 0 && index + length <= size;
        for (std::size_t offset = 1; valid && offset < length; ++offset) {
            const auto continuation = bytes[index + offset];
            valid = (continuation & 0xc0) == 0x80;
            if (valid) codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        valid = valid && codepoint >= minimum && codepoint <= 0x10ffff &&
                !(codepoint >= 0xd800 && codepoint <= 0xdfff);
        if (valid) {
            output.append(reinterpret_cast<const char*>(bytes + index), length);
            index += length;
        } else {
            appendUtf8(output, 0xfffd);
            ++index;
        }
    }
    return output;
}

std::string formatUtf16Le(const std::uint8_t* bytes, std::size_t size) {
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
        appendUtf8(output, codepoint);
    }
    return output;
}

bool decodeUtf8Codepoint(const std::string& input, std::size_t& index,
                         std::uint32_t& codepoint) {
    const auto lead = static_cast<std::uint8_t>(input[index]);
    if (lead < 0x80) {
        codepoint = lead;
        ++index;
        return true;
    }
    std::size_t length = 0;
    std::uint32_t minimum = 0;
    if ((lead & 0xe0) == 0xc0) {
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
    if (length == 0 || index + length > input.size()) {
        ++index;
        codepoint = 0xfffd;
        return false;
    }
    for (std::size_t offset = 1; offset < length; ++offset) {
        const auto continuation = static_cast<std::uint8_t>(input[index + offset]);
        if ((continuation & 0xc0) != 0x80) {
            ++index;
            codepoint = 0xfffd;
            return false;
        }
        codepoint = (codepoint << 6) | (continuation & 0x3f);
    }
    index += length;
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff)) {
        codepoint = 0xfffd;
        return false;
    }
    return true;
}

std::vector<std::uint8_t> encodeUtf16Le(const std::string& text) {
    std::vector<std::uint8_t> output;
    output.reserve(text.size() * 2);
    for (std::size_t index = 0; index < text.size();) {
        std::uint32_t codepoint = 0;
        decodeUtf8Codepoint(text, index, codepoint);
        if (codepoint <= 0xffff) {
            const auto unit = static_cast<std::uint16_t>(codepoint);
            output.push_back(static_cast<std::uint8_t>(unit));
            output.push_back(static_cast<std::uint8_t>(unit >> 8));
        } else {
            codepoint -= 0x10000;
            const auto high = static_cast<std::uint16_t>(0xd800 + (codepoint >> 10));
            const auto low = static_cast<std::uint16_t>(0xdc00 + (codepoint & 0x3ff));
            output.push_back(static_cast<std::uint8_t>(high));
            output.push_back(static_cast<std::uint8_t>(high >> 8));
            output.push_back(static_cast<std::uint8_t>(low));
            output.push_back(static_cast<std::uint8_t>(low >> 8));
        }
    }
    return output;
}

std::string formatBytes(const std::uint8_t* bytes, std::size_t size) {
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

bool parseBytes(const std::string& text, std::vector<std::uint8_t>& output) {
    std::istringstream stream(text);
    std::string token;
    while (stream >> token) {
        if (token.size() != 2) return false;
        unsigned value = 0;
        const auto parsed = std::from_chars(token.data(), token.data() + token.size(), value, 16);
        if (parsed.ec != std::errc{} || parsed.ptr != token.data() + token.size() || value > 0xff)
            return false;
        output.push_back(static_cast<std::uint8_t>(value));
    }
    return !output.empty();
}

bool parseFiniteDouble(std::string text, double& value) {
    text = trim(std::move(text));
    if (text.find('.') == std::string::npos)
        std::replace(text.begin(), text.end(), ',', '.');
    errno = 0;
    char* end = nullptr;
    value = std::strtod(text.c_str(), &end);
    return end != text.c_str() && *end == '\0' && errno != ERANGE && std::isfinite(value);
}

bool parsePointer(std::string text, bool hexadecimal, std::uint64_t& value) {
    text = trim(std::move(text));
    if (text.empty() || text[0] == '-') return false;
    int base = hexadecimal ? 16 : 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        base = 16;
        text.erase(0, 2);
    }
    if (text.empty()) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value, base);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
}

} // namespace

void AddressListController::setProcess(ProcessHandle* process) noexcept {
    if (process_ == process) return;
    disableAllWithoutExecute();
    process_ = process;
    for (auto& record : records_) {
        record.readable = false;
        record.error = process ? std::string{} : "No process is attached.";
        if (!process && !record.isGroup) record.currentValue = "??";
    }
}

int AddressListController::indexOf(int id) const noexcept {
    for (std::size_t index = 0; index < records_.size(); ++index)
        if (records_[index].id == id) return static_cast<int>(index);
    return -1;
}

AddressOperationResult AddressListController::failure(int id, std::string code,
                                                      std::string message) const {
    return {.success = false, .id = id, .errorCode = std::move(code),
            .errorMessage = std::move(message)};
}

AddressOperationResult AddressListController::success(int id) const {
    return {.success = true, .id = id, .errorCode = {}, .errorMessage = {}};
}

AddressOperationResult AddressListController::addRecord(
    uintptr_t address, ValueType type, const std::string& description,
    std::size_t byteCount, bool showAsHex) {
    if (byteCount > kMaxRecordValueSize)
        return failure(0, "value_too_large", "The address-list value width is too large.");
    Record record;
    record.id = nextId_++;
    record.description = description.empty() ? "No description" : description;
    record.address = address;
    record.type = type;
    record.byteCount = byteCount;
    record.showAsHex = showAsHex;
    const int id = record.id;
    records_.push_back(std::move(record));
    ++generation_;
    if (process_) refreshRecord(records_.back());
    return success(id);
}

bool AddressListController::resolveAddress(Record& record) {
    if (record.addressExpression.empty()) return true;
    if (!process_) {
        record.error = "No process is attached.";
        record.readable = false;
        return false;
    }
    try {
        ExpressionParser parser(process_, symbolResolver_);
        const auto resolved = parser.parse(record.addressExpression);
        if (!resolved) {
            record.error = "The address expression could not be resolved.";
            record.readable = false;
            return false;
        }
        record.address = *resolved;
        return true;
    } catch (...) {
        record.error = "The address expression could not be resolved.";
        record.readable = false;
        return false;
    }
}

bool AddressListController::refreshRecord(Record& record) {
    if (record.isGroup) {
        record.readable = true;
        record.error.clear();
        return true;
    }
    if (!process_) {
        record.currentValue = "??";
        record.readable = false;
        record.error = "No process is attached.";
        return false;
    }
    if (!resolveAddress(record)) {
        record.currentValue = "??";
        return false;
    }

    std::size_t width = static_cast<std::size_t>(std::max(0, scalarWidth(record.type)));
    bool variable = false;
    switch (record.type) {
        case ValueType::String:
        case ValueType::UnicodeString:
            width = record.byteCount != 0 ? record.byteCount : kDefaultTextReadSize;
            variable = true;
            break;
        case ValueType::ByteArray:
        case ValueType::Binary:
        case ValueType::All:
        case ValueType::Grouped:
        case ValueType::Custom:
            width = record.byteCount != 0 ? record.byteCount : kDefaultByteArrayReadSize;
            variable = true;
            break;
        default:
            break;
    }
    if (width == 0 || width > kMaxRecordValueSize) {
        record.currentValue = "??";
        record.readable = false;
        record.error = "The record value width is invalid.";
        return false;
    }

    std::vector<std::uint8_t> bytes(width);
    const auto read = process_->read(record.address, bytes.data(), width);
    if (!read || (!variable && *read != width) || (variable && *read == 0)) {
        record.currentValue = "??";
        record.readable = false;
        record.error = read ? "Only part of the value could be read."
                            : "The target memory could not be read: " + read.error().message();
        return false;
    }
    const std::size_t size = *read;
    const auto bits = decodeScalarBits(record.type, bytes.data(), record.bigEndian, record.codec);
    switch (record.type) {
        case ValueType::Byte:
        case ValueType::Int16:
        case ValueType::Int32:
        case ValueType::Int64:
            record.currentValue = formatIntegerScalar(
                bits, scalarWidth(record.type), record.showAsSigned, record.showAsHex);
            break;
        case ValueType::Pointer:
            record.currentValue = formatIntegerScalar(
                bits, scalarWidth(record.type), false, true);
            break;
        case ValueType::Float: {
            float value = 0;
            std::memcpy(&value, &bits, sizeof value);
            record.currentValue = formatFloatScalar(value, false);
            break;
        }
        case ValueType::Double: {
            double value = 0;
            std::memcpy(&value, &bits, sizeof value);
            record.currentValue = formatFloatScalar(value, true);
            break;
        }
        case ValueType::String:
            record.currentValue = sanitizeUtf8(bytes.data(), size);
            break;
        case ValueType::UnicodeString:
            record.currentValue = formatUtf16Le(bytes.data(), size);
            break;
        default:
            record.currentValue = formatBytes(bytes.data(), size);
            break;
    }
    record.readable = true;
    record.error.clear();
    return true;
}

bool AddressListController::writeRecord(Record& record, const std::string& value) {
    if (!process_) {
        record.error = "No process is attached.";
        record.readable = false;
        return false;
    }
    if (!resolveAddress(record)) return false;

    std::vector<std::uint8_t> bytes;
    const int scalar = scalarWidth(record.type);
    if (scalar > 0) {
        bytes.assign(static_cast<std::size_t>(scalar), 0);
        std::uint64_t bits = 0;
        if (record.type == ValueType::Byte || record.type == ValueType::Int16 ||
            record.type == ValueType::Int32 || record.type == ValueType::Int64) {
            bool ok = false;
            bits = static_cast<std::uint64_t>(parseIntegerScalar(value, record.showAsHex, ok));
            if (!ok) {
                record.error = "Enter a valid integer value.";
                return false;
            }
        } else if (record.type == ValueType::Pointer) {
            if (!parsePointer(value, record.showAsHex, bits)) {
                record.error = "Enter a valid pointer value.";
                return false;
            }
        } else {
            double parsed = 0;
            if (!parseFiniteDouble(value, parsed)) {
                record.error = "Enter a finite floating-point value.";
                return false;
            }
            if (record.type == ValueType::Float) {
                const float narrow = static_cast<float>(parsed);
                if (!std::isfinite(narrow)) {
                    record.error = "The value is outside the Float range.";
                    return false;
                }
                std::memcpy(&bits, &narrow, sizeof narrow);
            } else {
                std::memcpy(&bits, &parsed, sizeof parsed);
            }
        }
        encodeScalarBits(record.type, bits, record.bigEndian, record.codec, bytes.data());
    } else if (record.type == ValueType::String) {
        bytes.assign(value.begin(), value.end());
        if (record.byteCount != 0) {
            if (bytes.size() > record.byteCount) {
                record.error = "The encoded string is longer than this record's byte width.";
                return false;
            }
            bytes.resize(record.byteCount, 0);
        } else if (bytes.empty()) {
            bytes.push_back(0);
        }
    } else if (record.type == ValueType::UnicodeString) {
        bytes = encodeUtf16Le(value);
        if (record.byteCount != 0) {
            if (bytes.size() > record.byteCount) {
                record.error = "The UTF-16 string is longer than this record's byte width.";
                return false;
            }
            bytes.resize(record.byteCount, 0);
        } else if (bytes.empty()) {
            bytes.resize(2, 0);
        }
    } else if (record.type == ValueType::ByteArray) {
        if (!parseBytes(value, bytes)) {
            record.error = "Enter complete hexadecimal bytes such as '90 90 48 8B'.";
            return false;
        }
        if (record.byteCount != 0 && bytes.size() != record.byteCount) {
            record.error = "The byte array must keep this record's original width.";
            return false;
        }
    } else {
        record.error = "This record type cannot be edited yet.";
        return false;
    }

    if (bytes.empty() || bytes.size() > kMaxRecordValueSize) {
        record.error = "The encoded value width is invalid.";
        return false;
    }
    const auto written = process_->write(record.address, bytes.data(), bytes.size());
    if (!written || *written != bytes.size()) {
        record.error = written ? "Only part of the value could be written."
                               : "The target memory could not be written: " + written.error().message();
        record.readable = false;
        return false;
    }
    record.currentValue = value;
    record.readable = true;
    record.error.clear();
    return true;
}

bool AddressListController::readComparable(const Record& record, double& value) {
    if (!process_) return false;
    const int width = scalarWidth(record.type);
    if (width <= 0) return false;
    std::uint8_t bytes[8] = {};
    const auto read = process_->read(record.address, bytes, static_cast<std::size_t>(width));
    if (!read || *read != static_cast<std::size_t>(width)) return false;
    const auto bits = decodeScalarBits(record.type, bytes, record.bigEndian, record.codec);
    switch (record.type) {
        case ValueType::Byte:
            value = record.showAsSigned ? static_cast<double>(static_cast<std::int8_t>(bits))
                                        : static_cast<double>(static_cast<std::uint8_t>(bits));
            return true;
        case ValueType::Int16:
            value = record.showAsSigned ? static_cast<double>(static_cast<std::int16_t>(bits))
                                        : static_cast<double>(static_cast<std::uint16_t>(bits));
            return true;
        case ValueType::Int32:
            value = record.showAsSigned ? static_cast<double>(static_cast<std::int32_t>(bits))
                                        : static_cast<double>(static_cast<std::uint32_t>(bits));
            return true;
        case ValueType::Int64:
            value = record.showAsSigned ? static_cast<double>(static_cast<std::int64_t>(bits))
                                        : static_cast<double>(bits);
            return true;
        case ValueType::Pointer:
            value = static_cast<double>(bits);
            return true;
        case ValueType::Float: {
            float scalarValue = 0;
            std::memcpy(&scalarValue, &bits, sizeof scalarValue);
            value = scalarValue;
            return std::isfinite(value);
        }
        case ValueType::Double:
            std::memcpy(&value, &bits, sizeof value);
            return std::isfinite(value);
        default:
            return false;
    }
}

bool AddressListController::parseComparable(const Record& record, const std::string& text,
                                            double& value) const {
    if (record.type == ValueType::Byte || record.type == ValueType::Int16 ||
        record.type == ValueType::Int32 || record.type == ValueType::Int64) {
        bool ok = false;
        const auto parsed = parseIntegerScalar(text, record.showAsHex, ok);
        value = static_cast<double>(parsed);
        return ok;
    }
    if (record.type == ValueType::Pointer) {
        std::uint64_t parsed = 0;
        if (!parsePointer(text, true, parsed)) return false;
        value = static_cast<double>(parsed);
        return true;
    }
    if (record.type == ValueType::Float || record.type == ValueType::Double)
        return parseFiniteDouble(text, value);
    return false;
}

AddressOperationResult AddressListController::writeRecordValue(int id,
                                                               const std::string& value) {
    const int index = indexOf(id);
    if (index < 0) return failure(id, "record_not_found", "The address-list record no longer exists.");
    auto& record = records_[static_cast<std::size_t>(index)];
    if (record.isGroup) return failure(id, "group_not_editable", "A group has no memory value.");
    if (!writeRecord(record, value)) return failure(id, "write_failed", record.error);
    if (record.active) record.frozenValue = record.currentValue;
    return success(id);
}

AddressOperationResult AddressListController::activateRecord(int id, bool active) {
    const int index = indexOf(id);
    if (index < 0) return failure(id, "record_not_found", "The address-list record no longer exists.");
    auto& record = records_[static_cast<std::size_t>(index)];
    if (record.isGroup) return failure(id, "group_not_freezable", "A group cannot be frozen.");
    if (record.active == active) return success(id);
    if (active) {
        if (!refreshRecord(record)) return failure(id, "read_failed", record.error);
        record.frozenValue = record.currentValue;
    } else {
        record.frozenValue.clear();
    }
    record.active = active;
    if (activationCallback_) activationCallback_(id, active);
    return success(id);
}

AddressOperationResult AddressListController::changeFreezeMode(int id, FreezeMode mode) {
    const int index = indexOf(id);
    if (index < 0) return failure(id, "record_not_found", "The address-list record no longer exists.");
    records_[static_cast<std::size_t>(index)].freezeMode = mode;
    return success(id);
}

AddressOperationResult AddressListController::removeRecord(int id) {
    const int index = indexOf(id);
    if (index < 0) return failure(id, "record_not_found", "The address-list record no longer exists.");
    std::vector<int> indents;
    indents.reserve(records_.size());
    for (const auto& record : records_) indents.push_back(record.indent);
    const auto remove = expandGroupDeletion(indents, {static_cast<std::size_t>(index)});
    for (auto iterator = remove.rbegin(); iterator != remove.rend(); ++iterator)
        records_.erase(records_.begin() + static_cast<std::ptrdiff_t>(*iterator));
    ++generation_;
    return success(id);
}

void AddressListController::freezeTick() noexcept {
    try {
        if (!process_) return;
        for (auto& record : records_) {
            if (!record.active || record.isGroup || record.frozenValue.empty()) continue;
            if (!resolveAddress(record)) continue;
            bool shouldWrite = true;
            if (record.freezeMode != FreezeMode::Normal) {
                double current = 0;
                double frozen = 0;
                if (readComparable(record, current) &&
                    parseComparable(record, record.frozenValue, frozen))
                    shouldWrite = freezeShouldWrite(record.freezeMode, current, frozen);
            }
            if (shouldWrite) writeRecord(record, record.frozenValue);
        }
    } catch (...) {
        // Freeze runs from a UI timer and must never unwind through the CXX ABI.
    }
}

AddressRecordSnapshot AddressListController::snapshot(const Record& record) const {
    return {.id = record.id,
            .description = record.description,
            .address = record.address,
            .addressExpression = record.addressExpression,
            .type = record.type,
            .value = record.currentValue,
            .error = record.error,
            .readable = record.readable,
            .active = record.active,
            .freezeMode = record.freezeMode,
            .showAsHex = record.showAsHex,
            .showAsSigned = record.showAsSigned,
            .bigEndian = record.bigEndian,
            .byteCount = record.byteCount,
            .isGroup = record.isGroup,
            .indent = record.indent};
}

AddressEntrySnapshot AddressListController::interfaceSnapshot(const Record& record) const {
    AddressEntrySnapshot snapshot;
    snapshot.id = record.id;
    snapshot.description = record.description;
    snapshot.address = record.address;
    snapshot.type = record.type;
    snapshot.value = record.currentValue;
    snapshot.color = record.color;
    snapshot.script = record.script;
    snapshot.hotkeyKeys = record.hotkeyKeys;
    snapshot.active = record.active;
    snapshot.isGroup = record.isGroup;
    snapshot.showAsHex = record.showAsHex;
    snapshot.indent = record.indent;
    return snapshot;
}

std::vector<AddressRecordSnapshot> AddressListController::records(
    std::size_t start, std::size_t limit, bool refreshValues) {
    std::vector<AddressRecordSnapshot> output;
    if (start >= records_.size() || limit == 0) return output;
    const auto end = std::min(records_.size(), start + std::min(limit, records_.size() - start));
    output.reserve(end - start);
    for (std::size_t index = start; index < end; ++index) {
        if (refreshValues && !records_[index].active) refreshRecord(records_[index]);
        output.push_back(snapshot(records_[index]));
    }
    return output;
}

int AddressListController::count() const { return static_cast<int>(records_.size()); }

std::optional<AddressEntrySnapshot> AddressListController::at(int index) const {
    if (index < 0 || index >= count()) return std::nullopt;
    return interfaceSnapshot(records_[static_cast<std::size_t>(index)]);
}

std::optional<AddressEntrySnapshot> AddressListController::byId(int id) const {
    const int index = indexOf(id);
    return index < 0 ? std::nullopt
                     : std::optional(interfaceSnapshot(records_[static_cast<std::size_t>(index)]));
}

int AddressListController::findIdByDescription(const std::string& description) const {
    for (const auto& record : records_)
        if (record.description == description) return record.id;
    return -1;
}

std::vector<int> AddressListController::ids() const {
    std::vector<int> output;
    output.reserve(records_.size());
    for (const auto& record : records_) output.push_back(record.id);
    return output;
}

int AddressListController::createEntry(uintptr_t address, ValueType type,
                                       const std::string& description) {
    const auto result = addRecord(address, type, description);
    return result.success ? result.id : -1;
}

int AddressListController::createGroup(const std::string& description) {
    Record record;
    record.id = nextId_++;
    record.description = description.empty() ? "-- Group --" : description;
    record.isGroup = true;
    const int id = record.id;
    records_.push_back(std::move(record));
    ++generation_;
    return id;
}

bool AddressListController::deleteById(int id) { return removeRecord(id).success; }

bool AddressListController::disableAllWithoutExecute() {
    bool changed = false;
    for (auto& record : records_) {
        if (!record.active) continue;
        record.active = false;
        record.frozenValue.clear();
        changed = true;
        if (activationCallback_) activationCallback_(record.id, false);
    }
    return changed;
}

bool AddressListController::setDescription(int id, const std::string& description) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].description = description;
    ++generation_;
    return true;
}

bool AddressListController::setAddress(int id, uintptr_t address) {
    const int index = indexOf(id);
    if (index < 0) return false;
    auto& record = records_[static_cast<std::size_t>(index)];
    record.address = address;
    record.addressExpression.clear();
    record.active = false;
    record.frozenValue.clear();
    return true;
}

bool AddressListController::setAddressExpression(int id, const std::string& expression) {
    const int index = indexOf(id);
    if (index < 0) return false;
    auto& record = records_[static_cast<std::size_t>(index)];
    record.addressExpression = expression;
    record.active = false;
    record.frozenValue.clear();
    return resolveAddress(record);
}

bool AddressListController::setType(int id, ValueType type) {
    const int index = indexOf(id);
    if (index < 0) return false;
    auto& record = records_[static_cast<std::size_t>(index)];
    record.type = type;
    record.active = false;
    record.frozenValue.clear();
    record.currentValue.clear();
    return true;
}

bool AddressListController::setValue(int id, const std::string& value) {
    return writeRecordValue(id, value).success;
}

bool AddressListController::setActive(int id, bool active) {
    return activateRecord(id, active).success;
}

bool AddressListController::setColor(int id, const std::string& color) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].color = color;
    return true;
}

bool AddressListController::setScript(int id, const std::string& script) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].script = script;
    return true;
}

std::string AddressListController::liveValue(int id) {
    const int index = indexOf(id);
    if (index < 0) return {};
    auto& record = records_[static_cast<std::size_t>(index)];
    refreshRecord(record);
    return record.currentValue;
}

bool AddressListController::setFreezeMode(int id, int mode) {
    if (mode < 0 || mode > static_cast<int>(FreezeMode::NeverDecrease)) return false;
    return changeFreezeMode(id, static_cast<FreezeMode>(mode)).success;
}

bool AddressListController::setHexView(int id, bool hexadecimal) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].showAsHex = hexadecimal;
    return true;
}

bool AddressListController::setByteCount(int id, std::size_t count) {
    const int index = indexOf(id);
    if (index < 0 || count > kMaxRecordValueSize) return false;
    records_[static_cast<std::size_t>(index)].byteCount = count;
    return true;
}

bool AddressListController::setSigned(int id, bool isSigned) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].showAsSigned = isSigned;
    return true;
}

bool AddressListController::setIndent(int id, int indent) {
    const int index = indexOf(id);
    if (index < 0) return false;
    records_[static_cast<std::size_t>(index)].indent = std::max(0, indent);
    ++generation_;
    return true;
}

} // namespace ce
