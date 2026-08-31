#pragma once

/// Toolkit-neutral live cheat-table controller.
///
/// This is the shared owner for address-list records used by the Rust/GTK
/// frontend.  It deliberately contains no Qt or GTK types: stable IDs, live
/// reads/writes, pointer-expression resolution and freeze policy belong in the
/// engine, while presentation and transient selection stay in the frontend.

#include "core/address_list.hpp"
#include "core/ct_file.hpp"
#include "core/value_codec.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ce {

class ProcessHandle;
class SymbolResolver;

/// Complete toolkit-neutral state of one address-list record.
///
/// Unlike AddressRecordSnapshot this is a lossless adapter/persistence value:
/// Qt may export its existing model into the shared controller, apply a core
/// hierarchy operation, and import it again without dropping codecs, hotkeys,
/// scripts, or CE-specific options. Runtime-only frontend objects (for example
/// Auto Assembler DisableInfo) deliberately stay in the owning frontend and are
/// associated by this record's stable id.
struct AddressRecordState {
    int id = 0;
    std::string description;
    uintptr_t address = 0;
    std::string addressExpression;
    ValueType type = ValueType::Int32;
    std::size_t byteCount = 0;
    std::string currentValue;
    std::string frozenValue;
    std::string error;
    bool readable = false;
    bool active = false;
    FreezeMode freezeMode = FreezeMode::Normal;
    bool showAsHex = false;
    bool showAsSigned = true;
    bool bigEndian = false;
    bool isGroup = false;
    bool collapsed = false;
    bool activateChildren = true;
    bool deactivateChildren = true;
    int indent = 0;
    std::string color;
    std::string script;
    std::string luaScript;
    std::string addressString;
    std::vector<std::int64_t> offsets;
    std::string dropdownList;
    std::string hotkeyKeys;
    std::string increaseHotkeyKeys;
    std::string decreaseHotkeyKeys;
    std::string setValueHotkeyKeys;
    std::string setValueHotkeyValue;
    std::string hotkeyStep = "1";
    std::string optionsXml;
    ValueCodec codec;
};

struct AddressRecordSnapshot {
    int id = 0;
    std::string description;
    uintptr_t address = 0;
    std::string addressExpression;
    ValueType type = ValueType::Int32;
    std::string value;
    std::string error;
    bool readable = false;
    bool active = false;
    FreezeMode freezeMode = FreezeMode::Normal;
    bool showAsHex = false;
    bool showAsSigned = true;
    bool bigEndian = false;
    std::size_t byteCount = 0;
    bool isGroup = false;
    bool collapsed = false;
    bool hasScript = false;
    int indent = 0;
};

struct AddressOperationResult {
    bool success = false;
    int id = 0;
    std::string errorCode;
    std::string errorMessage;
};

struct TableOperationResult {
    bool success = false;
    std::size_t recordCount = 0;
    bool containsScripts = false;
    std::string errorCode;
    std::string errorMessage;
};

class AddressListController final : public IAddressList {
public:
    AddressListController() = default;

    /// ProcessHandle is borrowed and must outlive its assignment here. Changing
    /// sessions always disables records so a stale freeze can never write into a
    /// newly attached process.
    void setProcess(ProcessHandle* process) noexcept;
    void setSymbolResolver(SymbolResolver* resolver) noexcept { symbolResolver_ = resolver; }

    std::uint64_t generation() const noexcept { return generation_; }
    std::vector<AddressRecordSnapshot> records(std::size_t start, std::size_t limit,
                                               bool refreshValues);
    AddressOperationResult addRecord(uintptr_t address, ValueType type,
                                     const std::string& description,
                                     std::size_t byteCount = 0,
                                     bool showAsHex = false);
    AddressOperationResult writeRecordValue(int id, const std::string& value);
    AddressOperationResult activateRecord(int id, bool active);
    AddressOperationResult removeRecord(int id);
    AddressOperationResult changeFreezeMode(int id, FreezeMode mode);
    AddressOperationResult groupRecords(const std::vector<int>& ids,
                                        const std::string& description);
    AddressOperationResult moveRecord(int id, int direction);
    AddressOperationResult moveRecordBlock(int id, std::size_t destination,
                                           int newRootIndent = -1);
    AddressOperationResult setRecordCollapsed(int id, bool collapsed);
    std::vector<AddressRecordState> exportRecords() const { return records_; }
    AddressOperationResult replaceRecords(std::vector<AddressRecordState> records,
                                          bool allowActiveScripts = false);
    TableOperationResult loadTable(const std::string& path);
    TableOperationResult saveTable(const std::string& path, bool json) const;
    void freezeTick() noexcept;

    // IAddressList
    int count() const override;
    std::optional<AddressEntrySnapshot> at(int index) const override;
    std::optional<AddressEntrySnapshot> byId(int id) const override;
    int findIdByDescription(const std::string& description) const override;
    std::vector<int> ids() const override;
    int createEntry(uintptr_t address, ValueType type,
                    const std::string& description) override;
    int createGroup(const std::string& description) override;
    bool deleteById(int id) override;
    bool disableWithoutExecute(int id) override;
    bool disableAllWithoutExecute() override;
    bool setDescription(int id, const std::string& description) override;
    bool setAddress(int id, uintptr_t address) override;
    bool setAddressExpression(int id, const std::string& expression) override;
    bool setType(int id, ValueType type) override;
    bool setValue(int id, const std::string& value) override;
    bool setActive(int id, bool active) override;
    bool setColor(int id, const std::string& color) override;
    bool setScript(int id, const std::string& script) override;
    std::string liveValue(int id) override;
    bool setFreezeMode(int id, int mode) override;
    bool setHexView(int id, bool hexadecimal) override;
    bool setByteCount(int id, std::size_t count) override;
    bool setSigned(int id, bool isSigned) override;
    bool setIndent(int id, int indent) override;
    void setActivationCallback(ActivationCallback callback) override {
        activationCallback_ = std::move(callback);
    }

private:
    using Record = AddressRecordState;

    int indexOf(int id) const noexcept;
    bool resolveAddress(Record& record);
    bool refreshRecord(Record& record);
    bool writeRecord(Record& record, const std::string& value);
    bool readComparable(const Record& record, double& value);
    bool parseComparable(const Record& record, const std::string& text,
                         double& value) const;
    AddressRecordSnapshot snapshot(const Record& record) const;
    AddressEntrySnapshot interfaceSnapshot(const Record& record) const;
    AddressOperationResult failure(int id, std::string code,
                                   std::string message) const;
    AddressOperationResult success(int id) const;

    std::vector<Record> records_;
    CheatTable tableMetadata_;
    ProcessHandle* process_ = nullptr;
    SymbolResolver* symbolResolver_ = nullptr;
    ActivationCallback activationCallback_;
    int nextId_ = 1;
    std::uint64_t generation_ = 1;
};

} // namespace ce
