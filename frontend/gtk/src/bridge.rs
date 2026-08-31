#[cxx::bridge(namespace = "ce::bridge")]
mod ffi {
    struct ProcessRow {
        pid: i32,
        name: String,
        path: String,
        sandboxed: bool,
    }

    struct AttachResult {
        success: bool,
        pid: i32,
        name: String,
        summary: String,
        arch: String,
        endianness: String,
        wine: bool,
        sandboxed: bool,
        already_traced: bool,
        tracer_pid: i32,
        yama_scope: String,
        notes: Vec<String>,
        error_code: String,
        error_message: String,
    }

    struct ScanStartResult {
        accepted: bool,
        error_code: String,
        error_message: String,
    }

    struct ScanActionResult {
        accepted: bool,
        generation: u64,
        result_count: u64,
        undo_available: bool,
        error_code: String,
        error_message: String,
    }

    struct ScanRequest {
        value_type: u8,
        comparison: u8,
        value: String,
        value2: String,
        hexadecimal: bool,
        alignment: u32,
        start_address: u64,
        stop_address: u64,
        writable_match: u8,
        executable_match: u8,
        scan_private: bool,
        scan_image: bool,
        scan_mapped: bool,
        rounding_type: i32,
        float_decimals: i32,
        float_tolerance: f64,
        percentage_scan: bool,
        percentage_value: f64,
        percentage_value2: f64,
        case_sensitive: bool,
        string_encoding: String,
        value_size: u32,
    }

    struct ScanHit {
        address: u64,
        value: String,
    }

    struct ScanStatus {
        started: bool,
        generation: u64,
        running: bool,
        cancel_requested: bool,
        cancelled: bool,
        completed: bool,
        progress: f32,
        result_count: u64,
        write_error: bool,
        result_available: bool,
        undo_available: bool,
        error_message: String,
    }

    struct ScanPage {
        generation: u64,
        start: u64,
        total_count: u64,
        stale: bool,
        error_message: String,
        rows: Vec<ScanHit>,
    }

    struct DisassemblyRow {
        address: u64,
        bytes: String,
        mnemonic: String,
        operands: String,
        size: u8,
        follow_target: u64,
    }

    struct MemoryViewResult {
        accepted: bool,
        address: u64,
        next_address: u64,
        arch: String,
        region: String,
        bytes: Vec<u8>,
        instructions: Vec<DisassemblyRow>,
        error_code: String,
        error_message: String,
    }

    struct MemorySearchResult {
        accepted: bool,
        found: bool,
        complete: bool,
        address: u64,
        next_address: u64,
        scanned_bytes: u64,
        error_code: String,
        error_message: String,
    }

    struct MemoryWriteResult {
        accepted: bool,
        written: u32,
        protection_changed: bool,
        protection_restored: bool,
        warning: String,
        error_code: String,
        error_message: String,
    }

    struct AddressRow {
        id: i32,
        description: String,
        address: u64,
        address_expression: String,
        value_type: u8,
        type_name: String,
        value: String,
        error_message: String,
        readable: bool,
        active: bool,
        freeze_mode: u8,
        show_as_hex: bool,
        byte_count: u32,
        is_group: bool,
        collapsed: bool,
        has_script: bool,
        has_auto_assembler: bool,
        has_lua: bool,
        indent: i32,
    }

    struct AddressPage {
        generation: u64,
        start: u64,
        total_count: u64,
        raw_total_count: u64,
        error_message: String,
        rows: Vec<AddressRow>,
    }

    struct AddressActionResult {
        accepted: bool,
        id: i32,
        error_code: String,
        error_message: String,
    }

    struct TableCompatibilityIssueRow {
        code: String,
        title: String,
        detail: String,
        count: u64,
        preserved: bool,
    }

    struct TableActionResult {
        accepted: bool,
        record_count: u64,
        contains_scripts: bool,
        contains_auto_assembler: bool,
        contains_lua: bool,
        error_code: String,
        error_message: String,
        compatibility_issues: Vec<TableCompatibilityIssueRow>,
    }

    struct TableScriptRow {
        record_id: i32,
        kind: u8,
        description: String,
        byte_count: u64,
    }

    struct TableScriptPage {
        start: u64,
        next_start: u64,
        total_count: u64,
        truncated: bool,
        rows: Vec<TableScriptRow>,
    }

    struct TableScriptTextPage {
        accepted: bool,
        record_id: i32,
        kind: u8,
        offset: u64,
        next_offset: u64,
        total_bytes: u64,
        truncated: bool,
        text: String,
        error_code: String,
        error_message: String,
    }

    struct LuaExecutionResult {
        accepted: bool,
        record_id: i32,
        kind: u8,
        output: String,
        output_truncated: bool,
        runtime_error: String,
        error_code: String,
        error_message: String,
    }

    struct LuaConsoleResult {
        accepted: bool,
        runtime_generation: u64,
        output: String,
        output_truncated: bool,
        runtime_error: String,
        error_code: String,
        error_message: String,
    }

    struct RuntimeTickResult {
        runtime_generation: u64,
        address_generation: u64,
        address_refresh_due: bool,
        timer_count: u32,
        timers_fired: u32,
        timer_errors: u32,
        timers_deferred: u32,
        output: String,
        output_truncated: bool,
    }

    unsafe extern "C++" {
        include!("bridge/engine_facade.hpp");

        type EngineFacade;

        fn create_engine_facade() -> UniquePtr<EngineFacade>;
        fn version(self: &EngineFacade) -> String;
        fn list_processes(self: &EngineFacade, query: &str, limit: u32) -> Vec<ProcessRow>;
        fn attach(self: Pin<&mut EngineFacade>, pid: i32, display_name: &str) -> AttachResult;
        fn detach(self: Pin<&mut EngineFacade>) -> AddressActionResult;
        fn is_attached(self: &EngineFacade) -> bool;
        fn attached_pid(self: &EngineFacade) -> i32;
        fn start_first_scan(self: Pin<&mut EngineFacade>, request: &ScanRequest)
        -> ScanStartResult;
        fn start_next_scan(self: Pin<&mut EngineFacade>, request: &ScanRequest) -> ScanStartResult;
        fn undo_scan(self: Pin<&mut EngineFacade>) -> ScanActionResult;
        fn scan_status(self: &EngineFacade) -> ScanStatus;
        fn scan_rows(self: &EngineFacade, generation: u64, start: u64, limit: u32) -> ScanPage;
        fn memory_view(
            self: &EngineFacade,
            address: u64,
            byte_count: u32,
            instruction_limit: u32,
        ) -> MemoryViewResult;
        fn memory_search(
            self: &EngineFacade,
            pattern: &[u8],
            mask: &[u8],
            start: u64,
            backward: bool,
            page_bytes: u32,
        ) -> MemorySearchResult;
        fn memory_write(
            self: Pin<&mut EngineFacade>,
            address: u64,
            bytes: &[u8],
            allow_protection_change: bool,
        ) -> MemoryWriteResult;
        fn cancel_scan(self: Pin<&mut EngineFacade>);
        fn visible_address_rows(
            self: Pin<&mut EngineFacade>,
            start: u64,
            limit: u32,
            refresh_values: bool,
        ) -> AddressPage;
        fn add_scan_result(
            self: Pin<&mut EngineFacade>,
            scan_generation: u64,
            scan_index: u64,
            description: &str,
        ) -> AddressActionResult;
        fn add_address(
            self: Pin<&mut EngineFacade>,
            address: u64,
            value_type: u8,
            description: &str,
            byte_count: u32,
            show_as_hex: bool,
        ) -> AddressActionResult;
        fn set_address_value(
            self: Pin<&mut EngineFacade>,
            id: i32,
            value: &str,
        ) -> AddressActionResult;
        fn set_address_active(
            self: Pin<&mut EngineFacade>,
            id: i32,
            active: bool,
        ) -> AddressActionResult;
        fn set_address_freeze_mode(
            self: Pin<&mut EngineFacade>,
            id: i32,
            mode: u8,
        ) -> AddressActionResult;
        fn delete_address(self: Pin<&mut EngineFacade>, id: i32) -> AddressActionResult;
        fn add_address_group(
            self: Pin<&mut EngineFacade>,
            description: &str,
        ) -> AddressActionResult;
        fn group_addresses(
            self: Pin<&mut EngineFacade>,
            ids: &[i32],
            description: &str,
        ) -> AddressActionResult;
        fn move_address(
            self: Pin<&mut EngineFacade>,
            id: i32,
            direction: i32,
        ) -> AddressActionResult;
        fn set_address_collapsed(
            self: Pin<&mut EngineFacade>,
            id: i32,
            collapsed: bool,
        ) -> AddressActionResult;
        fn load_table(self: Pin<&mut EngineFacade>, path: &str) -> TableActionResult;
        fn load_protected_table(
            self: Pin<&mut EngineFacade>,
            path: &str,
            password: &str,
        ) -> TableActionResult;
        fn table_compatibility_issues(
            self: &EngineFacade,
            json_destination: bool,
        ) -> Vec<TableCompatibilityIssueRow>;
        fn save_table(self: &EngineFacade, path: &str, json: bool) -> TableActionResult;
        fn table_scripts(self: &EngineFacade, start: u64, limit: u32) -> TableScriptPage;
        fn table_script_text(
            self: &EngineFacade,
            record_id: i32,
            kind: u8,
            offset: u64,
            limit: u32,
        ) -> TableScriptTextPage;
        fn set_table_scripts_trusted(
            self: Pin<&mut EngineFacade>,
            trusted: bool,
        ) -> AddressActionResult;
        fn table_scripts_trusted(self: &EngineFacade) -> bool;
        fn set_table_lua_trusted(
            self: Pin<&mut EngineFacade>,
            trusted: bool,
        ) -> AddressActionResult;
        fn table_lua_trusted(self: &EngineFacade) -> bool;
        fn execute_table_lua(
            self: Pin<&mut EngineFacade>,
            record_id: i32,
            kind: u8,
        ) -> LuaExecutionResult;
        fn execute_lua_console(self: Pin<&mut EngineFacade>, source: &str) -> LuaConsoleResult;
        fn lua_runtime_generation(self: &EngineFacade) -> u64;
        fn periodic_tick(self: Pin<&mut EngineFacade>) -> RuntimeTickResult;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Process {
    pub pid: i32,
    pub name: String,
    pub path: String,
    pub sandboxed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Session {
    pub pid: i32,
    pub name: String,
    pub summary: String,
    pub arch: String,
    pub endianness: String,
    pub wine: bool,
    pub sandboxed: bool,
    pub already_traced: bool,
    pub tracer_pid: i32,
    pub yama_scope: String,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttachError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScanValueType {
    Byte = 0,
    Int16 = 1,
    Int32 = 2,
    Int64 = 3,
    Float = 4,
    Double = 5,
    String = 6,
    UnicodeString = 7,
    ByteArray = 8,
    Binary = 9,
    All = 10,
    Pointer = 11,
    Grouped = 12,
    Custom = 13,
}

impl ScanValueType {
    pub const LABELS: [&'static str; 14] = [
        "Byte",
        "2 Bytes",
        "4 Bytes",
        "8 Bytes",
        "Float",
        "Double",
        "String",
        "Unicode String",
        "Array of byte",
        "Binary",
        "All",
        "Pointer",
        "Grouped",
        "Custom",
    ];

    pub fn from_index(index: u32) -> Option<Self> {
        Some(match index {
            0 => Self::Byte,
            1 => Self::Int16,
            2 => Self::Int32,
            3 => Self::Int64,
            4 => Self::Float,
            5 => Self::Double,
            6 => Self::String,
            7 => Self::UnicodeString,
            8 => Self::ByteArray,
            9 => Self::Binary,
            10 => Self::All,
            11 => Self::Pointer,
            12 => Self::Grouped,
            13 => Self::Custom,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScanComparison {
    Exact = 0,
    Greater = 1,
    Less = 2,
    Between = 3,
    Unknown = 4,
    Changed = 5,
    Unchanged = 6,
    Increased = 7,
    Decreased = 8,
    IncreasedBy = 9,
    DecreasedBy = 10,
    SameAsFirst = 11,
}

impl ScanComparison {
    pub const LABELS: [&'static str; 12] = [
        "Exact value",
        "Greater than",
        "Less than",
        "Value between",
        "Unknown initial value",
        "Changed value",
        "Unchanged value",
        "Increased value",
        "Decreased value",
        "Increased by",
        "Decreased by",
        "Same as first scan",
    ];

    pub fn from_index(index: u32) -> Option<Self> {
        Some(match index {
            0 => Self::Exact,
            1 => Self::Greater,
            2 => Self::Less,
            3 => Self::Between,
            4 => Self::Unknown,
            5 => Self::Changed,
            6 => Self::Unchanged,
            7 => Self::Increased,
            8 => Self::Decreased,
            9 => Self::IncreasedBy,
            10 => Self::DecreasedBy,
            11 => Self::SameAsFirst,
            _ => return None,
        })
    }

    pub fn takes_value(self) -> bool {
        matches!(
            self,
            Self::Exact
                | Self::Greater
                | Self::Less
                | Self::Between
                | Self::IncreasedBy
                | Self::DecreasedBy
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ProtectionMatch {
    Any = 0,
    Yes = 1,
    No = 2,
}

impl ProtectionMatch {
    pub const LABELS: [&'static str; 3] = ["Any", "Required", "Excluded"];

    pub fn from_index(index: u32) -> Option<Self> {
        Some(match index {
            0 => Self::Any,
            1 => Self::Yes,
            2 => Self::No,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScanRequest {
    pub value_type: ScanValueType,
    pub comparison: ScanComparison,
    pub value: String,
    pub value2: String,
    pub hexadecimal: bool,
    pub alignment: u32,
    pub start_address: u64,
    pub stop_address: u64,
    pub writable_match: ProtectionMatch,
    pub executable_match: ProtectionMatch,
    pub scan_private: bool,
    pub scan_image: bool,
    pub scan_mapped: bool,
    pub rounding_type: i32,
    pub float_decimals: i32,
    pub float_tolerance: f64,
    pub percentage_scan: bool,
    pub percentage_value: f64,
    pub percentage_value2: f64,
    pub case_sensitive: bool,
    pub string_encoding: String,
    pub value_size: u32,
}

impl Default for ScanRequest {
    fn default() -> Self {
        Self {
            value_type: ScanValueType::Int32,
            comparison: ScanComparison::Exact,
            value: String::new(),
            value2: String::new(),
            hexadecimal: false,
            alignment: 4,
            start_address: 0,
            stop_address: 0x0000_7fff_ffff_ffff,
            writable_match: ProtectionMatch::Any,
            executable_match: ProtectionMatch::Any,
            scan_private: true,
            scan_image: true,
            scan_mapped: true,
            rounding_type: 0,
            float_decimals: -1,
            float_tolerance: 0.0,
            percentage_scan: false,
            percentage_value: 0.0,
            percentage_value2: 0.0,
            case_sensitive: true,
            string_encoding: "UTF-8".to_owned(),
            value_size: 0,
        }
    }
}

impl ScanRequest {
    fn to_ffi(&self) -> ffi::ScanRequest {
        ffi::ScanRequest {
            value_type: self.value_type as u8,
            comparison: self.comparison as u8,
            value: self.value.clone(),
            value2: self.value2.clone(),
            hexadecimal: self.hexadecimal,
            alignment: self.alignment,
            start_address: self.start_address,
            stop_address: self.stop_address,
            writable_match: self.writable_match as u8,
            executable_match: self.executable_match as u8,
            scan_private: self.scan_private,
            scan_image: self.scan_image,
            scan_mapped: self.scan_mapped,
            rounding_type: self.rounding_type,
            float_decimals: self.float_decimals,
            float_tolerance: self.float_tolerance,
            percentage_scan: self.percentage_scan,
            percentage_value: self.percentage_value,
            percentage_value2: self.percentage_value2,
            case_sensitive: self.case_sensitive,
            string_encoding: self.string_encoding.clone(),
            value_size: self.value_size,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanHit {
    pub address: u64,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ScanStatus {
    pub started: bool,
    pub generation: u64,
    pub running: bool,
    pub cancel_requested: bool,
    pub cancelled: bool,
    pub completed: bool,
    pub progress: f32,
    pub result_count: u64,
    pub write_error: bool,
    pub result_available: bool,
    pub undo_available: bool,
    pub error_message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanAction {
    pub generation: u64,
    pub result_count: u64,
    pub undo_available: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanPage {
    pub generation: u64,
    pub start: u64,
    pub total_count: u64,
    pub stale: bool,
    pub error_message: String,
    pub rows: Vec<ScanHit>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DisassemblyRow {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub size: u8,
    pub follow_target: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryView {
    pub address: u64,
    pub next_address: u64,
    pub arch: String,
    pub region: String,
    pub bytes: Vec<u8>,
    pub instructions: Vec<DisassemblyRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemorySearch {
    pub found: bool,
    pub complete: bool,
    pub address: u64,
    pub next_address: u64,
    pub scanned_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemoryWrite {
    pub written: u32,
    pub protection_changed: bool,
    pub protection_restored: bool,
    pub warning: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FreezeMode {
    Normal = 0,
    IncreaseOnly = 1,
    DecreaseOnly = 2,
    NeverIncrease = 3,
    NeverDecrease = 4,
}

impl FreezeMode {
    pub const LABELS: [&'static str; 5] = [
        "Locked",
        "Allow increase",
        "Allow decrease",
        "Never increase",
        "Never decrease",
    ];

    pub fn from_index(index: u32) -> Option<Self> {
        Some(match index {
            0 => Self::Normal,
            1 => Self::IncreaseOnly,
            2 => Self::DecreaseOnly,
            3 => Self::NeverIncrease,
            4 => Self::NeverDecrease,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressRecord {
    pub id: i32,
    pub description: String,
    pub address: u64,
    pub address_expression: String,
    pub value_type: ScanValueType,
    pub type_name: String,
    pub value: String,
    pub error_message: String,
    pub readable: bool,
    pub active: bool,
    pub freeze_mode: FreezeMode,
    pub show_as_hex: bool,
    pub byte_count: u32,
    pub is_group: bool,
    pub collapsed: bool,
    pub has_script: bool,
    pub has_auto_assembler: bool,
    pub has_lua: bool,
    pub indent: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressPage {
    pub generation: u64,
    pub start: u64,
    pub total_count: u64,
    pub raw_total_count: u64,
    pub error_message: String,
    pub rows: Vec<AddressRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddressError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableAction {
    pub record_count: u64,
    pub contains_scripts: bool,
    pub contains_auto_assembler: bool,
    pub contains_lua: bool,
    pub compatibility_issues: Vec<TableCompatibilityIssue>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableCompatibilityIssue {
    pub code: String,
    pub title: String,
    pub detail: String,
    pub count: u64,
    pub preserved: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableScriptKind {
    TableLua,
    AutoAssembler,
    RecordLua,
    Unknown(u8),
}

impl TableScriptKind {
    fn from_bridge(value: u8) -> Self {
        match value {
            0 => Self::TableLua,
            1 => Self::AutoAssembler,
            2 => Self::RecordLua,
            value => Self::Unknown(value),
        }
    }

    fn bridge_value(self) -> u8 {
        match self {
            Self::TableLua => 0,
            Self::AutoAssembler => 1,
            Self::RecordLua => 2,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableScript {
    pub record_id: i32,
    pub kind: TableScriptKind,
    pub description: String,
    pub byte_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableScriptPage {
    pub start: u64,
    pub next_start: u64,
    pub total_count: u64,
    pub truncated: bool,
    pub rows: Vec<TableScript>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TableScriptTextPage {
    pub record_id: i32,
    pub kind: TableScriptKind,
    pub offset: u64,
    pub next_offset: u64,
    pub total_bytes: u64,
    pub truncated: bool,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LuaExecution {
    pub record_id: i32,
    pub kind: TableScriptKind,
    pub output: String,
    pub output_truncated: bool,
    pub runtime_error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LuaConsoleExecution {
    pub runtime_generation: u64,
    pub output: String,
    pub output_truncated: bool,
    pub runtime_error: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeTick {
    pub runtime_generation: u64,
    pub address_generation: u64,
    pub address_refresh_due: bool,
    pub timer_count: u32,
    pub timers_fired: u32,
    pub timer_errors: u32,
    pub timers_deferred: u32,
    pub output: String,
    pub output_truncated: bool,
}

pub struct Engine {
    inner: cxx::UniquePtr<ffi::EngineFacade>,
}

// Engine owns its C++ facade uniquely and the Linux process handle has no UI or
// thread affinity. Moving the whole owner to a worker thread is therefore safe;
// callers never share or access it concurrently.
unsafe impl Send for Engine {}

fn address_page(page: ffi::AddressPage) -> AddressPage {
    AddressPage {
        generation: page.generation,
        start: page.start,
        total_count: page.total_count,
        raw_total_count: page.raw_total_count,
        error_message: page.error_message,
        rows: page
            .rows
            .into_iter()
            .filter_map(|row| {
                Some(AddressRecord {
                    id: row.id,
                    description: row.description,
                    address: row.address,
                    address_expression: row.address_expression,
                    value_type: ScanValueType::from_index(u32::from(row.value_type))?,
                    type_name: row.type_name,
                    value: row.value,
                    error_message: row.error_message,
                    readable: row.readable,
                    active: row.active,
                    freeze_mode: FreezeMode::from_index(u32::from(row.freeze_mode))?,
                    show_as_hex: row.show_as_hex,
                    byte_count: row.byte_count,
                    is_group: row.is_group,
                    collapsed: row.collapsed,
                    has_script: row.has_script,
                    has_auto_assembler: row.has_auto_assembler,
                    has_lua: row.has_lua,
                    indent: row.indent,
                })
            })
            .collect(),
    }
}

impl Engine {
    pub fn new() -> Self {
        Self {
            inner: ffi::create_engine_facade(),
        }
    }

    pub fn version(&self) -> String {
        self.inner.version()
    }

    pub fn list_processes(&self, query: &str, limit: u32) -> Vec<Process> {
        self.inner
            .list_processes(query, limit)
            .into_iter()
            .map(|process| Process {
                pid: process.pid,
                name: process.name,
                path: process.path,
                sandboxed: process.sandboxed,
            })
            .collect()
    }

    pub fn attach(&mut self, pid: i32, display_name: &str) -> Result<Session, AttachError> {
        let result = self.inner.pin_mut().attach(pid, display_name);
        if !result.success {
            return Err(AttachError {
                code: result.error_code,
                message: result.error_message,
            });
        }

        Ok(Session {
            pid: result.pid,
            name: result.name,
            summary: result.summary,
            arch: result.arch,
            endianness: result.endianness,
            wine: result.wine,
            sandboxed: result.sandboxed,
            already_traced: result.already_traced,
            tracer_pid: result.tracer_pid,
            yama_scope: result.yama_scope,
            notes: result.notes,
        })
    }

    pub fn detach(&mut self) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().detach()).map(|_| ())
    }

    pub fn is_attached(&self) -> bool {
        self.inner.is_attached()
    }

    pub fn attached_pid(&self) -> i32 {
        self.inner.attached_pid()
    }

    pub fn start_first_scan(&mut self, request: &ScanRequest) -> Result<(), AttachError> {
        let request = request.to_ffi();
        let result = self.inner.pin_mut().start_first_scan(&request);
        if result.accepted {
            Ok(())
        } else {
            Err(AttachError {
                code: result.error_code,
                message: result.error_message,
            })
        }
    }

    pub fn scan_status(&self) -> ScanStatus {
        let status = self.inner.scan_status();
        ScanStatus {
            started: status.started,
            generation: status.generation,
            running: status.running,
            cancel_requested: status.cancel_requested,
            cancelled: status.cancelled,
            completed: status.completed,
            progress: status.progress,
            result_count: status.result_count,
            write_error: status.write_error,
            result_available: status.result_available,
            undo_available: status.undo_available,
            error_message: status.error_message,
        }
    }

    pub fn start_next_scan(&mut self, request: &ScanRequest) -> Result<(), AttachError> {
        let request = request.to_ffi();
        let result = self.inner.pin_mut().start_next_scan(&request);
        if result.accepted {
            Ok(())
        } else {
            Err(AttachError {
                code: result.error_code,
                message: result.error_message,
            })
        }
    }

    pub fn undo_scan(&mut self) -> Result<ScanAction, AttachError> {
        let result = self.inner.pin_mut().undo_scan();
        if result.accepted {
            Ok(ScanAction {
                generation: result.generation,
                result_count: result.result_count,
                undo_available: result.undo_available,
            })
        } else {
            Err(AttachError {
                code: result.error_code,
                message: result.error_message,
            })
        }
    }

    pub fn scan_rows(&self, generation: u64, start: u64, limit: u32) -> ScanPage {
        let page = self.inner.scan_rows(generation, start, limit);
        ScanPage {
            generation: page.generation,
            start: page.start,
            total_count: page.total_count,
            stale: page.stale,
            error_message: page.error_message,
            rows: page
                .rows
                .into_iter()
                .map(|hit| ScanHit {
                    address: hit.address,
                    value: hit.value,
                })
                .collect(),
        }
    }

    pub fn memory_view(
        &self,
        address: u64,
        byte_count: u32,
        instruction_limit: u32,
    ) -> Result<MemoryView, AddressError> {
        let view = self
            .inner
            .memory_view(address, byte_count, instruction_limit);
        if !view.accepted {
            return Err(AddressError {
                code: view.error_code,
                message: view.error_message,
            });
        }
        Ok(MemoryView {
            address: view.address,
            next_address: view.next_address,
            arch: view.arch,
            region: view.region,
            bytes: view.bytes,
            instructions: view
                .instructions
                .into_iter()
                .map(|row| DisassemblyRow {
                    address: row.address,
                    bytes: row.bytes,
                    mnemonic: row.mnemonic,
                    operands: row.operands,
                    size: row.size,
                    follow_target: row.follow_target,
                })
                .collect(),
        })
    }

    pub fn memory_search(
        &self,
        pattern: &[u8],
        mask: &[u8],
        start: u64,
        backward: bool,
        page_bytes: u32,
    ) -> Result<MemorySearch, AddressError> {
        let result = self
            .inner
            .memory_search(pattern, mask, start, backward, page_bytes);
        if !result.accepted {
            return Err(AddressError {
                code: result.error_code,
                message: result.error_message,
            });
        }
        Ok(MemorySearch {
            found: result.found,
            complete: result.complete,
            address: result.address,
            next_address: result.next_address,
            scanned_bytes: result.scanned_bytes,
        })
    }

    pub fn memory_write(
        &mut self,
        address: u64,
        bytes: &[u8],
        allow_protection_change: bool,
    ) -> Result<MemoryWrite, AddressError> {
        let result = self
            .inner
            .pin_mut()
            .memory_write(address, bytes, allow_protection_change);
        if !result.accepted {
            return Err(AddressError {
                code: result.error_code,
                message: result.error_message,
            });
        }
        Ok(MemoryWrite {
            written: result.written,
            protection_changed: result.protection_changed,
            protection_restored: result.protection_restored,
            warning: result.warning,
        })
    }

    pub fn cancel_scan(&mut self) {
        self.inner.pin_mut().cancel_scan();
    }

    pub fn visible_address_rows(
        &mut self,
        start: u64,
        limit: u32,
        refresh_values: bool,
    ) -> AddressPage {
        let page = self
            .inner
            .pin_mut()
            .visible_address_rows(start, limit, refresh_values);
        address_page(page)
    }

    pub fn add_scan_result(
        &mut self,
        scan_generation: u64,
        scan_index: u64,
        description: &str,
    ) -> Result<i32, AddressError> {
        address_action(self.inner.pin_mut().add_scan_result(
            scan_generation,
            scan_index,
            description,
        ))
    }

    pub fn add_address(
        &mut self,
        address: u64,
        value_type: ScanValueType,
        description: &str,
        byte_count: u32,
        show_as_hex: bool,
    ) -> Result<i32, AddressError> {
        address_action(self.inner.pin_mut().add_address(
            address,
            value_type as u8,
            description,
            byte_count,
            show_as_hex,
        ))
    }

    pub fn set_address_value(&mut self, id: i32, value: &str) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_address_value(id, value)).map(|_| ())
    }

    pub fn set_address_active(&mut self, id: i32, active: bool) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_address_active(id, active)).map(|_| ())
    }

    pub fn set_address_freeze_mode(
        &mut self,
        id: i32,
        mode: FreezeMode,
    ) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_address_freeze_mode(id, mode as u8)).map(|_| ())
    }

    pub fn delete_address(&mut self, id: i32) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().delete_address(id)).map(|_| ())
    }

    pub fn add_address_group(&mut self, description: &str) -> Result<i32, AddressError> {
        address_action(self.inner.pin_mut().add_address_group(description))
    }

    pub fn group_addresses(&mut self, ids: &[i32], description: &str) -> Result<i32, AddressError> {
        address_action(self.inner.pin_mut().group_addresses(ids, description))
    }

    pub fn move_address(&mut self, id: i32, direction: i32) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().move_address(id, direction)).map(|_| ())
    }

    pub fn set_address_collapsed(&mut self, id: i32, collapsed: bool) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_address_collapsed(id, collapsed)).map(|_| ())
    }

    pub fn load_table(&mut self, path: &str) -> Result<TableAction, AddressError> {
        table_action(self.inner.pin_mut().load_table(path))
    }

    pub fn load_protected_table(
        &mut self,
        path: &str,
        password: &str,
    ) -> Result<TableAction, AddressError> {
        table_action(self.inner.pin_mut().load_protected_table(path, password))
    }

    pub fn save_table(&self, path: &str, json: bool) -> Result<TableAction, AddressError> {
        table_action(self.inner.save_table(path, json))
    }

    pub fn table_compatibility_issues(
        &self,
        json_destination: bool,
    ) -> Vec<TableCompatibilityIssue> {
        self.inner
            .table_compatibility_issues(json_destination)
            .into_iter()
            .map(table_compatibility_issue)
            .collect()
    }

    pub fn table_scripts(&self, start: u64, limit: u32) -> TableScriptPage {
        let page = self.inner.table_scripts(start, limit);
        TableScriptPage {
            start: page.start,
            next_start: page.next_start,
            total_count: page.total_count,
            truncated: page.truncated,
            rows: page
                .rows
                .into_iter()
                .map(|row| TableScript {
                    record_id: row.record_id,
                    kind: TableScriptKind::from_bridge(row.kind),
                    description: row.description,
                    byte_count: row.byte_count,
                })
                .collect(),
        }
    }

    pub fn table_script_text(
        &self,
        record_id: i32,
        kind: TableScriptKind,
        offset: u64,
        limit: u32,
    ) -> Result<TableScriptTextPage, AddressError> {
        let page = self
            .inner
            .table_script_text(record_id, kind.bridge_value(), offset, limit);
        if page.accepted {
            Ok(TableScriptTextPage {
                record_id: page.record_id,
                kind: TableScriptKind::from_bridge(page.kind),
                offset: page.offset,
                next_offset: page.next_offset,
                total_bytes: page.total_bytes,
                truncated: page.truncated,
                text: page.text,
            })
        } else {
            Err(AddressError {
                code: page.error_code,
                message: page.error_message,
            })
        }
    }

    pub fn set_table_scripts_trusted(&mut self, trusted: bool) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_table_scripts_trusted(trusted)).map(|_| ())
    }

    pub fn table_scripts_trusted(&self) -> bool {
        self.inner.table_scripts_trusted()
    }

    pub fn set_table_lua_trusted(&mut self, trusted: bool) -> Result<(), AddressError> {
        address_action(self.inner.pin_mut().set_table_lua_trusted(trusted)).map(|_| ())
    }

    pub fn table_lua_trusted(&self) -> bool {
        self.inner.table_lua_trusted()
    }

    pub fn execute_table_lua(
        &mut self,
        record_id: i32,
        kind: TableScriptKind,
    ) -> Result<LuaExecution, AddressError> {
        let result = self
            .inner
            .pin_mut()
            .execute_table_lua(record_id, kind.bridge_value());
        if result.accepted {
            Ok(LuaExecution {
                record_id: result.record_id,
                kind: TableScriptKind::from_bridge(result.kind),
                output: result.output,
                output_truncated: result.output_truncated,
                runtime_error: result.runtime_error,
            })
        } else {
            Err(AddressError {
                code: result.error_code,
                message: result.error_message,
            })
        }
    }

    pub fn execute_lua_console(
        &mut self,
        source: &str,
    ) -> Result<LuaConsoleExecution, AddressError> {
        let result = self.inner.pin_mut().execute_lua_console(source);
        if result.accepted {
            Ok(LuaConsoleExecution {
                runtime_generation: result.runtime_generation,
                output: result.output,
                output_truncated: result.output_truncated,
                runtime_error: result.runtime_error,
            })
        } else {
            Err(AddressError {
                code: result.error_code,
                message: result.error_message,
            })
        }
    }

    pub fn lua_runtime_generation(&self) -> u64 {
        self.inner.lua_runtime_generation()
    }

    pub fn periodic_tick(&mut self) -> RuntimeTick {
        let result = self.inner.pin_mut().periodic_tick();
        RuntimeTick {
            runtime_generation: result.runtime_generation,
            address_generation: result.address_generation,
            address_refresh_due: result.address_refresh_due,
            timer_count: result.timer_count,
            timers_fired: result.timers_fired,
            timer_errors: result.timer_errors,
            timers_deferred: result.timers_deferred,
            output: result.output,
            output_truncated: result.output_truncated,
        }
    }
}

fn address_action(result: ffi::AddressActionResult) -> Result<i32, AddressError> {
    if result.accepted {
        Ok(result.id)
    } else {
        Err(AddressError {
            code: result.error_code,
            message: result.error_message,
        })
    }
}

fn table_action(result: ffi::TableActionResult) -> Result<TableAction, AddressError> {
    if result.accepted {
        Ok(TableAction {
            record_count: result.record_count,
            contains_scripts: result.contains_scripts,
            contains_auto_assembler: result.contains_auto_assembler,
            contains_lua: result.contains_lua,
            compatibility_issues: result
                .compatibility_issues
                .into_iter()
                .map(table_compatibility_issue)
                .collect(),
        })
    } else {
        Err(AddressError {
            code: result.error_code,
            message: result.error_message,
        })
    }
}

fn table_compatibility_issue(issue: ffi::TableCompatibilityIssueRow) -> TableCompatibilityIssue {
    TableCompatibilityIssue {
        code: issue.code,
        title: issue.title,
        detail: issue.detail,
        count: issue.count,
        preserved: issue.preserved,
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::UnsafeCell;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use super::{
        Engine, FreezeMode, ScanComparison, ScanRequest, ScanStatus, ScanValueType, TableScriptKind,
    };

    fn temporary_table_path(extension: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        std::env::temp_dir().join(format!("ce-gtk-{}-{nonce}.{extension}", std::process::id()))
    }

    fn write_protected_table(path: &PathBuf, password: &str, json: &str) {
        fn fnv1a(text: &str) -> u64 {
            text.bytes().fold(1_469_598_103_934_665_603, |hash, byte| {
                (hash ^ u64::from(byte)).wrapping_mul(1_099_511_628_211)
            })
        }

        fn xorshift64(state: &mut u64) -> u64 {
            *state ^= *state << 13;
            *state ^= *state >> 7;
            *state ^= *state << 17;
            *state
        }

        let verifier = fnv1a(password);
        let mut state = fnv1a(if password.is_empty() {
            "cecore"
        } else {
            password
        });
        let encrypted = json
            .bytes()
            .map(|byte| byte ^ (xorshift64(&mut state) & 0xff) as u8)
            .collect::<Vec<_>>();
        let mut payload = format!("CETRAINER1\n{verifier}\n").into_bytes();
        payload.extend(encrypted);
        std::fs::write(path, payload).expect("write protected table fixture");
    }

    fn wait_for_scan(engine: &Engine) -> ScanStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = engine.scan_status();
            if !status.running {
                return status;
            }
            assert!(Instant::now() < deadline, "scan timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn attached_engine() -> Engine {
        let mut engine = Engine::new();
        engine
            .attach(std::process::id() as i32, "scan fixture")
            .expect("attach to self");
        engine
    }

    #[test]
    fn reads_version_from_libcecore() {
        assert!(!Engine::new().version().is_empty());
    }

    #[test]
    fn process_listing_is_bounded() {
        assert!(Engine::new().list_processes("", 3).len() <= 3);
        assert!(Engine::new().list_processes("", 10_000).len() <= 512);
    }

    #[test]
    fn process_listing_filters_unknown_names() {
        let query = "ce-gtk-process-name-that-cannot-reasonably-exist-7f93d4";
        assert!(Engine::new().list_processes(query, 32).is_empty());
    }

    #[test]
    fn attaches_to_self_and_detaches() {
        let mut engine = Engine::new();
        let pid = std::process::id() as i32;

        let session = engine.attach(pid, "bridge test").expect("attach to self");
        assert_eq!(session.pid, pid);
        assert!(engine.is_attached());
        assert_eq!(engine.attached_pid(), pid);

        engine.detach().expect("detach from self");
        assert!(!engine.is_attached());
        assert_eq!(engine.attached_pid(), 0);
    }

    #[test]
    fn memory_view_reads_and_disassembles_a_bounded_page() {
        let code = Box::new([
            0xE8_u8, 0x05, 0x00, 0x00, 0x00, // call address + 10
            0x90, 0xC3, 0xCC, 0x90, 0x90, 0xC3,
        ]);
        let address = code.as_ptr() as u64;
        let mut engine = Engine::new();
        engine
            .attach(std::process::id() as i32, "memory-view fixture")
            .expect("attach to self");

        let view = engine
            .memory_view(address, code.len() as u32, 16)
            .expect("read memory-view page");
        assert_eq!(view.address, address);
        assert_eq!(view.bytes, code.as_slice());
        assert_eq!(view.next_address, address + code.len() as u64);
        assert!(view.arch == "x86-64" || view.arch == "x86-32");
        assert!(!view.region.is_empty());
        assert_eq!(view.instructions[0].address, address);
        assert_eq!(view.instructions[0].mnemonic, "call");
        assert_eq!(view.instructions[0].follow_target, address + 10);
        assert_eq!(view.instructions[1].mnemonic, "nop");

        let bounded = engine
            .memory_view(address, u32::MAX, u32::MAX)
            .expect("bounded memory-view page");
        assert!(bounded.bytes.len() <= 4096);
        assert!(bounded.instructions.len() <= 256);
    }

    #[test]
    fn memory_view_requires_an_attached_process() {
        let error = Engine::new()
            .memory_view(0x1000, 256, 64)
            .expect_err("memory view without a process must fail");
        assert_eq!(error.code, "no_session");
    }

    #[test]
    fn memory_search_pages_forward_backward_and_supports_wildcards() {
        let marker = [0xD3_u8, 0x71, 0xA9, 0x4C, 0xE2, 0x86, 0x5B, 0xF0];
        let mut fixture = vec![0x11_u8; 320].into_boxed_slice();
        fixture[173..181].copy_from_slice(&marker);
        let base = fixture.as_ptr() as u64;
        let expected = base + 173;
        let mut engine = attached_engine();

        let mut cursor = base;
        let mut found = None;
        for _ in 0..8 {
            let page = engine
                .memory_search(&marker, &[], cursor, false, 64)
                .expect("search memory page");
            assert!(page.scanned_bytes <= 64);
            if page.found {
                found = Some(page.address);
                break;
            }
            assert!(
                !page.complete,
                "fixture should remain inside the search range"
            );
            assert!(page.next_address > cursor);
            cursor = page.next_address;
        }
        assert_eq!(found, Some(expected));

        let wildcard_mask = [1_u8, 1, 0, 1, 1, 1, 1, 1];
        let mut wildcard = marker;
        wildcard[2] = 0;
        let hit = engine
            .memory_search(&wildcard, &wildcard_mask, base, false, 512)
            .expect("wildcard memory search");
        assert!(hit.found);
        assert_eq!(hit.address, expected);

        let hit = engine
            .memory_search(&marker, &[], expected + marker.len() as u64, true, 512)
            .expect("backward memory search");
        assert!(hit.found);
        assert_eq!(hit.address, expected);
        assert_eq!(
            engine
                .memory_search(&marker, &[1], base, false, 64)
                .expect_err("mismatched wildcard masks must fail")
                .code,
            "invalid_mask"
        );
        std::hint::black_box(&fixture);
    }

    #[test]
    fn memory_write_is_bounded_and_verified() {
        let mut fixture = Box::new([0x11_u8, 0x22, 0x33, 0x44]);
        let address = fixture.as_mut_ptr() as u64;
        let mut engine = attached_engine();

        let write = engine
            .memory_write(address + 1, &[0xAA, 0xBB], false)
            .expect("write self memory");
        assert_eq!(write.written, 2);
        assert!(!write.protection_changed);
        assert!(write.protection_restored);
        assert!(write.warning.is_empty());
        assert_eq!(*fixture, [0x11, 0xAA, 0xBB, 0x44]);

        let error = engine
            .memory_write(address, &[], false)
            .expect_err("empty writes must fail");
        assert_eq!(error.code, "empty_write");
        let oversized = vec![0x90; 4097];
        assert_eq!(
            engine
                .memory_write(address, &oversized, false)
                .expect_err("oversized writes must fail")
                .code,
            "write_too_large"
        );
        std::hint::black_box(&fixture);
    }

    #[test]
    fn memory_search_and_write_require_an_attached_process() {
        let mut engine = Engine::new();
        assert_eq!(
            engine
                .memory_search(&[0x90], &[], 0x1000, false, 4096)
                .expect_err("search without a process must fail")
                .code,
            "no_session"
        );
        assert_eq!(
            engine
                .memory_write(0x1000, &[0x90], false)
                .expect_err("write without a process must fail")
                .code,
            "no_session"
        );
    }

    #[test]
    fn failed_attach_preserves_current_session() {
        let mut engine = Engine::new();
        let pid = std::process::id() as i32;
        engine.attach(pid, "bridge test").expect("attach to self");

        let error = engine
            .attach(-1, "invalid")
            .expect_err("invalid PID must fail");
        assert_eq!(error.code, "process_not_found");
        assert_eq!(engine.attached_pid(), pid);
    }

    #[test]
    fn attaches_to_child_process() {
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start child process");
        let mut engine = Engine::new();

        let result = engine.attach(child.id() as i32, "sleep child");
        let _ = child.kill();
        let _ = child.wait();

        let session = result.expect("parent should be allowed to read child memory");
        assert_eq!(session.name, "sleep child");
    }

    #[test]
    fn first_scan_pages_known_values_and_rejects_stale_generation() {
        let sentinel = 0x0123_4567_i32;
        let mut values = vec![sentinel; 300].into_boxed_slice();
        let address = values.as_ptr() as u64;
        let byte_len = std::mem::size_of_val(&*values) as u64;
        let mut engine = Engine::new();
        engine
            .attach(std::process::id() as i32, "scan fixture")
            .expect("attach to self");

        let request = ScanRequest {
            value: sentinel.to_string(),
            start_address: address,
            stop_address: address + byte_len,
            alignment: 4,
            ..ScanRequest::default()
        };
        engine
            .start_first_scan(&request)
            .expect("start bounded first scan");

        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 300);

        let first_page = engine.scan_rows(status.generation, 0, 10_000);
        assert!(!first_page.stale);
        assert_eq!(first_page.rows.len(), 256, "facade page cap");
        assert_eq!(first_page.rows[0].address, address);
        assert_eq!(first_page.rows[0].value, sentinel.to_string());

        let second_page = engine.scan_rows(status.generation, 256, 256);
        assert_eq!(second_page.rows.len(), 44);
        assert_eq!(second_page.total_count, 300);

        for value in values.iter_mut().take(100) {
            *value = -1;
        }
        let first_generation = status.generation;
        engine
            .start_next_scan(&request)
            .expect("start exact next scan");
        let next_status = wait_for_scan(&engine);
        assert!(next_status.completed);
        assert_eq!(next_status.result_count, 200);
        assert!(next_status.undo_available);
        assert_ne!(next_status.generation, first_generation);
        assert!(engine.scan_rows(first_generation, 0, 1).stale);

        let action = engine.undo_scan().expect("undo next scan");
        assert_eq!(action.result_count, 300);
        assert!(action.undo_available);
        assert!(engine.scan_rows(next_status.generation, 0, 1).stale);
        let restored = engine.scan_rows(action.generation, 0, 256);
        assert_eq!(restored.total_count, 300);
        assert_eq!(restored.rows.len(), 256);

        engine.detach().expect("detach after scan");
        assert!(engine.scan_rows(action.generation, 0, 1).stale);
    }

    #[test]
    fn scans_float_ranges_through_generic_request() {
        let values = vec![2.0_f32, 2.5, 3.0, 3.5, 4.0].into_boxed_slice();
        let address = values.as_ptr() as u64;
        let mut engine = attached_engine();
        let request = ScanRequest {
            value_type: ScanValueType::Float,
            comparison: ScanComparison::Between,
            value: "2.5".to_owned(),
            value2: "3.5".to_owned(),
            start_address: address,
            stop_address: address + std::mem::size_of_val(&*values) as u64,
            alignment: 4,
            ..ScanRequest::default()
        };

        engine.start_first_scan(&request).expect("start float scan");
        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 3);
        let page = engine.scan_rows(status.generation, 0, 10);
        assert_eq!(
            page.rows
                .iter()
                .map(|row| row.value.as_str())
                .collect::<Vec<_>>(),
            ["2.5", "3", "3.5"]
        );
        std::hint::black_box(&values);
    }

    #[test]
    fn scans_case_insensitive_text_and_narrows_exact_matches() {
        let mut bytes = b"RustBridge--RUSTBRIDGE".to_vec().into_boxed_slice();
        let address = bytes.as_ptr() as u64;
        let mut engine = attached_engine();
        let request = ScanRequest {
            value_type: ScanValueType::String,
            value: "rustbridge".to_owned(),
            case_sensitive: false,
            start_address: address,
            stop_address: address + bytes.len() as u64,
            alignment: 1,
            ..ScanRequest::default()
        };

        engine.start_first_scan(&request).expect("start text scan");
        let first = wait_for_scan(&engine);
        assert!(first.completed, "scan failed: {}", first.error_message);
        assert_eq!(first.result_count, 2);

        bytes[0] = b'X';
        engine
            .start_next_scan(&request)
            .expect("start text next scan");
        let next = wait_for_scan(&engine);
        assert!(next.completed, "scan failed: {}", next.error_message);
        assert_eq!(next.result_count, 1);
        let page = engine.scan_rows(next.generation, 0, 10);
        assert_eq!(page.rows[0].address, address + 12);
        assert_eq!(page.rows[0].value, "RUSTBRIDGE");
        std::hint::black_box(&bytes);
    }

    #[test]
    fn scans_aob_wildcards_and_unknown_width_changes() {
        let pattern_bytes = [0x7f_u8, 0x45, 0x91, 0x46, 0, 0x7f, 0x45, 0xa2, 0x46];
        let address = pattern_bytes.as_ptr() as u64;
        let mut engine = attached_engine();
        let request = ScanRequest {
            value_type: ScanValueType::ByteArray,
            value: "7F 45 ?? 46".to_owned(),
            start_address: address,
            stop_address: address + pattern_bytes.len() as u64,
            alignment: 1,
            ..ScanRequest::default()
        };

        engine.start_first_scan(&request).expect("start AOB scan");
        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 2);
        let page = engine.scan_rows(status.generation, 0, 10);
        assert_eq!(page.rows[0].value, "7F 45 91 46");
        assert_eq!(page.rows[1].value, "7F 45 A2 46");

        let mut unknown_bytes = vec![0x11_u8; 12].into_boxed_slice();
        let unknown_address = unknown_bytes.as_ptr() as u64;
        let unknown = ScanRequest {
            value_type: ScanValueType::ByteArray,
            comparison: ScanComparison::Unknown,
            value_size: 4,
            start_address: unknown_address,
            stop_address: unknown_address + unknown_bytes.len() as u64,
            alignment: 1,
            ..ScanRequest::default()
        };
        engine
            .start_first_scan(&unknown)
            .expect("start unknown AOB scan");
        let first = wait_for_scan(&engine);
        assert_eq!(first.result_count, 9);

        unknown_bytes[5] = 0x22;
        let changed = ScanRequest {
            comparison: ScanComparison::Changed,
            ..unknown
        };
        engine
            .start_next_scan(&changed)
            .expect("start changed AOB scan");
        let next = wait_for_scan(&engine);
        assert!(next.completed, "scan failed: {}", next.error_message);
        assert_eq!(next.result_count, 4);
        std::hint::black_box((&pattern_bytes, &unknown_bytes));
    }

    #[test]
    fn all_type_between_uses_both_bounds_and_unknown_is_one_snapshot_per_address() {
        let values = [10_i64, 20_i64];
        let address = values.as_ptr() as u64;
        let mut engine = attached_engine();
        let between = ScanRequest {
            value_type: ScanValueType::All,
            comparison: ScanComparison::Between,
            value: "09".to_owned(),
            value2: "0B".to_owned(),
            hexadecimal: true,
            start_address: address,
            stop_address: address + std::mem::size_of_val(&values) as u64,
            alignment: 8,
            ..ScanRequest::default()
        };

        engine.start_first_scan(&between).expect("start All scan");
        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 4);
        assert!(
            engine
                .scan_rows(status.generation, 0, 10)
                .rows
                .iter()
                .all(|row| row.address == address)
        );

        let snapshots = ScanRequest {
            comparison: ScanComparison::Unknown,
            value: String::new(),
            value2: String::new(),
            ..between
        };
        engine
            .start_first_scan(&snapshots)
            .expect("start unknown All scan");
        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 2);
        std::hint::black_box(&values);
    }

    #[test]
    fn rejects_non_finite_float_requests() {
        let mut engine = attached_engine();
        let value = 1.0_f32;
        let address = (&value as *const f32) as u64;
        let error = engine
            .start_first_scan(&ScanRequest {
                value_type: ScanValueType::Float,
                value: "NaN".to_owned(),
                start_address: address,
                stop_address: address + 4,
                ..ScanRequest::default()
            })
            .expect_err("non-finite values must be rejected");
        assert_eq!(error.code, "invalid_float");
        std::hint::black_box(value);
    }

    #[test]
    fn unknown_text_rows_replace_invalid_utf8() {
        let bytes = [0xff_u8, 0xfe];
        let address = bytes.as_ptr() as u64;
        let mut engine = attached_engine();
        engine
            .start_first_scan(&ScanRequest {
                value_type: ScanValueType::String,
                comparison: ScanComparison::Unknown,
                value_size: 2,
                start_address: address,
                stop_address: address + bytes.len() as u64,
                alignment: 1,
                ..ScanRequest::default()
            })
            .expect("start unknown text scan");
        let status = wait_for_scan(&engine);
        assert!(status.completed, "scan failed: {}", status.error_message);
        assert_eq!(status.result_count, 1);
        assert_eq!(
            engine.scan_rows(status.generation, 0, 1).rows[0].value,
            "\u{fffd}\u{fffd}"
        );
        std::hint::black_box(&bytes);
    }

    #[test]
    fn address_records_read_write_freeze_and_survive_detach_safely() {
        let value = Box::new(UnsafeCell::new(41_i32));
        let address = value.get() as u64;
        let mut engine = attached_engine();
        let id = engine
            .add_address(address, ScanValueType::Int32, "Score", 0, false)
            .expect("add a manual address");

        let page = engine.visible_address_rows(0, 10_000, true);
        assert_eq!(page.total_count, 1);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].id, id);
        assert_eq!(page.rows[0].description, "Score");
        assert_eq!(page.rows[0].value, "41");
        assert!(page.rows[0].readable);

        engine
            .set_address_value(id, "77")
            .expect("write the address-list value");
        // SAFETY: UnsafeCell is the synchronization boundary for the external
        // process-memory write performed by the engine in this single thread.
        assert_eq!(unsafe { *value.get() }, 77);

        engine
            .set_address_active(id, true)
            .expect("freeze the address-list value");
        unsafe { *value.get() = 5 };
        engine.periodic_tick();
        assert_eq!(unsafe { *value.get() }, 77);

        engine
            .set_address_freeze_mode(id, FreezeMode::IncreaseOnly)
            .expect("change the freeze mode");
        unsafe { *value.get() = 100 };
        std::thread::sleep(Duration::from_millis(105));
        engine.periodic_tick();
        assert_eq!(unsafe { *value.get() }, 100, "allowed increase must remain");
        unsafe { *value.get() = 1 };
        std::thread::sleep(Duration::from_millis(105));
        engine.periodic_tick();
        assert_eq!(
            unsafe { *value.get() },
            77,
            "decrease below the floor is restored"
        );

        engine.detach().expect("detach address-list target");
        let detached = engine.visible_address_rows(0, 10, false);
        assert_eq!(detached.total_count, 1);
        assert!(!detached.rows[0].active);
        assert!(!detached.rows[0].readable);
        assert_eq!(detached.rows[0].value, "??");

        engine.delete_address(id).expect("remove the record");
        assert_eq!(engine.visible_address_rows(0, 10, false).total_count, 0);
        std::hint::black_box(value);
    }

    #[test]
    fn scan_results_add_by_generation_and_reject_stale_rows() {
        let values = [111_i32, 222_i32];
        let address = values.as_ptr() as u64;
        let mut engine = attached_engine();
        let first_request = ScanRequest {
            value: "222".to_owned(),
            start_address: address,
            stop_address: address + std::mem::size_of_val(&values) as u64,
            alignment: 4,
            ..ScanRequest::default()
        };
        engine
            .start_first_scan(&first_request)
            .expect("start the source scan");
        let first = wait_for_scan(&engine);
        assert!(first.completed, "scan failed: {}", first.error_message);
        assert_eq!(first.result_count, 1);

        let id = engine
            .add_scan_result(first.generation, 0, "Scanned value")
            .expect("add the scan result");
        let records = engine.visible_address_rows(0, 10, true);
        assert_eq!(records.rows[0].id, id);
        assert_eq!(records.rows[0].address, address + 4);
        assert_eq!(records.rows[0].value, "222");
        assert_eq!(records.rows[0].value_type, ScanValueType::Int32);

        let second_request = ScanRequest {
            value: "111".to_owned(),
            ..first_request
        };
        engine
            .start_first_scan(&second_request)
            .expect("replace the result set");
        let second = wait_for_scan(&engine);
        assert!(second.completed);
        let error = engine
            .add_scan_result(first.generation, 0, "Stale")
            .expect_err("stale result generation must be rejected");
        assert_eq!(error.code, "stale_scan_result");
        std::hint::black_box(values);
    }

    #[test]
    fn address_records_encode_float_text_unicode_and_bytes() {
        let float_value = Box::new(UnsafeCell::new(1.5_f32));
        let text_value = Box::new(UnsafeCell::new(*b"abcdefgh"));
        let unicode_value = Box::new(UnsafeCell::new([0_u8; 8]));
        let bytes_value = Box::new(UnsafeCell::new([0_u8; 4]));
        let mut engine = attached_engine();

        let float_id = engine
            .add_address(
                float_value.get() as u64,
                ScanValueType::Float,
                "Float",
                0,
                false,
            )
            .expect("add float");
        let text_id = engine
            .add_address(
                text_value.get() as u64,
                ScanValueType::String,
                "Text",
                8,
                false,
            )
            .expect("add text");
        let unicode_id = engine
            .add_address(
                unicode_value.get() as u64,
                ScanValueType::UnicodeString,
                "Unicode",
                8,
                false,
            )
            .expect("add unicode");
        let bytes_id = engine
            .add_address(
                bytes_value.get() as u64,
                ScanValueType::ByteArray,
                "Bytes",
                4,
                false,
            )
            .expect("add bytes");

        engine
            .set_address_value(float_id, "2,5")
            .expect("write comma-decimal float");
        engine
            .set_address_value(text_id, "Rust")
            .expect("write padded UTF-8 text");
        engine
            .set_address_value(unicode_id, "Ж")
            .expect("write padded UTF-16 text");
        engine
            .set_address_value(bytes_id, "90 90 48 8B")
            .expect("write byte array");

        assert_eq!(unsafe { *float_value.get() }, 2.5);
        assert_eq!(unsafe { *text_value.get() }, *b"Rust\0\0\0\0");
        assert_eq!(
            unsafe { *unicode_value.get() },
            [0x16, 0x04, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(unsafe { *bytes_value.get() }, [0x90, 0x90, 0x48, 0x8b]);

        let page = engine.visible_address_rows(0, 10, true);
        assert_eq!(page.rows[0].value, "2.5");
        assert_eq!(page.rows[1].value, "Rust");
        assert_eq!(page.rows[2].value, "Ж");
        assert_eq!(page.rows[3].value, "90 90 48 8B");
        std::hint::black_box((float_value, text_value, unicode_value, bytes_value));
    }

    #[test]
    fn first_scan_requires_attached_session() {
        let mut engine = Engine::new();
        let request = ScanRequest {
            value: "42".to_owned(),
            start_address: 0,
            stop_address: 4,
            alignment: 1,
            ..ScanRequest::default()
        };
        let error = engine
            .start_first_scan(&request)
            .expect_err("scan without session must fail");
        assert_eq!(error.code, "no_session");
    }

    #[test]
    fn next_scan_requires_previous_result() {
        let mut engine = Engine::new();
        engine
            .attach(std::process::id() as i32, "scan fixture")
            .expect("attach to self");
        let error = engine
            .start_next_scan(&ScanRequest {
                value: "42".to_owned(),
                ..ScanRequest::default()
            })
            .expect_err("next scan without first result must fail");
        assert_eq!(error.code, "no_scan_result");
    }

    #[test]
    fn address_groups_move_as_subtrees_and_round_trip_through_ct() {
        let mut engine = Engine::new();
        let health = engine
            .add_address(0x1000, ScanValueType::Int32, "Health", 0, false)
            .expect("add health");
        let armor = engine
            .add_address(0x2000, ScanValueType::Int32, "Armor", 0, false)
            .expect("add armor");
        let score = engine
            .add_address(0x3000, ScanValueType::Int64, "Score", 0, true)
            .expect("add score");
        let group = engine
            .group_addresses(&[health, armor], "Player")
            .expect("group records");

        let grouped = engine.visible_address_rows(0, 20, false);
        assert_eq!(
            grouped.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            [group, health, armor, score]
        );
        assert_eq!(
            grouped
                .rows
                .iter()
                .map(|row| row.indent)
                .collect::<Vec<_>>(),
            [0, 1, 1, 0]
        );

        engine
            .move_address(group, 1)
            .expect("move complete group subtree down");
        engine
            .set_address_collapsed(group, true)
            .expect("collapse group");
        let moved = engine.visible_address_rows(0, 20, false);
        assert_eq!(moved.total_count, 2);
        assert_eq!(moved.raw_total_count, 4);
        assert_eq!(
            moved.rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            [score, group]
        );
        let second_visible = engine.visible_address_rows(1, 1, false);
        assert_eq!(second_visible.total_count, 2);
        assert_eq!(second_visible.rows[0].id, group);

        let path = temporary_table_path("CT");
        let action = engine
            .save_table(path.to_str().expect("UTF-8 temp path"), false)
            .expect("save CT");
        assert_eq!(action.record_count, 4);
        assert!(!action.contains_scripts);

        let mut loaded = Engine::new();
        let action = loaded
            .load_table(path.to_str().expect("UTF-8 temp path"))
            .expect("load CT");
        assert_eq!(action.record_count, 4);
        let collapsed_rows = loaded.visible_address_rows(0, 20, false).rows;
        assert_eq!(
            collapsed_rows
                .iter()
                .map(|row| row.description.as_str())
                .collect::<Vec<_>>(),
            ["Score", "Player"]
        );
        assert!(collapsed_rows[1].is_group);
        assert!(collapsed_rows[1].collapsed);
        let loaded_group = collapsed_rows[1].id;
        loaded
            .set_address_collapsed(loaded_group, false)
            .expect("expand the reloaded group");
        let rows = loaded.visible_address_rows(0, 20, false).rows;
        assert_eq!(
            rows.iter()
                .map(|row| row.description.as_str())
                .collect::<Vec<_>>(),
            ["Score", "Player", "Health", "Armor"]
        );
        assert_eq!(rows[2].indent, 1);
        assert_eq!(rows[3].indent, 1);

        loaded
            .delete_address(loaded_group)
            .expect("delete group subtree");
        assert_eq!(loaded.visible_address_rows(0, 20, false).total_count, 1);
        std::fs::remove_file(path).expect("remove temporary CT");
    }

    #[test]
    fn visible_address_pages_are_bounded_and_cover_large_tables() {
        let mut engine = Engine::new();
        for index in 0..600_u64 {
            engine
                .add_address(
                    0x1000 + index * 4,
                    ScanValueType::Int32,
                    &format!("Record {index}"),
                    0,
                    false,
                )
                .expect("add large-table fixture record");
        }

        let first = engine.visible_address_rows(0, 10_000, false);
        let second = engine.visible_address_rows(256, 10_000, false);
        let third = engine.visible_address_rows(512, 10_000, false);
        assert_eq!(first.total_count, 600);
        assert_eq!(first.raw_total_count, 600);
        assert_eq!(first.rows.len(), 256);
        assert_eq!(second.rows.len(), 256);
        assert_eq!(third.rows.len(), 88);
        assert_eq!(first.rows[0].description, "Record 0");
        assert_eq!(second.rows[0].description, "Record 256");
        assert_eq!(third.rows[87].description, "Record 599");
    }

    #[test]
    fn protected_tables_require_the_password_and_load_transactionally() {
        let path = temporary_table_path("CETRAINER");
        write_protected_table(
            &path,
            "correct horse",
            r#"{
  "game":"Protected fixture",
  "version":"1",
  "author":"test",
  "comment":"",
  "luaScript":"print('protected')",
  "structures":[],
  "disassemblerComments":[],
  "entries":[{"id":77,"desc":"Secret Gold","addr":"0x1234","type":2,"value":"42"}]
}"#,
        );

        let mut engine = Engine::new();
        engine
            .add_address(0x2222, ScanValueType::Int32, "Existing record", 0, false)
            .expect("add existing record");
        engine
            .set_table_lua_trusted(true)
            .expect("set existing trust state");

        let password_required = engine
            .load_table(path.to_str().expect("UTF-8 temp path"))
            .expect_err("generic load must request a password");
        assert_eq!(password_required.code, "protected_table");
        assert!(engine.table_lua_trusted());
        assert_eq!(
            engine.visible_address_rows(0, 10, false).rows[0].description,
            "Existing record"
        );

        let wrong_password = engine
            .load_protected_table(path.to_str().expect("UTF-8 temp path"), "wrong")
            .expect_err("wrong password must fail");
        assert_eq!(wrong_password.code, "protected_table_decrypt_failed");
        assert!(engine.table_lua_trusted());
        assert_eq!(
            engine.visible_address_rows(0, 10, false).rows[0].description,
            "Existing record"
        );

        let loaded = engine
            .load_protected_table(path.to_str().expect("UTF-8 temp path"), "correct horse")
            .expect("correct password loads protected table");
        assert_eq!(loaded.record_count, 1);
        assert!(loaded.contains_scripts);
        assert!(loaded.contains_lua);
        assert!(!loaded.contains_auto_assembler);
        assert!(!engine.table_lua_trusted());
        let rows = engine.visible_address_rows(0, 10, false).rows;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 77);
        assert_eq!(rows[0].description, "Secret Gold");

        std::fs::remove_file(path).expect("remove protected table fixture");
    }

    #[test]
    fn table_compatibility_report_distinguishes_preserved_and_lossy_data() {
        let source = temporary_table_path("compatibility.CT");
        let saved_ct = temporary_table_path("compatibility-roundtrip.CT");
        let saved_json = temporary_table_path("compatibility.json");
        std::fs::write(
            &source,
            r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>1</ID><Description>"Advanced group"</Description><GroupHeader>1</GroupHeader>
      <Options moActivateChildrenAsWell="1" moDeactivateChildrenAsWell="1" moRecursiveSetValue="1"/>
    </CheatEntry>
    <CheatEntry>
      <ID>2</ID><Description>"Styled value"</Description><VariableType>4 Bytes</VariableType>
      <Address>1234</Address><Color>FF00FF</Color><DropDownList>0:Off
1:On</DropDownList><Hotkeys>Ctrl+H</Hotkeys>
    </CheatEntry>
  </CheatEntries>
  <Forms><Form><Name>TrainerForm</Name><Data>AABBCC</Data></Form></Forms>
</CheatTable>"#,
        )
        .expect("write compatibility fixture");

        let mut engine = Engine::new();
        let loaded = engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("load compatibility fixture");
        let issue = |code: &str| {
            loaded
                .compatibility_issues
                .iter()
                .find(|issue| issue.code == code)
                .unwrap_or_else(|| panic!("missing compatibility issue {code}"))
        };
        assert!(issue("embedded_forms").preserved);
        assert!(issue("advanced_group_options").preserved);
        assert!(issue("record_colors").preserved);
        assert!(issue("dropdown_lists").preserved);
        assert_eq!(issue("hotkeys").count, 1);
        assert!(
            loaded
                .compatibility_issues
                .iter()
                .all(|issue| issue.preserved)
        );

        let ct_preflight = engine.table_compatibility_issues(false);
        assert!(
            ct_preflight
                .iter()
                .find(|issue| issue.code == "embedded_forms")
                .expect("CT forms report")
                .preserved
        );
        let json_preflight = engine.table_compatibility_issues(true);
        let json_loss = json_preflight
            .iter()
            .find(|issue| issue.code == "embedded_forms_json_loss")
            .expect("JSON forms loss report");
        assert!(!json_loss.preserved);
        assert_eq!(json_loss.count, 1);

        let ct_action = engine
            .save_table(saved_ct.to_str().expect("UTF-8 temp path"), false)
            .expect("save lossless CT");
        assert!(
            ct_action
                .compatibility_issues
                .iter()
                .all(|issue| issue.preserved)
        );
        assert!(
            std::fs::read_to_string(&saved_ct)
                .expect("read saved CT")
                .contains("<Forms><Form><Name>TrainerForm</Name>")
        );

        let json_action = engine
            .save_table(saved_json.to_str().expect("UTF-8 temp path"), true)
            .expect("save JSON with acknowledged loss");
        assert!(
            json_action
                .compatibility_issues
                .iter()
                .any(|issue| issue.code == "embedded_forms_json_loss" && !issue.preserved)
        );
        assert!(
            !std::fs::read_to_string(&saved_json)
                .expect("read saved JSON")
                .contains("TrainerForm")
        );

        std::fs::remove_file(source).expect("remove compatibility fixture");
        std::fs::remove_file(saved_ct).expect("remove CT round trip");
        std::fs::remove_file(saved_json).expect("remove JSON round trip");
    }

    #[test]
    fn table_scripts_are_preserved_and_require_explicit_trust() {
        let source = temporary_table_path("CT");
        let saved = temporary_table_path("roundtrip.CT");
        std::fs::write(
            &source,
            r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>7</ID>
      <Description>"Untrusted script"</Description>
      <Activated>1</Activated>
      <VariableType>Auto Assembler Script</VariableType>
      <AssemblerScript>[ENABLE]
alloc(newmem,64)
[DISABLE]
dealloc(newmem)</AssemblerScript>
    </CheatEntry>
    <CheatEntry>
      <ID>8</ID>
      <Description>"Record Lua"</Description>
      <VariableType>4 Bytes</VariableType>
      <Address>0</Address>
      <LuaScript>error('record lua must remain blocked')</LuaScript>
    </CheatEntry>
  </CheatEntries>
  <LuaScript>error('must not execute')</LuaScript>
</CheatTable>
"#,
        )
        .expect("write script table fixture");

        let mut engine = Engine::new();
        let action = engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("load script table without execution");
        assert!(action.contains_scripts);
        assert!(action.contains_auto_assembler);
        assert!(action.contains_lua);
        assert!(!engine.table_scripts_trusted());
        assert!(!engine.table_lua_trusted());
        assert_eq!(
            engine
                .execute_table_lua(0, TableScriptKind::TableLua)
                .expect_err("Lua execution must remain default-deny")
                .code,
            "table_lua_not_trusted"
        );
        let first_scripts = engine.table_scripts(0, 2);
        assert_eq!(first_scripts.start, 0);
        assert_eq!(first_scripts.next_start, 2);
        assert_eq!(first_scripts.total_count, 3);
        assert!(first_scripts.truncated);
        assert_eq!(first_scripts.rows[0].record_id, 0);
        assert_eq!(first_scripts.rows[0].kind, TableScriptKind::TableLua);
        assert_eq!(first_scripts.rows[1].record_id, 7);
        assert_eq!(first_scripts.rows[1].kind, TableScriptKind::AutoAssembler);
        let last_scripts = engine.table_scripts(first_scripts.next_start, 2);
        assert_eq!(last_scripts.start, 2);
        assert_eq!(last_scripts.next_start, 3);
        assert!(!last_scripts.truncated);
        assert_eq!(last_scripts.rows.len(), 1);
        assert_eq!(last_scripts.rows[0].record_id, 8);
        assert_eq!(last_scripts.rows[0].kind, TableScriptKind::RecordLua);
        assert_eq!(
            engine
                .table_script_text(0, TableScriptKind::TableLua, 0, 1024)
                .expect("read table Lua review")
                .text,
            "error('must not execute')"
        );
        assert_eq!(
            engine
                .table_script_text(8, TableScriptKind::RecordLua, 0, 1024)
                .expect("read record Lua review")
                .text,
            "error('record lua must remain blocked')"
        );

        let mut reviewed_aa = String::new();
        let mut review_offset = 0;
        loop {
            let page = engine
                .table_script_text(7, TableScriptKind::AutoAssembler, review_offset, 7)
                .expect("read bounded AA review page");
            assert_eq!(page.record_id, 7);
            assert_eq!(page.kind, TableScriptKind::AutoAssembler);
            assert_eq!(page.offset, review_offset);
            reviewed_aa.push_str(&page.text);
            if !page.truncated {
                assert_eq!(page.next_offset, page.total_bytes);
                break;
            }
            assert!(page.next_offset > review_offset);
            review_offset = page.next_offset;
        }
        assert_eq!(
            reviewed_aa,
            "[ENABLE]\nalloc(newmem,64)\n[DISABLE]\ndealloc(newmem)"
        );
        assert!(
            !engine.table_scripts_trusted(),
            "review must never grant trust"
        );
        assert!(!engine.table_lua_trusted(), "review must never trust Lua");
        assert_eq!(
            engine
                .table_script_text(7, TableScriptKind::Unknown(255), 0, 16)
                .expect_err("unknown script kind must be rejected")
                .code,
            "invalid_script_kind"
        );
        let rows = engine.visible_address_rows(0, 10, false).rows;
        let row = rows.iter().find(|row| row.id == 7).expect("AA row");
        let lua_row = rows.iter().find(|row| row.id == 8).expect("Lua row");
        assert!(row.has_script && row.has_auto_assembler && !row.has_lua);
        assert!(lua_row.has_script && !lua_row.has_auto_assembler && lua_row.has_lua);
        assert!(
            !row.active && !lua_row.active,
            "loaded scripts must remain inactive"
        );
        assert_eq!(
            engine
                .set_address_active(row.id, true)
                .expect_err("untrusted script activation must remain blocked")
                .code,
            "table_not_trusted"
        );
        engine
            .set_table_scripts_trusted(true)
            .expect("trust is an explicit, non-executing state change");
        assert!(engine.table_scripts_trusted());
        assert_eq!(
            engine
                .set_address_active(lua_row.id, true)
                .expect_err("record toggles must never execute Lua")
                .code,
            "lua_requires_explicit_run"
        );
        assert_eq!(
            engine
                .set_address_active(row.id, true)
                .expect_err("activation still needs a process")
                .code,
            "no_session"
        );
        engine
            .set_table_lua_trusted(true)
            .expect("Lua trust is a separate explicit state change");
        assert!(engine.table_lua_trusted());
        let table_lua = engine
            .execute_table_lua(0, TableScriptKind::TableLua)
            .expect("trusted table Lua is attempted explicitly");
        assert!(table_lua.runtime_error.contains("must not execute"));
        let record_lua = engine
            .execute_table_lua(8, TableScriptKind::RecordLua)
            .expect("trusted record Lua is attempted explicitly");
        assert!(
            record_lua
                .runtime_error
                .contains("record lua must remain blocked")
        );
        engine
            .set_table_lua_trusted(false)
            .expect("Lua trust revocation resets its runtime");
        assert!(!engine.table_lua_trusted());

        engine
            .save_table(saved.to_str().expect("UTF-8 temp path"), false)
            .expect("save script table");
        let xml = std::fs::read_to_string(&saved).expect("read saved script table");
        assert!(xml.contains("error('must not execute')"));
        assert!(xml.contains("alloc(newmem,64)"));
        assert!(xml.contains("record lua must remain blocked"));

        std::fs::remove_file(source).expect("remove script table fixture");
        std::fs::remove_file(saved).expect("remove script table round trip");
    }

    #[test]
    fn table_script_review_enforces_bridge_text_limit() {
        let source = temporary_table_path("large-script.CT");
        let payload = "A".repeat((64 << 10) + 4096);
        std::fs::write(
            &source,
            format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable><CheatEntries><CheatEntry>
<ID>41</ID><Description>Large review</Description>
<VariableType>Auto Assembler Script</VariableType>
<AssemblerScript>{payload}</AssemblerScript>
</CheatEntry></CheatEntries></CheatTable>"#
            ),
        )
        .expect("write large script table fixture");

        let mut engine = Engine::new();
        engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("load large script table");
        let scripts = engine.table_scripts(0, u32::MAX);
        assert_eq!(scripts.total_count, 1);
        assert_eq!(scripts.rows[0].byte_count, payload.len() as u64);
        let page = engine
            .table_script_text(41, TableScriptKind::AutoAssembler, 0, u32::MAX)
            .expect("review capped payload page");
        assert_eq!(page.text.len(), 64 << 10);
        assert_eq!(page.next_offset, (64 << 10) as u64);
        assert_eq!(page.total_bytes, payload.len() as u64);
        assert!(page.truncated);
        assert!(!engine.table_scripts_trusted());

        std::fs::remove_file(source).expect("remove large script table fixture");
    }

    #[test]
    fn lua_execution_is_explicit_bounded_and_reset_on_revoke() {
        let source = temporary_table_path("lua-runtime.CT");
        std::fs::write(
            &source,
            r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>55</ID><Description>Read state</Description>
      <VariableType>4 Bytes</VariableType><Address>0</Address>
      <LuaScript>print('marker=' .. tostring(TABLE_MARK))</LuaScript>
    </CheatEntry>
    <CheatEntry>
      <ID>56</ID><Description>Bounded output and loop</Description>
      <VariableType>4 Bytes</VariableType><Address>0</Address>
      <LuaScript>print(string.rep('x', 70000)); while true do end</LuaScript>
    </CheatEntry>
  </CheatEntries>
  <LuaScript>TABLE_MARK = 73; print('table-ready'); table_timer=createTimer(1); timer_onTimer(table_timer, function() print('table-timer'); object_destroy(table_timer) end)</LuaScript>
</CheatTable>
"#,
        )
        .expect("write Lua runtime table fixture");

        let mut engine = Engine::new();
        engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("load Lua runtime table");
        assert_eq!(
            engine
                .execute_table_lua(55, TableScriptKind::RecordLua)
                .expect_err("untrusted record Lua must be blocked")
                .code,
            "table_lua_not_trusted"
        );
        engine
            .set_table_lua_trusted(true)
            .expect("trust reviewed Lua payloads");
        let before_table = engine
            .execute_table_lua(55, TableScriptKind::RecordLua)
            .expect("run record Lua before table initializer");
        assert_eq!(before_table.output, "marker=nil");
        assert!(before_table.runtime_error.is_empty());
        let table = engine
            .execute_table_lua(0, TableScriptKind::TableLua)
            .expect("run table Lua explicitly");
        assert_eq!(table.output, "table-ready");
        std::thread::sleep(Duration::from_millis(5));
        let table_timer = engine.periodic_tick();
        assert_eq!(table_timer.timers_fired, 1);
        assert_eq!(table_timer.timer_count, 0);
        assert_eq!(table_timer.output, "table-timer");
        let after_table = engine
            .execute_table_lua(55, TableScriptKind::RecordLua)
            .expect("run record Lua after table initializer");
        assert_eq!(after_table.output, "marker=73");

        let bounded = engine
            .execute_table_lua(56, TableScriptKind::RecordLua)
            .expect("bounded Lua run returns its runtime outcome");
        assert_eq!(bounded.output.len(), 64 << 10);
        assert!(bounded.output_truncated);
        assert!(bounded.runtime_error.contains("instruction limit"));

        engine
            .set_table_lua_trusted(false)
            .expect("revoke Lua trust");
        assert!(!engine.table_lua_trusted());
        engine
            .set_table_lua_trusted(true)
            .expect("re-trust starts with a clean Lua state");
        let after_reset = engine
            .execute_table_lua(55, TableScriptKind::RecordLua)
            .expect("run record Lua after state reset");
        assert_eq!(after_reset.output, "marker=nil");

        engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("reloading a table resets Lua trust");
        assert!(!engine.table_lua_trusted());
        std::fs::remove_file(source).expect("remove Lua runtime table fixture");

        let oversized_source = temporary_table_path("oversized-lua.CT");
        let oversized_payload = format!("--{}", "x".repeat((1 << 20) + 1));
        std::fs::write(
            &oversized_source,
            format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable><CheatEntries><CheatEntry>
<ID>57</ID><Description>Oversized Lua</Description>
<VariableType>4 Bytes</VariableType><Address>0</Address>
<LuaScript>{oversized_payload}</LuaScript>
</CheatEntry></CheatEntries></CheatTable>"#
            ),
        )
        .expect("write oversized Lua fixture");
        engine
            .load_table(oversized_source.to_str().expect("UTF-8 temp path"))
            .expect("load oversized Lua table without execution");
        engine
            .set_table_lua_trusted(true)
            .expect("trust does not itself execute oversized Lua");
        assert_eq!(
            engine
                .execute_table_lua(57, TableScriptKind::RecordLua)
                .expect_err("oversized Lua must be rejected")
                .code,
            "lua_script_too_large"
        );
        std::fs::remove_file(oversized_source).expect("remove oversized Lua fixture");
    }

    #[test]
    fn lua_console_is_explicit_bounded_and_does_not_grant_table_trust() {
        let mut engine = Engine::new();
        let generation = engine.lua_runtime_generation();
        assert!(generation > 0);
        assert!(!engine.table_lua_trusted());

        let first = engine
            .execute_lua_console("CONSOLE_MARK = 91; print('console-ready')")
            .expect("run explicit console input");
        assert_eq!(first.runtime_generation, generation);
        assert_eq!(first.output, "console-ready");
        assert!(first.runtime_error.is_empty());
        assert!(
            !engine.table_lua_trusted(),
            "console use must not trust a table"
        );

        let persisted = engine
            .execute_lua_console("print('marker=' .. tostring(CONSOLE_MARK))")
            .expect("console shares its live Lua state");
        assert_eq!(persisted.output, "marker=91");

        let bounded = engine
            .execute_lua_console("while true do end")
            .expect("runtime errors are returned as console results");
        assert!(bounded.runtime_error.contains("instruction limit"));

        let oversized = "x".repeat((1 << 20) + 1);
        assert_eq!(
            engine
                .execute_lua_console(&oversized)
                .expect_err("oversized console input must be rejected")
                .code,
            "lua_console_source_too_large"
        );
        assert_eq!(
            engine
                .execute_lua_console("print('before')\0print('after')")
                .expect_err("NUL-bearing console input must be rejected")
                .code,
            "lua_console_source_contains_nul"
        );
    }

    #[test]
    fn periodic_tick_pumps_bounded_timers_and_runtime_reset_cancels_them() {
        let mut engine = Engine::new();
        let generation = engine.lua_runtime_generation();
        engine
            .execute_lua_console(
                "ticks=0; t=createTimer(1); timer_onTimer(t, function() ticks=ticks+1; print('tick=' .. ticks) end)",
            )
            .expect("create a console timer");
        std::thread::sleep(Duration::from_millis(5));
        let tick = engine.periodic_tick();
        assert_eq!(tick.runtime_generation, generation);
        assert_eq!(tick.timer_count, 1);
        assert_eq!(tick.timers_fired, 1);
        assert_eq!(tick.timer_errors, 0);
        assert_eq!(tick.output, "tick=1");

        engine
            .execute_lua_console(
                "bad=createTimer(1); timer_onTimer(bad, function() while true do end end)",
            )
            .expect("create a runaway timer without running it synchronously");
        std::thread::sleep(Duration::from_millis(5));
        let failed = engine.periodic_tick();
        assert_eq!(failed.timers_fired, 1);
        assert_eq!(failed.timer_errors, 1);
        assert!(failed.output.contains("instruction limit"));
        assert!(failed.output.contains("timer disabled"));
        let after_failure = engine.periodic_tick();
        assert_eq!(after_failure.timer_errors, 0, "failed timer stays disabled");

        engine
            .set_table_lua_trusted(false)
            .expect("runtime reset is allowed even without table trust");
        assert!(engine.lua_runtime_generation() > generation);
        let reset = engine.periodic_tick();
        assert_eq!(reset.timer_count, 0);
        let clean = engine
            .execute_lua_console("print(tostring(ticks))")
            .expect("console remains usable after reset");
        assert_eq!(clean.output, "nil");
    }

    #[test]
    fn periodic_tick_caps_due_timer_callbacks_without_starvation() {
        let mut engine = Engine::new();
        engine
            .execute_lua_console(
                r#"
                timer_total = 0
                for index = 1, 40 do
                    local timer
                    timer = createTimer(1)
                    timer_onTimer(timer, function()
                        timer_total = timer_total + 1
                        object_destroy(timer)
                    end)
                end
            "#,
            )
            .expect("create many one-shot timers");
        std::thread::sleep(Duration::from_millis(5));
        let first = engine.periodic_tick();
        assert_eq!(first.timers_fired, 32);
        assert_eq!(first.timers_deferred, 8);
        assert_eq!(first.timer_count, 8);
        let second = engine.periodic_tick();
        assert_eq!(second.timers_fired, 8);
        assert_eq!(second.timers_deferred, 0);
        assert_eq!(second.timer_count, 0);
        let total = engine
            .execute_lua_console("print(timer_total)")
            .expect("all deferred timers eventually run");
        assert_eq!(total.output, "40");
    }

    #[test]
    fn trusted_auto_assembler_activation_disables_and_cleans_up() {
        let value = Box::new(UnsafeCell::new(41_i32));
        let address = value.get() as usize;
        let source = temporary_table_path("CT");
        std::fs::write(
            &source,
            format!(
                r#"<?xml version="1.0" encoding="utf-8"?>
<CheatTable>
  <CheatEntries>
    <CheatEntry>
      <ID>8</ID>
      <Description>"Trusted scripts"</Description>
      <GroupHeader>1</GroupHeader>
      <CheatEntries>
        <CheatEntry>
          <ID>9</ID>
          <Description>"Trusted patch"</Description>
          <VariableType>Auto Assembler Script</VariableType>
          <AssemblerScript>[ENABLE]
{address:X}:
dd #99
[DISABLE]</AssemblerScript>
        </CheatEntry>
      </CheatEntries>
    </CheatEntry>
  </CheatEntries>
</CheatTable>
"#
            ),
        )
        .expect("write executable table fixture");

        let mut engine = attached_engine();
        let action = engine
            .load_table(source.to_str().expect("UTF-8 temp path"))
            .expect("load script without executing it");
        assert!(action.contains_auto_assembler);
        let rows = engine.visible_address_rows(0, 10, false).rows;
        let group_id = rows
            .iter()
            .find(|row| row.is_group)
            .expect("script group")
            .id;
        let id = rows
            .iter()
            .find(|row| row.has_auto_assembler)
            .expect("Auto Assembler row")
            .id;
        assert_eq!(unsafe { *value.get() }, 41);
        assert_eq!(
            engine
                .set_address_active(id, true)
                .expect_err("untrusted table must not patch memory")
                .code,
            "table_not_trusted"
        );
        assert_eq!(unsafe { *value.get() }, 41);

        engine
            .set_table_scripts_trusted(true)
            .expect("explicitly trust this table");
        engine
            .set_address_active(id, true)
            .expect("enable trusted Auto Assembler record");
        assert_eq!(unsafe { *value.get() }, 99);
        assert!(
            engine
                .visible_address_rows(0, 10, false)
                .rows
                .iter()
                .find(|row| row.id == id)
                .expect("AA row after activation")
                .active
        );

        engine
            .set_table_scripts_trusted(false)
            .expect("revoking trust disables active scripts first");
        assert_eq!(unsafe { *value.get() }, 41);
        assert!(
            !engine
                .visible_address_rows(0, 10, false)
                .rows
                .iter()
                .find(|row| row.id == id)
                .expect("AA row after trust revocation")
                .active
        );
        assert!(!engine.table_scripts_trusted());

        engine
            .set_table_scripts_trusted(true)
            .expect("trust the same loaded table again");
        engine
            .set_address_active(id, true)
            .expect("re-enable trusted record");
        assert_eq!(unsafe { *value.get() }, 99);
        engine
            .attach(std::process::id() as i32, "reattach cleanup")
            .expect("changing sessions disables the old target script first");
        assert_eq!(unsafe { *value.get() }, 41);
        assert!(
            !engine
                .visible_address_rows(0, 10, false)
                .rows
                .iter()
                .find(|row| row.id == id)
                .expect("AA row after reattach")
                .active
        );

        engine
            .set_address_active(id, true)
            .expect("trust remains scoped to the loaded table after reattach");
        assert_eq!(unsafe { *value.get() }, 99);
        engine
            .detach()
            .expect("detaching disables the active script first");
        assert_eq!(unsafe { *value.get() }, 41);
        assert!(
            !engine
                .visible_address_rows(0, 10, false)
                .rows
                .iter()
                .find(|row| row.id == id)
                .expect("AA row after detach")
                .active
        );

        engine
            .attach(std::process::id() as i32, "delete cleanup")
            .expect("reattach after cleanup");
        engine
            .set_address_active(id, true)
            .expect("enable before deletion cleanup");
        assert_eq!(unsafe { *value.get() }, 99);
        engine
            .delete_address(group_id)
            .expect("deleting an active script subtree disables it first");
        assert_eq!(unsafe { *value.get() }, 41);
        assert_eq!(engine.visible_address_rows(0, 10, false).total_count, 0);

        std::fs::remove_file(source).expect("remove executable table fixture");
        std::hint::black_box(value);
    }

    #[test]
    fn failed_or_protected_table_load_keeps_the_current_records() {
        let invalid = temporary_table_path("CT");
        let protected = temporary_table_path("CETRAINER");
        std::fs::write(&invalid, "this is not a cheat table").expect("write invalid table");
        std::fs::write(&protected, "CETRAINER1\nopaque payload").expect("write protected table");

        let mut engine = Engine::new();
        let id = engine
            .add_address(0x1234, ScanValueType::Int32, "Keep me", 0, false)
            .expect("add existing record");
        let invalid_error = engine
            .load_table(invalid.to_str().expect("UTF-8 temp path"))
            .expect_err("invalid table must be rejected");
        assert_eq!(invalid_error.code, "invalid_table");
        let protected_error = engine
            .load_table(protected.to_str().expect("UTF-8 temp path"))
            .expect_err("protected table needs an explicit password workflow");
        assert_eq!(protected_error.code, "protected_table");

        let rows = engine.visible_address_rows(0, 10, false).rows;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, id);
        assert_eq!(rows[0].description, "Keep me");

        std::fs::remove_file(invalid).expect("remove invalid table fixture");
        std::fs::remove_file(protected).expect("remove protected table fixture");
    }
}
