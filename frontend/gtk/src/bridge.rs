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

    unsafe extern "C++" {
        include!("bridge/engine_facade.hpp");

        type EngineFacade;

        fn create_engine_facade() -> UniquePtr<EngineFacade>;
        fn version(self: &EngineFacade) -> String;
        fn list_processes(self: &EngineFacade, query: &str, limit: u32) -> Vec<ProcessRow>;
        fn attach(self: Pin<&mut EngineFacade>, pid: i32, display_name: &str) -> AttachResult;
        fn detach(self: Pin<&mut EngineFacade>);
        fn is_attached(self: &EngineFacade) -> bool;
        fn attached_pid(self: &EngineFacade) -> i32;
        fn start_first_scan(self: Pin<&mut EngineFacade>, request: &ScanRequest)
        -> ScanStartResult;
        fn start_next_scan(self: Pin<&mut EngineFacade>, request: &ScanRequest) -> ScanStartResult;
        fn undo_scan(self: Pin<&mut EngineFacade>) -> ScanActionResult;
        fn scan_status(self: &EngineFacade) -> ScanStatus;
        fn scan_rows(self: &EngineFacade, generation: u64, start: u64, limit: u32) -> ScanPage;
        fn cancel_scan(self: Pin<&mut EngineFacade>);
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

pub struct Engine {
    inner: cxx::UniquePtr<ffi::EngineFacade>,
}

// Engine owns its C++ facade uniquely and the Linux process handle has no UI or
// thread affinity. Moving the whole owner to a worker thread is therefore safe;
// callers never share or access it concurrently.
unsafe impl Send for Engine {}

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

    pub fn detach(&mut self) {
        self.inner.pin_mut().detach();
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

    pub fn cancel_scan(&mut self) {
        self.inner.pin_mut().cancel_scan();
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::{Engine, ScanComparison, ScanRequest, ScanStatus, ScanValueType};

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

        engine.detach();
        assert!(!engine.is_attached());
        assert_eq!(engine.attached_pid(), 0);
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

        engine.detach();
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
}
