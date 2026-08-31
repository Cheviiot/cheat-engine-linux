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
        fn start_first_scan_i32(
            self: Pin<&mut EngineFacade>,
            value: i32,
            start_address: u64,
            stop_address: u64,
            alignment: u32,
        ) -> ScanStartResult;
        fn start_next_scan_i32(self: Pin<&mut EngineFacade>, value: i32) -> ScanStartResult;
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

    pub fn start_first_scan_i32(
        &mut self,
        value: i32,
        start_address: u64,
        stop_address: u64,
        alignment: u32,
    ) -> Result<(), AttachError> {
        let result = self.inner.pin_mut().start_first_scan_i32(
            value,
            start_address,
            stop_address,
            alignment,
        );
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

    pub fn start_next_scan_i32(&mut self, value: i32) -> Result<(), AttachError> {
        let result = self.inner.pin_mut().start_next_scan_i32(value);
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

    use super::Engine;

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

        engine
            .start_first_scan_i32(sentinel, address, address + byte_len, 4)
            .expect("start bounded first scan");

        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            let status = engine.scan_status();
            if !status.running {
                break status;
            }
            assert!(Instant::now() < deadline, "scan timed out");
            std::thread::sleep(Duration::from_millis(10));
        };
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
            .start_next_scan_i32(sentinel)
            .expect("start exact next scan");
        let deadline = Instant::now() + Duration::from_secs(10);
        let next_status = loop {
            let status = engine.scan_status();
            if !status.running {
                break status;
            }
            assert!(Instant::now() < deadline, "next scan timed out");
            std::thread::sleep(Duration::from_millis(10));
        };
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
    fn first_scan_requires_attached_session() {
        let mut engine = Engine::new();
        let error = engine
            .start_first_scan_i32(42, 0, 4, 1)
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
            .start_next_scan_i32(42)
            .expect_err("next scan without first result must fail");
        assert_eq!(error.code, "no_scan_result");
    }
}
