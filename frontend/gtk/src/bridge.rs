#[cxx::bridge(namespace = "ce::bridge")]
mod ffi {
    struct ProcessRow {
        pid: i32,
        name: String,
        path: String,
        sandboxed: bool,
    }

    unsafe extern "C++" {
        include!("bridge/engine_facade.hpp");

        type EngineFacade;

        fn create_engine_facade() -> UniquePtr<EngineFacade>;
        fn version(self: &EngineFacade) -> String;
        fn list_processes(self: &EngineFacade, query: &str, limit: u32) -> Vec<ProcessRow>;
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Process {
    pub pid: i32,
    pub name: String,
    pub path: String,
    pub sandboxed: bool,
}

pub struct Engine {
    inner: cxx::UniquePtr<ffi::EngineFacade>,
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
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
}
