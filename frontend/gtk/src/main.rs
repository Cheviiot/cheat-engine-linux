mod application;
mod bridge;
mod process_dialog;

use adw::prelude::*;
use std::time::Duration;

fn main() -> adw::glib::ExitCode {
    let arguments: Vec<String> = std::env::args().collect();

    if arguments
        .iter()
        .any(|argument| argument == "--core-version")
    {
        println!("{}", bridge::Engine::new().version());
        return adw::glib::ExitCode::SUCCESS;
    }

    let application = application::build_application();
    let startup_smoke = arguments.iter().any(|argument| argument == "--smoke-test");
    let lua_console_smoke = arguments
        .iter()
        .any(|argument| argument == "--lua-console-smoke");
    if startup_smoke || lua_console_smoke {
        application.connect_activate(move |application| {
            if startup_smoke && let Some(window) = application.active_window() {
                process_dialog::present(&window, |_| {});
            }
            let application = application.clone();
            adw::glib::timeout_add_local_once(Duration::from_millis(350), move || {
                application.quit();
            });
        });
    }

    // Custom diagnostic flags are handled above and must not reach GApplication's
    // own option parser, which correctly rejects unknown command-line options.
    application.run_with_args(&["ce-gtk"])
}
