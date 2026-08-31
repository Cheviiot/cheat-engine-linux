mod address_list_model;
mod application;
mod bridge;
mod process_dialog;
mod scan_result_model;

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
    let address_list_smoke = arguments
        .iter()
        .any(|argument| argument == "--address-list-smoke");
    let main_layout_smoke = arguments
        .iter()
        .any(|argument| argument == "--main-layout-smoke");
    if startup_smoke || lua_console_smoke || address_list_smoke || main_layout_smoke {
        application.connect_activate(move |application| {
            if startup_smoke && let Some(window) = application.active_window() {
                process_dialog::present(&window, |_| {});
            }
            let application = application.clone();
            let timeout = if address_list_smoke { 1800 } else { 350 };
            adw::glib::timeout_add_local_once(Duration::from_millis(timeout), move || {
                application.quit();
            });
        });
    }

    // Custom diagnostic flags are handled above and must not reach GApplication's
    // own option parser, which correctly rejects unknown command-line options.
    let exit_code = application.run_with_args(&["ce-gtk"]);
    if address_list_smoke && !application::address_list_smoke_ok() {
        eprintln!("virtual address-list smoke did not load the second page");
        adw::glib::ExitCode::FAILURE
    } else if main_layout_smoke && !application::main_layout_smoke_ok() {
        eprintln!("main window does not preserve the process/results/controls/address-list layout");
        adw::glib::ExitCode::FAILURE
    } else {
        exit_code
    }
}
