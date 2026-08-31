use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use adw::prelude::*;
use gtk::{Align, Orientation};

use crate::bridge::{AttachError, Engine, Process, Session};
use crate::process_dialog;

pub const DEVELOPMENT_APP_ID: &str = "io.github.cheviiot.CeGtk.Devel";
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Clone)]
struct SessionState {
    engine: Rc<RefCell<Option<Engine>>>,
    selected: Rc<RefCell<Option<Process>>>,
    attached: Rc<Cell<bool>>,
    scanning: Rc<Cell<bool>>,
}

#[derive(Clone)]
struct SessionWidgets {
    selected_process: gtk::Label,
    session_details: gtk::Label,
    process_button: gtk::Button,
    session_button: gtk::Button,
    scan_value: gtk::Entry,
    first_scan_button: gtk::Button,
    cancel_scan_button: gtk::Button,
    scan_progress: gtk::ProgressBar,
    scan_summary: gtk::Label,
    scan_results: gtk::ListBox,
}

pub fn build_application() -> adw::Application {
    let application = adw::Application::builder()
        .application_id(DEVELOPMENT_APP_ID)
        .build();

    application.connect_activate(build_window);
    application
}

fn build_window(application: &adw::Application) {
    let engine = Engine::new();
    let core_version = engine.version();
    let state = SessionState {
        engine: Rc::new(RefCell::new(Some(engine))),
        selected: Rc::new(RefCell::new(None)),
        attached: Rc::new(Cell::new(false)),
        scanning: Rc::new(Cell::new(false)),
    };

    let header = adw::HeaderBar::builder().show_title(false).build();

    let title = gtk::Label::builder()
        .label("Rust/GTK frontend foundation")
        .css_classes(["title-1"])
        .halign(Align::Start)
        .build();

    let description = gtk::Label::builder()
        .label("The first migration slice is connected to the existing C++ engine.")
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();

    let version = gtk::Label::builder()
        .label(format!("libcecore {core_version}"))
        .selectable(true)
        .xalign(0.0)
        .build();

    let selected_process = gtk::Label::builder()
        .label("No process selected")
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();

    let session_details = gtk::Label::builder()
        .label("Choose a running process to begin.")
        .wrap(true)
        .xalign(0.0)
        .selectable(true)
        .css_classes(["dim-label"])
        .build();

    let process_button = gtk::Button::builder()
        .label("Choose process")
        .css_classes(["pill"])
        .halign(Align::Start)
        .build();

    let session_button = gtk::Button::builder()
        .label("Attach")
        .css_classes(["suggested-action", "pill"])
        .sensitive(false)
        .halign(Align::Start)
        .build();

    let session_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    session_actions.append(&process_button);
    session_actions.append(&session_button);

    let scan_title = gtk::Label::builder()
        .label("First scan")
        .css_classes(["title-3"])
        .halign(Align::Start)
        .build();

    let scan_value = gtk::Entry::builder()
        .placeholder_text("32-bit integer value")
        .hexpand(true)
        .build();
    let first_scan_button = gtk::Button::builder()
        .label("First Scan")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();
    let cancel_scan_button = gtk::Button::builder()
        .label("Cancel")
        .sensitive(false)
        .build();

    let scan_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    scan_actions.append(&scan_value);
    scan_actions.append(&first_scan_button);
    scan_actions.append(&cancel_scan_button);

    let scan_progress = gtk::ProgressBar::builder().show_text(true).build();
    scan_progress.set_fraction(0.0);
    scan_progress.set_text(Some("Ready"));

    let scan_summary = gtk::Label::builder()
        .label("Attach to a process to enable exact 4-byte scans.")
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();

    let scan_results = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let scan_results_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(160)
        .vexpand(true)
        .child(&scan_results)
        .build();

    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(18)
        .margin_top(36)
        .margin_bottom(36)
        .margin_start(36)
        .margin_end(36)
        .build();
    content.append(&title);
    content.append(&description);
    content.append(&version);
    content.append(&selected_process);
    content.append(&session_details);
    content.append(&session_actions);
    content.append(&gtk::Separator::new(Orientation::Horizontal));
    content.append(&scan_title);
    content.append(&scan_actions);
    content.append(&scan_progress);
    content.append(&scan_summary);
    content.append(&scan_results_scrolled);

    let clamp = adw::Clamp::builder()
        .maximum_size(720)
        .tightening_threshold(520)
        .child(&content)
        .build();

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.set_content(Some(&clamp));

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("Engine UI — development preview")
        .default_width(900)
        .default_height(760)
        .content(&toolbar_view)
        .build();

    let widgets = SessionWidgets {
        selected_process,
        session_details,
        process_button,
        session_button,
        scan_value,
        first_scan_button,
        cancel_scan_button,
        scan_progress,
        scan_summary,
        scan_results,
    };

    widgets.process_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| {
            process_dialog::present(&window, {
                let state = state.clone();
                let widgets = widgets.clone();
                move |process| {
                    widgets
                        .selected_process
                        .set_label(&format!("Selected {} (PID {})", process.name, process.pid));
                    widgets
                        .session_details
                        .set_label("Ready to open a memory session.");
                    widgets.session_button.set_sensitive(true);
                    *state.selected.borrow_mut() = Some(process);
                }
            });
        }
    });

    widgets.session_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| {
            if state.attached.get() {
                detach(&state, &widgets);
            } else {
                start_attach(&window, &state, &widgets);
            }
        }
    });

    widgets.first_scan_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| start_first_scan(&window, &state, &widgets)
    });

    widgets.cancel_scan_button.connect_clicked({
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| {
            if !state.scanning.get() {
                return;
            }
            if let Some(engine) = state.engine.borrow_mut().as_mut() {
                engine.cancel_scan();
            }
            widgets.cancel_scan_button.set_sensitive(false);
            widgets.scan_progress.set_text(Some("Cancelling…"));
        }
    });

    window.present();
}

fn start_attach(window: &adw::ApplicationWindow, state: &SessionState, widgets: &SessionWidgets) {
    let Some(process) = state.selected.borrow().clone() else {
        return;
    };
    let Some(mut engine) = state.engine.borrow_mut().take() else {
        return;
    };

    widgets.process_button.set_sensitive(false);
    widgets.session_button.set_sensitive(false);
    widgets.session_button.set_label("Attaching…");
    widgets.first_scan_button.set_sensitive(false);
    widgets
        .session_details
        .set_label("Checking target architecture and memory access…");

    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = engine.attach(process.pid, &process.name);
        let _ = sender.send((engine, result));
    });

    let window = window.clone();
    let state = state.clone();
    let widgets = widgets.clone();
    adw::glib::timeout_add_local(WORKER_POLL_INTERVAL, move || match receiver.try_recv() {
        Ok((engine, result)) => {
            let engine_attached = engine.is_attached();
            let engine_pid = engine.attached_pid();
            *state.engine.borrow_mut() = Some(engine);
            match result {
                Ok(session) if engine_attached && engine_pid == session.pid => {
                    show_attached(&state, &widgets, &session);
                }
                Ok(_) => {
                    let error = AttachError {
                        code: "session_state_mismatch".to_owned(),
                        message: "The engine returned an inconsistent session state.".to_owned(),
                    };
                    show_attach_error(&window, &state, &widgets, &error);
                }
                Err(error) => show_attach_error(&window, &state, &widgets, &error),
            }
            adw::glib::ControlFlow::Break
        }
        Err(TryRecvError::Empty) => adw::glib::ControlFlow::Continue,
        Err(TryRecvError::Disconnected) => {
            // Keep the UI recoverable if the worker exits before returning its
            // uniquely-owned engine facade.
            *state.engine.borrow_mut() = Some(Engine::new());
            let error = AttachError {
                code: "worker_failed".to_owned(),
                message: "The attach worker stopped unexpectedly.".to_owned(),
            };
            show_attach_error(&window, &state, &widgets, &error);
            adw::glib::ControlFlow::Break
        }
    });
}

fn show_attached(state: &SessionState, widgets: &SessionWidgets, session: &Session) {
    state.attached.set(true);
    widgets.selected_process.set_label(&format!(
        "Attached to {} (PID {})",
        session.name, session.pid
    ));
    widgets
        .session_details
        .set_label(&session_description(session));
    widgets.process_button.set_sensitive(false);
    widgets.session_button.set_label("Detach");
    widgets.session_button.set_sensitive(true);
    widgets.first_scan_button.set_sensitive(true);
    widgets
        .scan_summary
        .set_label("Enter a signed 32-bit value for an exact scan.");
}

fn show_attach_error(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    error: &AttachError,
) {
    state.attached.set(false);
    widgets.session_details.set_label(&error.message);
    widgets.process_button.set_sensitive(true);
    widgets.session_button.set_label("Attach");
    widgets
        .session_button
        .set_sensitive(state.selected.borrow().is_some());
    widgets.first_scan_button.set_sensitive(false);

    let dialog = adw::AlertDialog::builder()
        .heading("Could not attach to process")
        .body(format!("{}\n\nDiagnostic: {}", error.message, error.code))
        .build();
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}

fn detach(state: &SessionState, widgets: &SessionWidgets) {
    if let Some(engine) = state.engine.borrow_mut().as_mut() {
        engine.detach();
    }
    state.attached.set(false);
    widgets.selected_process.set_label("No process attached");
    widgets
        .session_details
        .set_label("The previous memory session has been closed.");
    widgets.process_button.set_sensitive(true);
    widgets.session_button.set_label("Attach");
    widgets
        .session_button
        .set_sensitive(state.selected.borrow().is_some());
    reset_scan_ui(state, widgets);
}

fn session_description(session: &Session) -> String {
    let mut lines = vec![format!(
        "{} · {}-endian · Yama ptrace_scope={}",
        session.summary, session.endianness, session.yama_scope
    )];
    lines.extend(session.notes.iter().map(|note| format!("• {note}")));
    lines.join("\n")
}

fn start_first_scan(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
) {
    let value_text = widgets.scan_value.text();
    let Some(value) = parse_i32(&value_text) else {
        show_message(
            window,
            "Invalid scan value",
            "Enter a signed 32-bit integer, for example 100 or 0x64.",
        );
        return;
    };

    let start_result = state
        .engine
        .borrow_mut()
        .as_mut()
        .expect("engine is present outside attach worker")
        .start_first_scan_i32(value, 0, 0x0000_7fff_ffff_ffff, 4);
    if let Err(error) = start_result {
        show_message(window, "Could not start scan", &error.message);
        return;
    }

    state.scanning.set(true);
    widgets.process_button.set_sensitive(false);
    widgets.session_button.set_sensitive(false);
    widgets.scan_value.set_sensitive(false);
    widgets.first_scan_button.set_sensitive(false);
    widgets.cancel_scan_button.set_sensitive(true);
    widgets.scan_progress.set_fraction(0.0);
    widgets.scan_progress.set_text(Some("Scanning… 0%"));
    widgets.scan_summary.set_label("Reading target memory…");
    clear_scan_results(&widgets.scan_results);

    let window = window.clone();
    let state = state.clone();
    let widgets = widgets.clone();
    adw::glib::timeout_add_local(WORKER_POLL_INTERVAL, move || {
        let status = state
            .engine
            .borrow()
            .as_ref()
            .expect("engine remains present during scan")
            .scan_status();
        let progress = f64::from(status.progress.clamp(0.0, 1.0));
        widgets.scan_progress.set_fraction(progress);
        let progress_text = if status.cancel_requested {
            "Cancelling…".to_owned()
        } else {
            format!("Scanning… {:.0}%", progress * 100.0)
        };
        widgets.scan_progress.set_text(Some(&progress_text));

        if status.running {
            return adw::glib::ControlFlow::Continue;
        }

        if !status.started {
            widgets.scan_progress.set_text(Some("Not started"));
            return adw::glib::ControlFlow::Break;
        }

        state.scanning.set(false);
        widgets.process_button.set_sensitive(false);
        widgets.session_button.set_sensitive(true);
        widgets.scan_value.set_sensitive(true);
        widgets.first_scan_button.set_sensitive(true);
        widgets.cancel_scan_button.set_sensitive(false);

        if status.cancelled {
            widgets.scan_progress.set_text(Some("Cancelled"));
            widgets.scan_summary.set_label("The scan was cancelled.");
        } else if !status.error_message.is_empty() {
            widgets.scan_progress.set_text(Some("Failed"));
            widgets.scan_summary.set_label(&status.error_message);
            show_message(&window, "Scan failed", &status.error_message);
        } else if status.completed {
            widgets.scan_progress.set_fraction(1.0);
            widgets.scan_progress.set_text(Some("Complete"));
            let preview_note = if status.result_count > status.preview.len() as u64 {
                format!(" Showing the first {}.", status.preview.len())
            } else {
                String::new()
            };
            let disk_note = if status.write_error {
                " Result storage was truncated; check available disk space."
            } else {
                ""
            };
            widgets.scan_summary.set_label(&format!(
                "Found {} addresses.{}{}",
                status.result_count, preview_note, disk_note
            ));
            render_scan_results(&widgets.scan_results, &status.preview);
        }
        adw::glib::ControlFlow::Break
    });
}

fn parse_i32(text: &str) -> Option<i32> {
    let trimmed = text.trim();
    let (negative, digits) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |digits| (true, digits));
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        let magnitude = i64::from_str_radix(hex, 16).ok()?;
        let signed = if negative { -magnitude } else { magnitude };
        i32::try_from(signed).ok()
    } else {
        trimmed.parse().ok()
    }
}

fn render_scan_results(list: &gtk::ListBox, hits: &[crate::bridge::ScanHit]) {
    clear_scan_results(list);
    for hit in hits {
        let row = adw::ActionRow::builder()
            .title(format!("0x{:016X}", hit.address))
            .subtitle(format!("Value: {}", hit.value))
            .build();
        list.append(&row);
    }
}

fn clear_scan_results(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn reset_scan_ui(state: &SessionState, widgets: &SessionWidgets) {
    state.scanning.set(false);
    widgets.scan_value.set_sensitive(true);
    widgets.first_scan_button.set_sensitive(false);
    widgets.cancel_scan_button.set_sensitive(false);
    widgets.scan_progress.set_fraction(0.0);
    widgets.scan_progress.set_text(Some("Ready"));
    widgets
        .scan_summary
        .set_label("Attach to a process to enable exact 4-byte scans.");
    clear_scan_results(&widgets.scan_results);
}

fn show_message(window: &adw::ApplicationWindow, heading: &str, body: &str) {
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}
