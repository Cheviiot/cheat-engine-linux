use adw::prelude::*;
use gtk::{Align, Orientation};

use crate::bridge::Engine;
use crate::process_dialog;

pub const DEVELOPMENT_APP_ID: &str = "io.github.cheviiot.CeGtk.Devel";

pub fn build_application() -> adw::Application {
    let application = adw::Application::builder()
        .application_id(DEVELOPMENT_APP_ID)
        .build();

    application.connect_activate(build_window);
    application
}

fn build_window(application: &adw::Application) {
    let engine = Engine::new();

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
        .label(format!("libcecore {}", engine.version()))
        .selectable(true)
        .xalign(0.0)
        .build();

    let selected_process = gtk::Label::builder()
        .label("No process selected")
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();

    let process_button = gtk::Button::builder()
        .label("Choose process")
        .css_classes(["suggested-action", "pill"])
        .halign(Align::Start)
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
    content.append(&process_button);

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
        .default_height(620)
        .content(&toolbar_view)
        .build();

    process_button.connect_clicked({
        let window = window.clone();
        let selected_process = selected_process.clone();
        move |_| {
            process_dialog::present(&window, {
                let selected_process = selected_process.clone();
                move |process| {
                    selected_process.set_label(&format!(
                        "Selected {} (PID {}) — attach is the next slice",
                        process.name, process.pid
                    ));
                }
            });
        }
    });

    window.present();
}
