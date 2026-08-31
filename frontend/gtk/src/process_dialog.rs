use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use adw::prelude::*;

use crate::bridge::{Engine, Process};

const PROCESS_PAGE_SIZE: u32 = 256;
const SEARCH_DEBOUNCE: Duration = Duration::from_millis(180);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);

pub fn present(parent: &impl IsA<gtk::Widget>, on_selected: impl Fn(Process) + 'static) {
    let dialog = adw::Dialog::builder()
        .title("Choose process")
        .content_width(720)
        .content_height(620)
        .build();

    let header = adw::HeaderBar::new();
    let search = gtk::SearchEntry::builder()
        .placeholder_text("Filter by process name or command")
        .hexpand(true)
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::Single)
        .css_classes(["boxed-list"])
        .build();

    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&list)
        .build();

    let empty = adw::StatusPage::builder()
        .title("No matching processes")
        .description("Try a different name or refresh after starting the target application.")
        .icon_name("system-search-symbolic")
        .build();

    let spinner = gtk::Spinner::builder().spinning(true).build();
    let loading_label = gtk::Label::new(Some("Reading running processes…"));
    let loading = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .halign(gtk::Align::Center)
        .valign(gtk::Align::Center)
        .build();
    loading.append(&spinner);
    loading.append(&loading_label);

    let stack = gtk::Stack::new();
    stack.add_named(&scrolled, Some("results"));
    stack.add_named(&empty, Some("empty"));
    stack.add_named(&loading, Some("loading"));

    let content = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .margin_top(12)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&search);
    content.append(&stack);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));
    dialog.set_child(Some(&toolbar));

    let visible_processes = Rc::new(RefCell::new(Vec::<Process>::new()));
    let generation = Rc::new(Cell::new(0_u64));
    let refresh: Rc<dyn Fn(String)> = Rc::new({
        let list = list.clone();
        let stack = stack.clone();
        let visible_processes = visible_processes.clone();
        let generation = generation.clone();
        move |query: String| {
            let request_generation = generation.get().wrapping_add(1);
            generation.set(request_generation);
            stack.set_visible_child_name("loading");

            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let processes = Engine::new().list_processes(&query, PROCESS_PAGE_SIZE);
                let _ = sender.send(processes);
            });

            let list = list.clone();
            let stack = stack.clone();
            let visible_processes = visible_processes.clone();
            let generation = generation.clone();
            adw::glib::timeout_add_local(WORKER_POLL_INTERVAL, move || match receiver.try_recv() {
                Ok(processes) => {
                    if generation.get() == request_generation {
                        render_processes(&list, &stack, &visible_processes, processes);
                    }
                    adw::glib::ControlFlow::Break
                }
                Err(TryRecvError::Empty) => adw::glib::ControlFlow::Continue,
                Err(TryRecvError::Disconnected) => {
                    if generation.get() == request_generation {
                        render_processes(&list, &stack, &visible_processes, Vec::new());
                    }
                    adw::glib::ControlFlow::Break
                }
            });
        }
    });

    refresh(String::new());
    let pending_search = Rc::new(RefCell::new(None::<adw::glib::SourceId>));
    search.connect_search_changed({
        let refresh = refresh.clone();
        let pending_search = pending_search.clone();
        move |search| {
            if let Some(source) = pending_search.borrow_mut().take() {
                source.remove();
            }

            let query = search.text().to_string();
            let refresh = refresh.clone();
            let pending_search_after_timeout = pending_search.clone();
            let source = adw::glib::timeout_add_local_once(SEARCH_DEBOUNCE, move || {
                pending_search_after_timeout.borrow_mut().take();
                refresh(query);
            });
            *pending_search.borrow_mut() = Some(source);
        }
    });

    let dialog_for_activation = dialog.clone();
    list.connect_row_activated(move |_, row| {
        let Some(process) = visible_processes
            .borrow()
            .get(row.index() as usize)
            .cloned()
        else {
            return;
        };
        on_selected(process);
        dialog_for_activation.close();
    });

    dialog.present(Some(parent));
}

fn render_processes(
    list: &gtk::ListBox,
    stack: &gtk::Stack,
    visible_processes: &RefCell<Vec<Process>>,
    processes: Vec<Process>,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }

    for process in &processes {
        let subtitle = if process.path.is_empty() {
            format!("PID {}", process.pid)
        } else {
            format!("PID {}  ·  {}", process.pid, process.path)
        };
        let row = adw::ActionRow::builder()
            .title(&process.name)
            .subtitle(&subtitle)
            .activatable(true)
            .build();
        row.set_tooltip_text(Some(&process.path));
        if process.sandboxed {
            let badge = gtk::Label::builder()
                .label("Sandboxed")
                .css_classes(["caption", "dim-label"])
                .build();
            row.add_suffix(&badge);
        }
        list.append(&row);
    }

    stack.set_visible_child_name(if processes.is_empty() {
        "empty"
    } else {
        "results"
    });
    *visible_processes.borrow_mut() = processes;
}
