use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

use adw::prelude::*;
use gtk::{Align, Orientation};

use crate::address_list_model::{
    AddressListModel, DEFAULT_ADDRESS_CACHE_PAGES, IssueHandler as AddressIssueHandler,
    MAX_ADDRESS_PAGE_SIZE, ModelIssue as AddressModelIssue, PageLoader as AddressPageLoader,
    VirtualAddressRow,
};
use crate::bridge::{
    AddressRecord, AttachError, Engine, FreezeMode, LuaExecution, Process, ProtectionMatch,
    ScanComparison, ScanRequest, ScanValueType, Session, TableAction, TableCompatibilityIssue,
    TableScript, TableScriptKind,
};
use crate::process_dialog;
use crate::scan_result_model::{
    DEFAULT_CACHE_PAGES, IssueHandler, MAX_BRIDGE_PAGE_SIZE, ModelIssue, PageLoader,
    ScanResultModel, VirtualScanRow,
};

pub const DEVELOPMENT_APP_ID: &str = "io.github.cheviiot.CeGtk.Devel";
static ADDRESS_LIST_SMOKE_OK: AtomicBool = AtomicBool::new(false);
static MAIN_LAYOUT_SMOKE_OK: AtomicBool = AtomicBool::new(false);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SCRIPT_REVIEW_PAGE_SIZE: u32 = 64;
const SCRIPT_TEXT_PAGE_SIZE: u32 = 64 << 10;
const RUNTIME_TICK_INTERVAL: Duration = Duration::from_millis(30);
const LUA_CONSOLE_TRANSCRIPT_LIMIT: i32 = 256 << 10;
const LUA_CONSOLE_HISTORY_LIMIT: usize = 100;
const LUA_CONSOLE_HISTORY_BYTES_LIMIT: usize = 1 << 20;

#[derive(Clone)]
struct SessionState {
    engine: Rc<RefCell<Option<Engine>>>,
    selected: Rc<RefCell<Option<Process>>>,
    attached: Rc<Cell<bool>>,
    scanning: Rc<Cell<bool>>,
    scan_generation: Rc<Cell<u64>>,
    address_value_entries: Rc<RefCell<HashMap<i32, gtk::Entry>>>,
    address_visible_pages: Rc<RefCell<HashMap<u64, usize>>>,
    selected_address_ids: Rc<RefCell<HashSet<i32>>>,
    table_scripts_trusted: Rc<Cell<bool>>,
    table_lua_trusted: Rc<Cell<bool>>,
    table_contains_auto_assembler: Rc<Cell<bool>>,
    table_contains_lua: Rc<Cell<bool>>,
    table_compatibility_issues: Rc<RefCell<Vec<TableCompatibilityIssue>>>,
    lua_runtime_generation: Rc<Cell<u64>>,
    lua_console_dialog: Rc<RefCell<Option<adw::Dialog>>>,
    lua_console_output: Rc<RefCell<Option<gtk::TextView>>>,
    lua_console_status: Rc<RefCell<Option<gtk::Label>>>,
    lua_console_backlog: Rc<RefCell<String>>,
    lua_console_history: Rc<RefCell<Vec<String>>>,
}

#[derive(Clone)]
struct SessionWidgets {
    selected_process: gtk::Label,
    session_details: gtk::Label,
    process_button: gtk::Button,
    session_button: gtk::Button,
    value_type: gtk::DropDown,
    comparison: gtk::DropDown,
    scan_value: gtk::Entry,
    scan_value2: gtk::Entry,
    hexadecimal: gtk::CheckButton,
    start_address: gtk::Entry,
    stop_address: gtk::Entry,
    fast_scan: gtk::CheckButton,
    alignment: gtk::Entry,
    value_size: gtk::Entry,
    value_size_label: gtk::Label,
    writable_match: gtk::DropDown,
    executable_match: gtk::DropDown,
    scan_private: gtk::CheckButton,
    scan_image: gtk::CheckButton,
    scan_mapped: gtk::CheckButton,
    rounding_type: gtk::DropDown,
    rounding_type_label: gtk::Label,
    float_tolerance: gtk::Entry,
    float_tolerance_label: gtk::Label,
    percentage_scan: gtk::CheckButton,
    percentage_label: gtk::Label,
    percentage_value: gtk::Entry,
    percentage_value2: gtk::Entry,
    case_sensitive: gtk::CheckButton,
    string_matching_label: gtk::Label,
    string_encoding: gtk::Entry,
    string_encoding_label: gtk::Label,
    first_scan_button: gtk::Button,
    next_scan_button: gtk::Button,
    undo_scan_button: gtk::Button,
    cancel_scan_button: gtk::Button,
    scan_progress: gtk::ProgressBar,
    scan_summary: gtk::Label,
    scan_result_model: ScanResultModel,
    page_label: gtk::Label,
    scan_empty_hint: gtk::Label,
    address_list_model: AddressListModel,
    address_summary: gtk::Label,
    address_empty_hint: gtk::Label,
    memory_view_button: gtk::Button,
    group_selected_button: gtk::Button,
    script_trust_button: gtk::Button,
    compatibility_report_button: gtk::Button,
}

#[derive(Clone, Copy)]
enum ScanKind {
    First,
    Next,
}

pub fn build_application() -> adw::Application {
    let application = adw::Application::builder()
        .application_id(DEVELOPMENT_APP_ID)
        .build();

    application.connect_activate(build_window);
    application
}

pub fn address_list_smoke_ok() -> bool {
    ADDRESS_LIST_SMOKE_OK.load(Ordering::SeqCst)
}

pub fn main_layout_smoke_ok() -> bool {
    MAIN_LAYOUT_SMOKE_OK.load(Ordering::SeqCst)
}

fn build_window(application: &adw::Application) {
    let mut engine = Engine::new();
    let address_list_smoke = std::env::var_os("CE_GTK_ADDRESS_LIST_SMOKE").is_some();
    let memory_debug_smoke = std::env::var_os("CE_GTK_MEMORY_DEBUG_SMOKE").is_some();
    let memory_view_smoke =
        memory_debug_smoke || std::env::var_os("CE_GTK_MEMORY_VIEW_SMOKE").is_some();
    let debug_smoke_child: Rc<RefCell<Option<Child>>> =
        Rc::new(RefCell::new(memory_debug_smoke.then(|| {
            Command::new("sh")
                .args(["-c", "while :; do :; done"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("start GTK debugger smoke target")
        })));
    if address_list_smoke {
        for index in 0..600_u64 {
            engine
                .add_address(
                    0x1000 + index * 4,
                    ScanValueType::Int32,
                    &format!("Virtual address {index}"),
                    0,
                    false,
                )
                .expect("populate the virtual address-list smoke fixture");
        }
    }
    let memory_view_smoke_session = if memory_view_smoke {
        let pid = debug_smoke_child
            .borrow()
            .as_ref()
            .map_or_else(|| std::process::id() as i32, |child| child.id() as i32);
        Some(
            engine
                .attach(pid, "GTK memory-view smoke")
                .expect("attach the memory-view smoke fixture"),
        )
    } else {
        None
    };
    let core_version = engine.version();
    let lua_runtime_generation = engine.lua_runtime_generation();
    let state = SessionState {
        engine: Rc::new(RefCell::new(Some(engine))),
        selected: Rc::new(RefCell::new(memory_view_smoke_session.as_ref().map(
            |session| Process {
                pid: session.pid,
                name: session.name.clone(),
                path: String::new(),
                sandboxed: session.sandboxed,
            },
        ))),
        attached: Rc::new(Cell::new(memory_view_smoke_session.is_some())),
        scanning: Rc::new(Cell::new(false)),
        scan_generation: Rc::new(Cell::new(0)),
        address_value_entries: Rc::new(RefCell::new(HashMap::new())),
        address_visible_pages: Rc::new(RefCell::new(HashMap::new())),
        selected_address_ids: Rc::new(RefCell::new(HashSet::new())),
        table_scripts_trusted: Rc::new(Cell::new(false)),
        table_lua_trusted: Rc::new(Cell::new(false)),
        table_contains_auto_assembler: Rc::new(Cell::new(false)),
        table_contains_lua: Rc::new(Cell::new(false)),
        table_compatibility_issues: Rc::new(RefCell::new(Vec::new())),
        lua_runtime_generation: Rc::new(Cell::new(lua_runtime_generation)),
        lua_console_dialog: Rc::new(RefCell::new(None)),
        lua_console_output: Rc::new(RefCell::new(None)),
        lua_console_status: Rc::new(RefCell::new(None)),
        lua_console_backlog: Rc::new(RefCell::new(String::new())),
        lua_console_history: Rc::new(RefCell::new(Vec::new())),
    };
    if memory_debug_smoke {
        application.connect_shutdown({
            let debug_smoke_child = debug_smoke_child.clone();
            move |_| {
                if let Some(mut child) = debug_smoke_child.borrow_mut().take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        });
    }

    let header = adw::HeaderBar::new();
    let window_title = adw::WindowTitle::builder()
        .title("LCH")
        .subtitle(format!("Memory scanner · libcecore {core_version}"))
        .build();
    header.set_title_widget(Some(&window_title));

    let main_menu_model = gtk::gio::Menu::new();
    let file_menu = gtk::gio::Menu::new();
    file_menu.append(Some("Open table…"), Some("main.open-table"));
    file_menu.append(Some("Save table…"), Some("main.save-table"));
    file_menu.append(Some("Quit"), Some("main.quit"));
    main_menu_model.append_submenu(Some("File"), &file_menu);

    let process_menu = gtk::gio::Menu::new();
    process_menu.append(Some("Open process…"), Some("main.open-process"));
    process_menu.append(Some("Attach / Detach"), Some("main.toggle-session"));
    main_menu_model.append_submenu(Some("Process"), &process_menu);

    let table_menu = gtk::gio::Menu::new();
    table_menu.append(Some("Add address…"), Some("main.add-address"));
    table_menu.append(Some("New group"), Some("main.add-group"));
    main_menu_model.append_submenu(Some("Table"), &table_menu);

    let tools_menu = gtk::gio::Menu::new();
    tools_menu.append(Some("Memory View"), Some("main.memory-view"));
    tools_menu.append(Some("Lua Console"), Some("main.lua-console"));
    main_menu_model.append_submenu(Some("Tools"), &tools_menu);

    let help_menu = gtk::gio::Menu::new();
    help_menu.append(Some("About this build"), Some("main.about"));
    main_menu_model.append_submenu(Some("Help"), &help_menu);
    let main_menu_bar = gtk::PopoverMenuBar::from_model(Some(&main_menu_model));
    let main_action_group = gtk::gio::SimpleActionGroup::new();
    let lua_console_button = gtk::Button::builder()
        .label("Lua Console")
        .icon_name("utilities-terminal-symbolic")
        .tooltip_text("Open the bounded interactive Lua console")
        .build();

    let selected_process = gtk::Label::builder()
        .label("No process selected")
        .xalign(0.0)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .css_classes(["heading"])
        .build();

    let session_details = gtk::Label::builder()
        .label("")
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .xalign(0.0)
        .hexpand(true)
        .selectable(true)
        .css_classes(["dim-label"])
        .build();

    let process_button = gtk::Button::builder()
        .icon_name("system-search-symbolic")
        .tooltip_text("Choose a running process")
        .halign(Align::Start)
        .build();

    let session_button = gtk::Button::builder()
        .label("Attach")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();

    let process_identity = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(10)
        .hexpand(true)
        .valign(Align::Center)
        .build();
    process_identity.append(&selected_process);
    process_identity.append(&session_details);

    let session_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(5)
        .margin_bottom(5)
        .margin_start(6)
        .margin_end(6)
        .build();
    session_actions.append(&process_button);
    session_actions.append(&process_identity);

    let value_type = gtk::DropDown::from_strings(&ScanValueType::LABELS);
    value_type.set_selected(ScanValueType::Int32 as u32);
    value_type.set_hexpand(true);
    let comparison = gtk::DropDown::from_strings(&ScanComparison::LABELS);
    comparison.set_selected(ScanComparison::Exact as u32);
    comparison.set_hexpand(true);

    let scan_value = gtk::Entry::builder()
        .placeholder_text("Value")
        .hexpand(true)
        .build();
    let scan_value2 = gtk::Entry::builder()
        .placeholder_text("Upper value")
        .hexpand(true)
        .visible(false)
        .build();
    let hexadecimal = gtk::CheckButton::builder().label("Hex").build();

    let scan_values_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    scan_values_row.append(&scan_value);
    scan_values_row.append(&scan_value2);
    scan_values_row.append(&hexadecimal);

    let first_scan_button = gtk::Button::builder()
        .label("First Scan")
        .css_classes(["suggested-action"])
        .sensitive(false)
        .build();
    let next_scan_button = gtk::Button::builder()
        .label("Next Scan")
        .sensitive(false)
        .build();
    let undo_scan_button = gtk::Button::builder()
        .label("Undo Scan")
        .sensitive(false)
        .build();
    let cancel_scan_button = gtk::Button::builder()
        .label("Cancel")
        .sensitive(false)
        .visible(false)
        .build();

    let scan_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .homogeneous(true)
        .build();
    scan_actions.append(&first_scan_button);
    scan_actions.append(&next_scan_button);
    scan_actions.append(&undo_scan_button);
    scan_actions.append(&cancel_scan_button);

    let start_address = gtk::Entry::builder().text("0x0").hexpand(true).build();
    let stop_address = gtk::Entry::builder()
        .text("0x00007FFFFFFFFFFF")
        .hexpand(true)
        .build();
    let fast_scan = gtk::CheckButton::builder()
        .label("Fast Scan")
        .active(true)
        .build();
    let alignment = gtk::Entry::builder()
        .text("4")
        .width_chars(5)
        .max_width_chars(8)
        .build();
    let fast_scan_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    fast_scan_row.append(&fast_scan);
    fast_scan_row.append(&alignment);
    let value_size = gtk::Entry::builder()
        .placeholder_text("Automatic")
        .hexpand(true)
        .build();
    let writable_match = gtk::DropDown::from_strings(&ProtectionMatch::LABELS);
    writable_match.set_hexpand(true);
    let executable_match = gtk::DropDown::from_strings(&ProtectionMatch::LABELS);
    executable_match.set_hexpand(true);
    let scan_private = gtk::CheckButton::builder()
        .label("Private")
        .active(true)
        .build();
    let scan_image = gtk::CheckButton::builder()
        .label("Image")
        .active(true)
        .build();
    let scan_mapped = gtk::CheckButton::builder()
        .label("Mapped")
        .active(true)
        .build();
    let rounding_type =
        gtk::DropDown::from_strings(&["Exact", "Rounded", "Truncated", "Tolerance"]);
    rounding_type.set_hexpand(true);
    let float_tolerance = gtk::Entry::builder().text("0").hexpand(true).build();
    let percentage_scan = gtk::CheckButton::builder().label("Compare by %").build();
    let percentage_value = gtk::Entry::builder()
        .text("0")
        .placeholder_text("Percent")
        .hexpand(true)
        .build();
    let percentage_value2 = gtk::Entry::builder()
        .text("0")
        .placeholder_text("Upper percent")
        .hexpand(true)
        .build();
    let case_sensitive = gtk::CheckButton::builder()
        .label("Case sensitive")
        .active(true)
        .build();
    let string_encoding = gtk::Entry::builder().text("UTF-8").hexpand(true).build();

    let regions_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    regions_row.append(&scan_private);
    regions_row.append(&scan_image);
    regions_row.append(&scan_mapped);
    let percentage_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    percentage_row.append(&percentage_scan);
    percentage_row.append(&percentage_value);
    percentage_row.append(&percentage_value2);

    let advanced_grid = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(5)
        .margin_top(6)
        .build();
    let range_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();
    range_row.append(&gtk::Label::new(Some("From")));
    range_row.append(&start_address);
    range_row.append(&gtk::Label::new(Some("To")));
    range_row.append(&stop_address);
    advanced_grid.attach(&range_row, 0, 0, 2, 1);
    advanced_grid.attach(&fast_scan_row, 0, 1, 2, 1);

    let protection_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();
    protection_row.append(&gtk::Label::new(Some("Writable")));
    protection_row.append(&writable_match);
    protection_row.append(&gtk::Label::new(Some("Executable")));
    protection_row.append(&executable_match);
    advanced_grid.attach(&protection_row, 0, 2, 2, 1);
    attach_advanced_row(&advanced_grid, 3, "Region types", &regions_row);
    let percentage_label = attach_advanced_row(&advanced_grid, 4, "", &percentage_row);
    let value_size_label =
        attach_advanced_row(&advanced_grid, 5, "Value size (bytes)", &value_size);
    let rounding_type_label =
        attach_advanced_row(&advanced_grid, 6, "Float rounding", &rounding_type);
    let float_tolerance_label =
        attach_advanced_row(&advanced_grid, 7, "Float tolerance", &float_tolerance);
    let string_matching_label =
        attach_advanced_row(&advanced_grid, 8, "String matching", &case_sensitive);
    let string_encoding_label =
        attach_advanced_row(&advanced_grid, 9, "String encoding", &string_encoding);
    let advanced_options = gtk::Expander::builder()
        .label("Memory Scan Options")
        .expanded(true)
        .child(&advanced_grid)
        .build();

    let scan_progress = gtk::ProgressBar::builder()
        .show_text(true)
        .visible(false)
        .build();
    scan_progress.set_fraction(0.0);
    scan_progress.set_text(Some("Ready"));

    let scan_summary = gtk::Label::builder()
        .label("Attach to a process to begin scanning memory.")
        .wrap(true)
        .xalign(0.0)
        .visible(false)
        .css_classes(["dim-label"])
        .build();

    let scan_result_model = ScanResultModel::new(MAX_BRIDGE_PAGE_SIZE, DEFAULT_CACHE_PAGES);
    let scan_result_selection = gtk::NoSelection::new(Some(scan_result_model.clone()));
    let scan_result_factory = gtk::SignalListItemFactory::new();
    let scan_results = gtk::ListView::new(
        Some(scan_result_selection),
        Some(scan_result_factory.clone()),
    );
    scan_results.set_show_separators(true);
    scan_results.add_css_class("boxed-list");
    let scan_results_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(160)
        .vexpand(true)
        .child(&scan_results)
        .build();
    let scan_empty_hint = gtk::Label::builder()
        .label("No results yet.\n\nEnter a value and press First Scan,\nor choose a process from the toolbar.")
        .justify(gtk::Justification::Center)
        .halign(Align::Center)
        .valign(Align::Center)
        .css_classes(["dim-label"])
        .build();
    scan_empty_hint.set_can_target(false);
    let scan_results_overlay = gtk::Overlay::new();
    scan_results_overlay.set_child(Some(&scan_results_scrolled));
    scan_results_overlay.add_overlay(&scan_empty_hint);

    let page_label = gtk::Label::builder()
        .label("Found: 0")
        .xalign(0.0)
        .hexpand(true)
        .css_classes(["dim-label"])
        .build();

    let memory_view_button = gtk::Button::builder()
        .label("Memory View")
        .tooltip_text("Open the disassembler and hex dump")
        .sensitive(false)
        .build();

    let add_address_button = gtk::Button::builder()
        .label("Add Address")
        .css_classes(["flat"])
        .build();
    let open_table_button = gtk::Button::builder()
        .label("Open")
        .css_classes(["flat"])
        .tooltip_text("Open a cheat table")
        .build();
    let save_table_button = gtk::Button::builder()
        .label("Save")
        .css_classes(["flat"])
        .tooltip_text("Save the current cheat table")
        .build();
    let address_header = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();
    address_header.set_hexpand(true);
    address_header.append(&open_table_button);
    address_header.append(&save_table_button);
    let add_group_button = gtk::Button::builder().label("New group").build();
    let group_selected_button = gtk::Button::builder()
        .label("Group selected")
        .sensitive(false)
        .build();
    let script_trust_button = gtk::Button::builder()
        .label("Scripts blocked")
        .icon_name("security-high-symbolic")
        .visible(false)
        .build();
    let compatibility_report_button = gtk::Button::builder()
        .label("Table report")
        .icon_name("dialog-information-symbolic")
        .tooltip_text("Review preserved-but-unavailable features and known format losses")
        .visible(false)
        .build();
    let address_structure_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();
    address_structure_actions.append(&add_group_button);
    address_structure_actions.append(&group_selected_button);
    address_structure_actions.append(&compatibility_report_button);
    address_structure_actions.append(&script_trust_button);
    let address_summary = gtk::Label::builder()
        .label("Add scan results here to edit or freeze their live values.")
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .css_classes(["dim-label"])
        .build();
    let address_list_model =
        AddressListModel::new(MAX_ADDRESS_PAGE_SIZE, DEFAULT_ADDRESS_CACHE_PAGES);
    let address_selection = gtk::NoSelection::new(Some(address_list_model.clone()));
    let address_factory = gtk::SignalListItemFactory::new();
    let address_list = gtk::ListView::new(Some(address_selection), Some(address_factory.clone()));
    address_list.set_show_separators(true);
    address_list.add_css_class("boxed-list");
    let address_list_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_height(180)
        .vexpand(true)
        .child(&address_list)
        .build();
    let address_empty_hint = gtk::Label::builder()
        .label("No saved addresses.\n\nDouble-click a scan result to add it here,\nor use Add Address.")
        .justify(gtk::Justification::Center)
        .halign(Align::Center)
        .valign(Align::Center)
        .css_classes(["dim-label"])
        .build();
    address_empty_hint.set_can_target(false);
    let address_list_overlay = gtk::Overlay::new();
    address_list_overlay.set_child(Some(&address_list_scrolled));
    address_list_overlay.add_overlay(&address_empty_hint);

    // Keep Cheat Engine's proven information architecture while using native
    // GTK/libadwaita widgets: process across the top, found addresses beside a
    // fixed-width scan panel, and the cheat table across the full lower pane.
    let process_bar = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .build();
    process_bar.append(&session_actions);
    process_bar.append(&gtk::Separator::new(Orientation::Horizontal));

    let result_columns = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .css_classes(["dim-label"])
        .build();
    let result_address_column = compact_column_header("Address", 24, true);
    let result_value_column = compact_column_header("Value", 10, false);
    result_value_column.set_hexpand(true);
    result_columns.append(&result_address_column);
    result_columns.append(&result_value_column);
    result_columns.append(&compact_column_header("", 8, false));

    let results_footer = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(6)
        .build();
    results_footer.append(&gtk::Box::builder().hexpand(true).build());
    results_footer.append(&memory_view_button);
    results_footer.append(&add_address_button);

    let results_panel = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    results_panel.append(&page_label);
    results_panel.append(&result_columns);
    results_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    results_panel.append(&scan_results_overlay);
    results_panel.append(&results_footer);
    let results_frame = gtk::Frame::builder().child(&results_panel).build();

    let scan_form = gtk::Grid::builder()
        .column_spacing(8)
        .row_spacing(8)
        .build();
    attach_scan_control_row(&scan_form, 0, "Scan value", &scan_values_row);
    attach_scan_control_row(&scan_form, 1, "Scan type", &comparison);
    attach_scan_control_row(&scan_form, 2, "Value type", &value_type);

    let scan_controls = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    scan_controls.append(&scan_actions);
    scan_controls.append(&scan_form);
    scan_controls.append(&advanced_options);
    scan_controls.append(&scan_progress);
    scan_controls.append(&scan_summary);
    let scan_controls_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .min_content_width(330)
        .child(&scan_controls)
        .build();
    let scan_controls_frame = gtk::Frame::builder().child(&scan_controls_scrolled).build();

    let top_paned = gtk::Paned::new(Orientation::Horizontal);
    top_paned.set_wide_handle(true);
    top_paned.set_start_child(Some(&results_frame));
    top_paned.set_end_child(Some(&scan_controls_frame));
    top_paned.set_resize_start_child(true);
    top_paned.set_shrink_start_child(false);
    top_paned.set_resize_end_child(false);
    top_paned.set_shrink_end_child(false);
    top_paned.set_position(690);

    let address_columns = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .css_classes(["dim-label"])
        .build();
    address_columns.append(&compact_column_header("Sel", 4, false));
    address_columns.append(&compact_column_header("Active", 5, false));
    let description_column = compact_column_header("Description", 18, false);
    description_column.set_hexpand(true);
    address_columns.append(&description_column);
    address_columns.append(&compact_column_header("Address / Type", 28, true));
    address_columns.append(&compact_column_header("Value", 12, true));
    address_columns.append(&compact_column_header("Actions", 12, false));

    let address_toolbar = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(6)
        .margin_end(6)
        .build();
    address_toolbar.append(&address_header);
    address_toolbar.append(&address_structure_actions);
    address_toolbar.append(&gtk::Separator::new(Orientation::Vertical));
    address_toolbar.append(&address_summary);

    let address_panel = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .build();
    address_panel.append(&address_columns);
    address_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    address_panel.append(&address_list_overlay);
    address_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    address_panel.append(&address_toolbar);
    let address_frame = gtk::Frame::builder().child(&address_panel).build();

    let workspace_paned = gtk::Paned::new(Orientation::Vertical);
    workspace_paned.set_wide_handle(true);
    workspace_paned.set_start_child(Some(&top_paned));
    workspace_paned.set_end_child(Some(&address_frame));
    workspace_paned.set_resize_start_child(false);
    workspace_paned.set_shrink_start_child(false);
    workspace_paned.set_resize_end_child(true);
    workspace_paned.set_shrink_end_child(false);
    workspace_paned.set_position(390);

    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(4)
        .margin_end(4)
        .build();
    content.append(&process_bar);
    content.append(&workspace_paned);

    MAIN_LAYOUT_SMOKE_OK.store(
        main_menu_model.n_items() == 5
            && process_bar.last_child().is_some()
            && session_actions
                .first_child()
                .and_then(|child| child.next_sibling())
                .is_some_and(|child| child.next_sibling().is_none())
            && advanced_options.is_expanded()
            && scan_empty_hint.is_visible()
            && address_empty_hint.is_visible()
            && memory_view_button.label().as_deref() == Some("Memory View")
            && add_address_button.label().as_deref() == Some("Add Address")
            && top_paned.orientation() == Orientation::Horizontal
            && top_paned.start_child().is_some()
            && top_paned.end_child().is_some()
            && workspace_paned.orientation() == Orientation::Vertical
            && workspace_paned.start_child().is_some()
            && workspace_paned.end_child().is_some(),
        Ordering::SeqCst,
    );

    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header);
    toolbar_view.add_top_bar(&main_menu_bar);
    toolbar_view.set_content(Some(&content));

    let window = adw::ApplicationWindow::builder()
        .application(application)
        .title("LCH — Memory Scanner")
        .default_width(1100)
        .default_height(760)
        .content(&toolbar_view)
        .build();
    window.insert_action_group("main", Some(&main_action_group));

    add_main_button_action(&main_action_group, "open-table", &open_table_button);
    add_main_button_action(&main_action_group, "save-table", &save_table_button);
    add_main_action(&main_action_group, "quit", {
        let window = window.clone();
        move || window.close()
    });
    add_main_button_action(&main_action_group, "open-process", &process_button);
    add_main_button_action(&main_action_group, "toggle-session", &session_button);
    add_main_button_action(&main_action_group, "add-address", &add_address_button);
    add_main_button_action(&main_action_group, "add-group", &add_group_button);
    add_main_button_action(&main_action_group, "memory-view", &memory_view_button);
    add_main_button_action(&main_action_group, "lua-console", &lua_console_button);
    add_main_action(&main_action_group, "about", {
        let window = window.clone();
        move || {
            show_message(
                &window,
                "LCH GTK development build",
                "A native GTK4/libadwaita rewrite using the shared libcecore engine.",
            )
        }
    });

    let widgets = SessionWidgets {
        selected_process,
        session_details,
        process_button,
        session_button,
        value_type,
        comparison,
        scan_value,
        scan_value2,
        hexadecimal,
        start_address,
        stop_address,
        fast_scan,
        alignment,
        value_size,
        value_size_label,
        writable_match,
        executable_match,
        scan_private,
        scan_image,
        scan_mapped,
        rounding_type,
        rounding_type_label,
        float_tolerance,
        float_tolerance_label,
        percentage_scan,
        percentage_label,
        percentage_value,
        percentage_value2,
        case_sensitive,
        string_matching_label,
        string_encoding,
        string_encoding_label,
        first_scan_button,
        next_scan_button,
        undo_scan_button,
        cancel_scan_button,
        scan_progress,
        scan_summary,
        scan_result_model,
        page_label,
        scan_empty_hint,
        address_list_model,
        address_summary,
        address_empty_hint,
        memory_view_button,
        group_selected_button,
        script_trust_button,
        compatibility_report_button,
    };

    configure_scan_result_factory(&scan_result_factory, &state, &widgets, &window);
    configure_address_list_factory(&address_factory, &state, &widgets, &window);
    if let Some(session) = memory_view_smoke_session.as_ref() {
        show_attached(&state, &widgets, session);
    }

    update_scan_option_visibility(&widgets);
    widgets.value_type.connect_selected_notify({
        let widgets = widgets.clone();
        move |_| update_scan_option_visibility(&widgets)
    });
    widgets.comparison.connect_selected_notify({
        let widgets = widgets.clone();
        move |_| update_scan_option_visibility(&widgets)
    });
    widgets.percentage_scan.connect_toggled({
        let widgets = widgets.clone();
        move |_| update_scan_option_visibility(&widgets)
    });
    widgets.fast_scan.connect_toggled({
        let widgets = widgets.clone();
        move |_| update_scan_option_visibility(&widgets)
    });
    widgets.rounding_type.connect_selected_notify({
        let widgets = widgets.clone();
        move |_| update_scan_option_visibility(&widgets)
    });

    widgets.process_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| {
            process_dialog::present(&window, {
                let window = window.clone();
                let state = state.clone();
                let widgets = widgets.clone();
                move |process| {
                    widgets
                        .selected_process
                        .set_label(&format!("Selected {} (PID {})", process.name, process.pid));
                    widgets.session_details.set_label("Opening memory session…");
                    widgets.session_button.set_sensitive(true);
                    *state.selected.borrow_mut() = Some(process);
                    start_attach(&window, &state, &widgets);
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
        move |_| start_scan(&window, &state, &widgets, ScanKind::First)
    });

    widgets.next_scan_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| start_scan(&window, &state, &widgets, ScanKind::Next)
    });

    widgets.undo_scan_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| undo_scan(&window, &state, &widgets)
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

    add_address_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| present_add_address_dialog(&window, &state, &widgets)
    });

    add_group_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| present_group_dialog(&window, &state, &widgets, false)
    });

    widgets.group_selected_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| present_group_dialog(&window, &state, &widgets, true)
    });

    open_table_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| present_open_table_dialog(&window, &state, &widgets)
    });

    save_table_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| present_save_table_dialog(&window, &state, &widgets)
    });

    widgets.script_trust_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_| {
            let action = crate::bridge::TableAction {
                record_count: 0,
                contains_scripts: true,
                contains_auto_assembler: state.table_contains_auto_assembler.get(),
                contains_lua: state.table_contains_lua.get(),
                compatibility_issues: Vec::new(),
            };
            present_script_trust_dialog(&window, &state, &widgets, &action);
        }
    });

    widgets.compatibility_report_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        move |_| present_table_compatibility_report(&window, &state)
    });

    lua_console_button.connect_clicked({
        let window = window.clone();
        let state = state.clone();
        move |_| present_lua_console_dialog(&window, &state)
    });

    widgets.memory_view_button.connect_clicked({
        let window = window.clone();
        let engine = state.engine.clone();
        move |_| crate::memory_view::present(&window, engine.clone(), 0)
    });

    scan_results.set_single_click_activate(false);
    scan_results.connect_activate({
        let state = state.clone();
        let widgets = widgets.clone();
        move |list, position| {
            let Some(item) = list
                .model()
                .and_then(|model| model.item(position))
                .and_downcast::<adw::glib::BoxedAnyObject>()
            else {
                return;
            };
            let row = item.borrow::<VirtualScanRow>();
            let VirtualScanRow::Loaded { index, .. } = &*row else {
                return;
            };
            add_virtual_scan_result(&state, &widgets, None, *index);
        }
    });

    if address_list_smoke {
        reload_address_list(&state, &widgets, false);
        let address_list = address_list.clone();
        let address_list_model = widgets.address_list_model.clone();
        adw::glib::timeout_add_local(Duration::from_millis(50), move || {
            address_list.scroll_to(300, gtk::ListScrollFlags::FOCUS, None);
            if address_list_model.total_count() == 600 && address_list_model.is_loaded(300) {
                ADDRESS_LIST_SMOKE_OK.store(true, Ordering::SeqCst);
                adw::glib::ControlFlow::Break
            } else {
                adw::glib::ControlFlow::Continue
            }
        });
    }

    install_runtime_tick(&state, &widgets);

    window.present();
    if memory_view_smoke {
        crate::memory_view::present(&window, state.engine.clone(), 0);
    }
}

fn attach_advanced_row<W: IsA<gtk::Widget>>(
    grid: &gtk::Grid,
    row: i32,
    title: &str,
    child: &W,
) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(title)
        .halign(Align::Start)
        .xalign(0.0)
        .build();
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(child, 1, row, 1, 1);
    label
}

fn attach_scan_control_row<W: IsA<gtk::Widget>>(
    grid: &gtk::Grid,
    row: i32,
    title: &str,
    child: &W,
) {
    let label = gtk::Label::builder()
        .label(title)
        .halign(Align::End)
        .xalign(1.0)
        .build();
    grid.attach(&label, 0, row, 1, 1);
    grid.attach(child, 1, row, 1, 1);
}

fn compact_column_header(title: &str, width_chars: i32, monospace: bool) -> gtk::Label {
    let label = gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .width_chars(width_chars)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .css_classes(["caption", "heading"])
        .build();
    if monospace {
        label.add_css_class("monospace");
    }
    label
}

fn update_scan_option_visibility(widgets: &SessionWidgets) {
    let value_type =
        ScanValueType::from_index(widgets.value_type.selected()).unwrap_or(ScanValueType::Int32);
    let comparison =
        ScanComparison::from_index(widgets.comparison.selected()).unwrap_or(ScanComparison::Exact);
    let takes_value = comparison.takes_value();
    let between = comparison == ScanComparison::Between;
    let integer = matches!(
        value_type,
        ScanValueType::Byte
            | ScanValueType::Int16
            | ScanValueType::Int32
            | ScanValueType::Int64
            | ScanValueType::All
            | ScanValueType::Pointer
    );
    let floating = matches!(
        value_type,
        ScanValueType::Float | ScanValueType::Double | ScanValueType::All
    );
    let string = matches!(
        value_type,
        ScanValueType::String | ScanValueType::UnicodeString
    );
    let bytewise = matches!(
        value_type,
        ScanValueType::String
            | ScanValueType::UnicodeString
            | ScanValueType::ByteArray
            | ScanValueType::Binary
            | ScanValueType::Grouped
            | ScanValueType::Custom
    );
    let variable_snapshot = !takes_value
        && matches!(
            value_type,
            ScanValueType::String
                | ScanValueType::UnicodeString
                | ScanValueType::ByteArray
                | ScanValueType::Binary
        );
    let show_value_size = variable_snapshot || value_type == ScanValueType::Custom;
    let show_float_tolerance = floating && widgets.rounding_type.selected() == 3;
    let show_percentage = floating || (integer && value_type != ScanValueType::All);

    widgets.scan_value.set_visible(takes_value);
    if value_type == ScanValueType::Grouped {
        widgets.scan_value.set_visible(true);
    }
    widgets.scan_value2.set_visible(between);
    widgets.hexadecimal.set_visible(takes_value && integer);
    widgets.rounding_type.set_sensitive(floating);
    widgets.float_tolerance.set_sensitive(show_float_tolerance);
    widgets.rounding_type.set_visible(floating);
    widgets.rounding_type_label.set_visible(floating);
    widgets.float_tolerance.set_visible(show_float_tolerance);
    widgets
        .float_tolerance_label
        .set_visible(show_float_tolerance);
    widgets.case_sensitive.set_sensitive(string);
    widgets.string_encoding.set_sensitive(string);
    widgets.case_sensitive.set_visible(string);
    widgets.string_matching_label.set_visible(string);
    widgets.string_encoding.set_visible(string);
    widgets.string_encoding_label.set_visible(string);
    widgets
        .alignment
        .set_sensitive(!bytewise && widgets.fast_scan.is_active());
    widgets.value_size.set_sensitive(show_value_size);
    widgets.value_size.set_visible(show_value_size);
    widgets.value_size_label.set_visible(show_value_size);
    widgets.percentage_scan.set_sensitive(show_percentage);
    widgets.percentage_scan.set_visible(show_percentage);
    widgets.percentage_label.set_visible(show_percentage);
    widgets
        .percentage_value
        .set_visible(show_percentage && widgets.percentage_scan.is_active());
    widgets.percentage_value2.set_visible(
        show_percentage
            && widgets.percentage_scan.is_active()
            && comparison == ScanComparison::Between,
    );
    widgets
        .percentage_value
        .set_sensitive(widgets.percentage_scan.is_active());
    widgets.percentage_value2.set_sensitive(
        widgets.percentage_scan.is_active() && comparison == ScanComparison::Between,
    );
    widgets
        .scan_value
        .set_placeholder_text(Some(match value_type {
            ScanValueType::ByteArray => "Bytes, for example 7F 45 ?? 46",
            ScanValueType::Binary => "Bits, for example 0110??01",
            ScanValueType::String | ScanValueType::UnicodeString => "Text to find",
            ScanValueType::Grouped => "Grouped expression",
            ScanValueType::Custom => "Custom formula",
            ScanValueType::Float | ScanValueType::Double => "Floating-point value",
            _ => "Value",
        }));
}

fn set_scan_inputs_sensitive(widgets: &SessionWidgets, sensitive: bool) {
    widgets.value_type.set_sensitive(sensitive);
    widgets.comparison.set_sensitive(sensitive);
    widgets.scan_value.set_sensitive(sensitive);
    widgets.scan_value2.set_sensitive(sensitive);
    widgets.hexadecimal.set_sensitive(sensitive);
    widgets.start_address.set_sensitive(sensitive);
    widgets.stop_address.set_sensitive(sensitive);
    widgets.fast_scan.set_sensitive(sensitive);
    widgets.alignment.set_sensitive(sensitive);
    widgets.value_size.set_sensitive(sensitive);
    widgets.writable_match.set_sensitive(sensitive);
    widgets.executable_match.set_sensitive(sensitive);
    widgets.scan_private.set_sensitive(sensitive);
    widgets.scan_image.set_sensitive(sensitive);
    widgets.scan_mapped.set_sensitive(sensitive);
    widgets.rounding_type.set_sensitive(sensitive);
    widgets.float_tolerance.set_sensitive(sensitive);
    widgets.percentage_scan.set_sensitive(sensitive);
    widgets.percentage_value.set_sensitive(sensitive);
    widgets.percentage_value2.set_sensitive(sensitive);
    widgets.case_sensitive.set_sensitive(sensitive);
    widgets.string_encoding.set_sensitive(sensitive);
    if sensitive {
        update_scan_option_visibility(widgets);
    }
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
    widgets.next_scan_button.set_sensitive(false);
    widgets.undo_scan_button.set_sensitive(false);
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
    widgets.process_button.set_sensitive(true);
    widgets.session_button.set_label("Detach");
    widgets.session_button.set_sensitive(true);
    widgets.memory_view_button.set_sensitive(true);
    widgets.first_scan_button.set_sensitive(true);
    widgets.next_scan_button.set_sensitive(false);
    widgets.undo_scan_button.set_sensitive(false);
    widgets
        .scan_summary
        .set_label("Choose a value type, comparison, and scan value.");
    reload_address_list(state, widgets, true);
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
    widgets.next_scan_button.set_sensitive(false);
    widgets.undo_scan_button.set_sensitive(false);
    widgets.memory_view_button.set_sensitive(false);

    let dialog = adw::AlertDialog::builder()
        .heading("Could not attach to process")
        .body(format!("{}\n\nDiagnostic: {}", error.message, error.code))
        .build();
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}

fn detach(state: &SessionState, widgets: &SessionWidgets) {
    let result = state
        .engine
        .borrow_mut()
        .as_mut()
        .map_or(Ok(()), Engine::detach);
    if let Err(error) = result {
        widgets.session_details.set_label(&format!(
            "Could not close the session safely: {} ({})",
            error.message, error.code
        ));
        widgets.address_summary.set_label(
            "An active Auto Assembler record could not be disabled; the target remains attached.",
        );
        reload_address_list(state, widgets, false);
        return;
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
    widgets.memory_view_button.set_sensitive(false);
    reset_scan_ui(state, widgets);
    reload_address_list(state, widgets, false);
}

fn session_description(session: &Session) -> String {
    let mut lines = vec![format!(
        "{} · {}-endian · Yama ptrace_scope={}",
        session.summary, session.endianness, session.yama_scope
    )];
    lines.extend(session.notes.iter().map(|note| format!("• {note}")));
    lines.join(" · ")
}

fn start_scan(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    kind: ScanKind,
) {
    let request = match build_scan_request(widgets) {
        Ok(request) => request,
        Err(message) => {
            show_message(window, "Invalid scan options", &message);
            return;
        }
    };

    let start_result = {
        let mut engine_slot = state.engine.borrow_mut();
        let engine = engine_slot
            .as_mut()
            .expect("engine is present outside attach worker");
        match kind {
            ScanKind::First => engine.start_first_scan(&request),
            ScanKind::Next => engine.start_next_scan(&request),
        }
    };
    if let Err(error) = start_result {
        show_message(
            window,
            "Could not start scan",
            &format!("{}\n\nDiagnostic: {}", error.message, error.code),
        );
        return;
    }

    state.scanning.set(true);
    widgets.process_button.set_sensitive(false);
    widgets.session_button.set_sensitive(false);
    set_scan_inputs_sensitive(widgets, false);
    widgets.first_scan_button.set_sensitive(false);
    widgets.next_scan_button.set_sensitive(false);
    widgets.undo_scan_button.set_sensitive(false);
    widgets.cancel_scan_button.set_sensitive(true);
    widgets.cancel_scan_button.set_visible(true);
    widgets.scan_progress.set_visible(true);
    widgets.scan_summary.set_visible(true);
    widgets.scan_progress.set_fraction(0.0);
    widgets.scan_progress.set_text(Some("Scanning… 0%"));
    widgets.scan_summary.set_label(match kind {
        ScanKind::First => "Reading target memory…",
        ScanKind::Next => "Narrowing the current result set…",
    });
    reset_scan_pages(state, widgets);

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
        widgets.process_button.set_sensitive(true);
        widgets.session_button.set_sensitive(true);
        set_scan_inputs_sensitive(&widgets, true);
        widgets.first_scan_button.set_sensitive(true);
        widgets
            .next_scan_button
            .set_sensitive(status.result_available);
        widgets
            .undo_scan_button
            .set_sensitive(status.undo_available);
        widgets.cancel_scan_button.set_sensitive(false);
        widgets.cancel_scan_button.set_visible(false);

        if status.cancelled {
            widgets.scan_progress.set_text(Some("Cancelled"));
            widgets.scan_summary.set_label(if status.result_available {
                "The scan was cancelled; the previous results were preserved."
            } else {
                "The scan was cancelled."
            });
            restore_available_result(&state, &widgets, &status);
        } else if !status.error_message.is_empty() {
            widgets.scan_progress.set_text(Some("Failed"));
            widgets.scan_summary.set_label(&status.error_message);
            restore_available_result(&state, &widgets, &status);
            show_message(&window, "Scan failed", &status.error_message);
        } else if status.completed {
            widgets.scan_progress.set_fraction(1.0);
            widgets.scan_progress.set_text(Some("Complete"));
            let disk_note = if status.write_error {
                " Result storage was truncated; check available disk space."
            } else {
                ""
            };
            widgets.scan_summary.set_label(&format!(
                "Found {} addresses.{}",
                status.result_count, disk_note
            ));
            show_scan_results(&state, &widgets, status.generation, status.result_count);
        }
        adw::glib::ControlFlow::Break
    });
}

fn restore_available_result(
    state: &SessionState,
    widgets: &SessionWidgets,
    status: &crate::bridge::ScanStatus,
) {
    if status.result_available {
        show_scan_results(state, widgets, status.generation, status.result_count);
    }
}

fn undo_scan(window: &adw::ApplicationWindow, state: &SessionState, widgets: &SessionWidgets) {
    let result = state
        .engine
        .borrow_mut()
        .as_mut()
        .expect("engine is present outside attach worker")
        .undo_scan();
    match result {
        Ok(action) => {
            widgets.scan_summary.set_label(&format!(
                "Restored the previous scan with {} addresses.",
                action.result_count
            ));
            widgets.next_scan_button.set_sensitive(true);
            widgets
                .undo_scan_button
                .set_sensitive(action.undo_available);
            show_scan_results(state, widgets, action.generation, action.result_count);
        }
        Err(error) => show_message(window, "Could not undo scan", &error.message),
    }
}

fn parse_u64(text: &str, label: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} cannot be empty."));
    }
    let parsed = if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16)
    } else {
        trimmed.parse()
    };
    parsed.map_err(|_| format!("{label} must be a decimal number or start with 0x."))
}

fn parse_u32_or_zero(text: &str, label: &str) -> Result<u32, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse()
        .map_err(|_| format!("{label} must be a non-negative whole number."))
}

fn parse_f64(text: &str, label: &str) -> Result<f64, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(format!("{label} cannot be empty."));
    }
    let normalized = if trimmed.contains('.') {
        trimmed.to_owned()
    } else {
        trimmed.replace(',', ".")
    };
    normalized
        .parse()
        .map_err(|_| format!("{label} must be a valid number."))
}

fn build_scan_request(widgets: &SessionWidgets) -> Result<ScanRequest, String> {
    let value_type = ScanValueType::from_index(widgets.value_type.selected())
        .ok_or_else(|| "Select a supported value type.".to_owned())?;
    let comparison = ScanComparison::from_index(widgets.comparison.selected())
        .ok_or_else(|| "Select a supported comparison.".to_owned())?;
    let writable_match = ProtectionMatch::from_index(widgets.writable_match.selected())
        .ok_or_else(|| "Select a valid writable-memory filter.".to_owned())?;
    let executable_match = ProtectionMatch::from_index(widgets.executable_match.selected())
        .ok_or_else(|| "Select a valid executable-memory filter.".to_owned())?;
    let percentage_scan = widgets.percentage_scan.is_active();

    Ok(ScanRequest {
        value_type,
        comparison,
        value: widgets.scan_value.text().trim().to_owned(),
        value2: widgets.scan_value2.text().trim().to_owned(),
        hexadecimal: widgets.hexadecimal.is_active(),
        alignment: if widgets.fast_scan.is_active() {
            parse_u32_or_zero(&widgets.alignment.text(), "Alignment")?
        } else {
            1
        },
        start_address: parse_u64(&widgets.start_address.text(), "Start address")?,
        stop_address: parse_u64(&widgets.stop_address.text(), "Stop address")?,
        writable_match,
        executable_match,
        scan_private: widgets.scan_private.is_active(),
        scan_image: widgets.scan_image.is_active(),
        scan_mapped: widgets.scan_mapped.is_active(),
        rounding_type: widgets.rounding_type.selected() as i32,
        float_decimals: -1,
        float_tolerance: parse_f64(&widgets.float_tolerance.text(), "Float tolerance")?,
        percentage_scan,
        percentage_value: if percentage_scan {
            parse_f64(&widgets.percentage_value.text(), "Percentage")?
        } else {
            0.0
        },
        percentage_value2: if percentage_scan {
            parse_f64(&widgets.percentage_value2.text(), "Second percentage")?
        } else {
            0.0
        },
        case_sensitive: widgets.case_sensitive.is_active(),
        string_encoding: widgets.string_encoding.text().trim().to_owned(),
        value_size: parse_u32_or_zero(&widgets.value_size.text(), "Value size")?,
    })
}

fn configure_scan_result_factory(
    factory: &gtk::SignalListItemFactory,
    state: &SessionState,
    widgets: &SessionWidgets,
    window: &adw::ApplicationWindow,
) {
    factory.connect_setup({
        let state = state.clone();
        let widgets = widgets.clone();
        let window = window.clone();
        move |_, object| {
            let list_item = object
                .downcast_ref::<gtk::ListItem>()
                .expect("scan result factory receives list items");
            let address = gtk::Label::builder()
                .xalign(0.0)
                .width_chars(24)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["monospace"])
                .build();
            let value = gtk::Label::builder()
                .xalign(0.0)
                .hexpand(true)
                .ellipsize(gtk::pango::EllipsizeMode::End)
                .css_classes(["monospace"])
                .build();
            let add_button = gtk::Button::builder()
                .icon_name("list-add-symbolic")
                .tooltip_text("Add to the address list")
                .valign(Align::Center)
                .sensitive(false)
                .css_classes(["flat"])
                .build();
            let browse_button = gtk::Button::builder()
                .icon_name("document-properties-symbolic")
                .tooltip_text("Browse this memory region")
                .valign(Align::Center)
                .sensitive(false)
                .css_classes(["flat"])
                .build();
            browse_button.connect_clicked({
                let list_item = list_item.downgrade();
                let engine = state.engine.clone();
                let window = window.clone();
                move |_| {
                    let Some(list_item) = list_item.upgrade() else {
                        return;
                    };
                    let Some(item) = list_item.item().and_downcast::<adw::glib::BoxedAnyObject>()
                    else {
                        return;
                    };
                    let row = item.borrow::<VirtualScanRow>();
                    let VirtualScanRow::Loaded { address, .. } = &*row else {
                        return;
                    };
                    crate::memory_view::present(&window, engine.clone(), *address);
                }
            });
            add_button.connect_clicked({
                let list_item = list_item.downgrade();
                let state = state.clone();
                let widgets = widgets.clone();
                move |button| {
                    let Some(list_item) = list_item.upgrade() else {
                        return;
                    };
                    let Some(item) = list_item.item().and_downcast::<adw::glib::BoxedAnyObject>()
                    else {
                        return;
                    };
                    let row = item.borrow::<VirtualScanRow>();
                    let VirtualScanRow::Loaded { index, .. } = &*row else {
                        return;
                    };
                    add_virtual_scan_result(&state, &widgets, Some(button), *index);
                }
            });
            let row = gtk::Box::builder()
                .orientation(Orientation::Horizontal)
                .spacing(12)
                .margin_top(5)
                .margin_bottom(5)
                .margin_start(12)
                .margin_end(12)
                .build();
            row.append(&address);
            row.append(&value);
            row.append(&browse_button);
            row.append(&add_button);
            list_item.set_child(Some(&row));
        }
    });

    factory.connect_bind(|_, object| {
        let list_item = object
            .downcast_ref::<gtk::ListItem>()
            .expect("scan result factory receives list items");
        let row = list_item
            .child()
            .and_downcast::<gtk::Box>()
            .expect("scan result row");
        let address = row
            .first_child()
            .and_downcast::<gtk::Label>()
            .expect("scan result address");
        let value = address
            .next_sibling()
            .and_downcast::<gtk::Label>()
            .expect("scan result value");
        let browse_button = value
            .next_sibling()
            .and_downcast::<gtk::Button>()
            .expect("scan result browse button");
        let add_button = browse_button
            .next_sibling()
            .and_downcast::<gtk::Button>()
            .expect("scan result add button");
        let item = list_item
            .item()
            .and_downcast::<adw::glib::BoxedAnyObject>()
            .expect("virtual scan result item");
        value.remove_css_class("dim-label");
        value.remove_css_class("error");
        match &*item.borrow::<VirtualScanRow>() {
            VirtualScanRow::Loading { index } => {
                address.set_label(&format!("Result #{}", index + 1));
                value.set_label("Loading…");
                value.add_css_class("dim-label");
                browse_button.set_sensitive(false);
                add_button.set_sensitive(false);
            }
            VirtualScanRow::Loaded {
                address: hit_address,
                value: hit_value,
                ..
            } => {
                address.set_label(&format!("0x{hit_address:016X}"));
                value.set_label(hit_value);
                browse_button.set_sensitive(true);
                add_button.set_sensitive(true);
            }
            VirtualScanRow::Error { index, message } => {
                address.set_label(&format!("Result #{}", index + 1));
                value.set_label(message);
                value.add_css_class("error");
                browse_button.set_sensitive(false);
                add_button.set_sensitive(false);
            }
        }
    });
}

fn add_virtual_scan_result(
    state: &SessionState,
    widgets: &SessionWidgets,
    button: Option<&gtk::Button>,
    scan_index: u64,
) {
    let generation = state.scan_generation.get();
    if generation == 0 {
        if let Some(button) = button {
            button.set_sensitive(false);
        }
        widgets
            .address_summary
            .set_label("The scan results are no longer current.");
        return;
    }
    if let Some(button) = button {
        button.set_sensitive(false);
    }
    let result = {
        let mut engine_slot = state.engine.borrow_mut();
        let Some(engine) = engine_slot.as_mut() else {
            widgets
                .address_summary
                .set_label("The engine is temporarily unavailable.");
            if let Some(button) = button {
                button.set_sensitive(true);
            }
            return;
        };
        engine.add_scan_result(generation, scan_index, "No description")
    };
    match result {
        Ok(_) => {
            widgets
                .address_summary
                .set_label("The scan result was added to the address list.");
            reload_address_list(state, widgets, true);
        }
        Err(error) if error.code == "stale_scan_result" => {
            reset_scan_pages(state, widgets);
            widgets
                .scan_summary
                .set_label("Scan results changed; the stale result was discarded.");
            widgets
                .address_summary
                .set_label("The selected scan result is no longer current.");
        }
        Err(error) => {
            widgets.address_summary.set_label(&format!(
                "Could not add the result: {} ({})",
                error.message, error.code
            ));
            if let Some(button) = button {
                button.set_sensitive(true);
            }
        }
    }
}

fn show_scan_results(
    state: &SessionState,
    widgets: &SessionWidgets,
    generation: u64,
    total_count: u64,
) {
    state.scan_generation.set(generation);
    widgets.scan_empty_hint.set_visible(total_count == 0);
    let engine = Rc::downgrade(&state.engine);
    let loader: PageLoader = Rc::new(move |generation, start, limit| {
        let Some(engine) = engine.upgrade() else {
            return Err("The scan engine is no longer available.".to_owned());
        };
        let engine_slot = engine
            .try_borrow()
            .map_err(|_| "The scan engine is busy; scroll away and back to retry.".to_owned())?;
        let Some(engine) = engine_slot.as_ref() else {
            return Err("The scan engine is temporarily unavailable.".to_owned());
        };
        Ok(engine.scan_rows(generation, start, limit))
    });
    let scan_generation = state.scan_generation.clone();
    let scan_summary = widgets.scan_summary.clone();
    let page_label = widgets.page_label.clone();
    let issue_handler: IssueHandler = Rc::new(move |issue| match issue {
        ModelIssue::Page(message) => {
            scan_summary.set_label(&message);
            page_label.set_label("Some results could not be loaded");
        }
        ModelIssue::Stale(message) => {
            scan_generation.set(0);
            scan_summary.set_label(&message);
            page_label.set_label("Results changed; scan again to refresh them");
        }
    });
    widgets
        .scan_result_model
        .configure(generation, total_count, loader, issue_handler);

    if total_count == 0 {
        widgets.page_label.set_label("Found: 0");
        return;
    }
    widgets
        .page_label
        .set_label(&format!("Found: {total_count}"));
    let displayed_count = u64::from(widgets.scan_result_model.displayed_count());
    let cache_capacity = widgets.scan_result_model.cached_row_capacity();
    widgets.page_label.set_tooltip_text(Some(&format!(
        "{displayed_count} virtual rows currently exposed · pages load while scrolling · cache up to {cache_capacity} rows"
    )));
}

fn present_add_address_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
) {
    let address = gtk::Entry::builder()
        .placeholder_text("0x7FFF…")
        .hexpand(true)
        .build();
    let description = gtk::Entry::builder()
        .text("Manual entry")
        .hexpand(true)
        .build();
    let value_type = gtk::DropDown::from_strings(&ScanValueType::LABELS);
    value_type.set_selected(ScanValueType::Int32 as u32);
    value_type.set_hexpand(true);
    let byte_count = gtk::Entry::builder()
        .placeholder_text("Automatic")
        .hexpand(true)
        .build();
    let hexadecimal = gtk::CheckButton::builder()
        .label("Show integer as hexadecimal")
        .build();
    let fields = gtk::Grid::builder()
        .column_spacing(12)
        .row_spacing(9)
        .margin_top(12)
        .build();
    attach_advanced_row(&fields, 0, "Address", &address);
    attach_advanced_row(&fields, 1, "Description", &description);
    attach_advanced_row(&fields, 2, "Value type", &value_type);
    attach_advanced_row(&fields, 3, "Value size (bytes)", &byte_count);
    fields.attach(&hexadecimal, 1, 4, 1, 1);

    let dialog = adw::AlertDialog::builder()
        .heading("Add an address")
        .body("Create a live record from a raw target address.")
        .extra_child(&fields)
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("add", "Add");
    dialog.set_default_response(Some("add"));
    dialog.set_response_appearance("add", adw::ResponseAppearance::Suggested);
    dialog.connect_response(Some("add"), {
        let state = state.clone();
        let widgets = widgets.clone();
        move |_, _| {
            let parsed_address = match parse_u64(&address.text(), "Address") {
                Ok(address) => address,
                Err(message) => {
                    widgets.address_summary.set_label(&message);
                    return;
                }
            };
            let parsed_byte_count = match parse_u32_or_zero(&byte_count.text(), "Value size") {
                Ok(count) => count,
                Err(message) => {
                    widgets.address_summary.set_label(&message);
                    return;
                }
            };
            let Some(selected_type) = ScanValueType::from_index(value_type.selected()) else {
                widgets
                    .address_summary
                    .set_label("Select a supported address-list value type.");
                return;
            };
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while adding an address")
                .add_address(
                    parsed_address,
                    selected_type,
                    description.text().trim(),
                    parsed_byte_count,
                    hexadecimal.is_active(),
                );
            match result {
                Ok(_) => reload_address_list(&state, &widgets, state.attached.get()),
                Err(error) => widgets.address_summary.set_label(&format!(
                    "Could not add the address: {} ({})",
                    error.message, error.code
                )),
            }
        }
    });
    dialog.present(Some(window));
}

fn present_group_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    selected_only: bool,
) {
    let description = gtk::Entry::builder()
        .text(if selected_only {
            "Selected records"
        } else {
            "New group"
        })
        .hexpand(true)
        .build();
    let dialog = adw::AlertDialog::builder()
        .heading(if selected_only {
            "Group selected records"
        } else {
            "Create a group"
        })
        .body(if selected_only {
            "The selected records and complete child groups will be placed under a new heading."
        } else {
            "Add an empty heading to organize this cheat table."
        })
        .extra_child(&description)
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("create", "Create");
    dialog.set_default_response(Some("create"));
    dialog.set_response_appearance("create", adw::ResponseAppearance::Suggested);
    dialog.connect_response(Some("create"), {
        let state = state.clone();
        let widgets = widgets.clone();
        move |_, _| {
            let label = description.text();
            let result = {
                let mut engine_slot = state.engine.borrow_mut();
                let engine = engine_slot
                    .as_mut()
                    .expect("engine remains present while creating a group");
                if selected_only {
                    let mut ids: Vec<_> = state
                        .selected_address_ids
                        .borrow()
                        .iter()
                        .copied()
                        .collect();
                    ids.sort_unstable();
                    engine.group_addresses(&ids, label.trim())
                } else {
                    engine.add_address_group(label.trim())
                }
            };
            match result {
                Ok(_) => {
                    state.selected_address_ids.borrow_mut().clear();
                    reload_address_list(&state, &widgets, state.attached.get());
                }
                Err(error) => widgets.address_summary.set_label(&format!(
                    "Could not create the group: {} ({})",
                    error.message, error.code
                )),
            }
        }
    });
    dialog.present(Some(window));
}

fn present_open_table_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
) {
    let dialog = gtk::FileDialog::builder()
        .title("Open Cheat Table")
        .modal(true)
        .build();
    let window = window.clone();
    dialog.open(Some(&window), gtk::gio::Cancellable::NONE, {
        let state = state.clone();
        let widgets = widgets.clone();
        let window = window.clone();
        move |result| {
            let Ok(file) = result else {
                return;
            };
            let Some(path) = file.path() else {
                widgets
                    .address_summary
                    .set_label("Only local cheat-table files can be opened.");
                return;
            };
            let Some(path_text) = path.to_str() else {
                widgets
                    .address_summary
                    .set_label("This file path is not valid UTF-8 and cannot be opened yet.");
                return;
            };
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while opening a table")
                .load_table(path_text);
            match result {
                Ok(action) => complete_table_load(&window, &state, &widgets, action),
                Err(error) if error.code == "protected_table" => {
                    present_protected_table_password_dialog(&window, &state, &widgets, path, false);
                }
                Err(error) => widgets.address_summary.set_label(&format!(
                    "Could not open the cheat table: {} ({})",
                    error.message, error.code
                )),
            }
        }
    });
}

fn complete_table_load(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    action: TableAction,
) {
    state.table_scripts_trusted.set(false);
    state.table_lua_trusted.set(false);
    state
        .table_contains_auto_assembler
        .set(action.contains_auto_assembler);
    state.table_contains_lua.set(action.contains_lua);
    *state.table_compatibility_issues.borrow_mut() = action.compatibility_issues.clone();
    update_script_trust_button(state, widgets);
    update_table_compatibility_button(state, widgets);
    state.selected_address_ids.borrow_mut().clear();
    reload_address_list(state, widgets, state.attached.get());
    let script_notice = if action.contains_scripts {
        " Scripts were preserved but not executed."
    } else {
        ""
    };
    let compatibility_notice = if action.compatibility_issues.is_empty() {
        ""
    } else {
        " Review the table compatibility report for features not yet exposed by GTK."
    };
    widgets.address_summary.set_label(&format!(
        "Opened {} record{}.{}{}",
        action.record_count,
        if action.record_count == 1 { "" } else { "s" },
        script_notice,
        compatibility_notice
    ));
    if action.contains_scripts {
        present_script_trust_dialog(window, state, widgets, &action);
    }
}

fn update_table_compatibility_button(state: &SessionState, widgets: &SessionWidgets) {
    let issues = state.table_compatibility_issues.borrow();
    widgets
        .compatibility_report_button
        .set_visible(!issues.is_empty());
    if issues.is_empty() {
        return;
    }
    let losses = issues.iter().filter(|issue| !issue.preserved).count();
    if losses == 0 {
        widgets
            .compatibility_report_button
            .set_label(&format!("Compatibility ({})", issues.len()));
        widgets
            .compatibility_report_button
            .set_icon_name("dialog-information-symbolic");
        widgets.compatibility_report_button.set_tooltip_text(Some(
            "Review features preserved in the table but not yet exposed by GTK",
        ));
    } else {
        widgets
            .compatibility_report_button
            .set_label(&format!("Loss report ({losses})"));
        widgets
            .compatibility_report_button
            .set_icon_name("dialog-warning-symbolic");
        widgets
            .compatibility_report_button
            .set_tooltip_text(Some("Review known data loss for the selected table format"));
    }
}

fn present_table_compatibility_report(window: &adw::ApplicationWindow, state: &SessionState) {
    let issues = state.table_compatibility_issues.borrow().clone();
    if issues.is_empty() {
        return;
    }
    let has_loss = issues.iter().any(|issue| !issue.preserved);
    let scrolled = build_compatibility_issue_list(&issues);
    let dialog = adw::AlertDialog::builder()
        .heading(if has_loss {
            "Known table-format data loss"
        } else {
            "Table compatibility report"
        })
        .body(if has_loss {
            "Items marked with a warning are not represented by the selected format. Other listed data is retained, but its GTK feature is not available yet."
        } else {
            "No known modeled data was dropped. These features remain available for a table round trip, but their GTK tools are not available yet."
        })
        .extra_child(&scrolled)
        .build();
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}

fn build_compatibility_issue_list(issues: &[TableCompatibilityIssue]) -> gtk::ScrolledWindow {
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    for issue in issues {
        let title = if issue.count == 1 {
            issue.title.clone()
        } else {
            format!("{} ({})", issue.title, issue.count)
        };
        let row = adw::ActionRow::builder()
            .title(title)
            .subtitle(&issue.detail)
            .subtitle_lines(3)
            .build();
        row.add_prefix(
            &gtk::Image::builder()
                .icon_name(if issue.preserved {
                    "emblem-ok-symbolic"
                } else {
                    "dialog-warning-symbolic"
                })
                .tooltip_text(if issue.preserved {
                    "Preserved on round trip"
                } else {
                    "Known format loss"
                })
                .build(),
        );
        list.append(&row);
    }
    gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .max_content_height(420)
        .propagate_natural_height(true)
        .child(&list)
        .build()
}

fn present_protected_table_password_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    path: PathBuf,
    retry: bool,
) {
    let password = gtk::PasswordEntry::builder()
        .placeholder_text("Table password")
        .show_peek_icon(true)
        .hexpand(true)
        .activates_default(true)
        .build();
    let filename = path
        .file_name()
        .map_or_else(|| "this table".into(), |name| name.to_string_lossy());
    let body = if retry {
        format!(
            "The password did not unlock {filename}. Try again, or cancel to keep the current table unchanged."
        )
    } else {
        format!(
            "{filename} is password-protected. Enter its password to decrypt and inspect it locally. Scripts remain blocked after loading."
        )
    };
    let dialog = adw::AlertDialog::builder()
        .heading(if retry {
            "Could not unlock the table"
        } else {
            "Protected cheat table"
        })
        .body(body)
        .extra_child(&password)
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("open", "Unlock");
    dialog.set_default_response(Some("open"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("open", adw::ResponseAppearance::Suggested);
    dialog.connect_response(Some("open"), {
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        let password = password.clone();
        move |_, _| {
            let Some(path_text) = path.to_str() else {
                password.set_text("");
                widgets
                    .address_summary
                    .set_label("This file path is not valid UTF-8 and cannot be opened yet.");
                return;
            };
            let password_text = password.text();
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while opening a protected table")
                .load_protected_table(path_text, password_text.as_str());
            drop(password_text);
            password.set_text("");
            match result {
                Ok(action) => complete_table_load(&window, &state, &widgets, action),
                Err(error) if error.code == "protected_table_decrypt_failed" => {
                    widgets.address_summary.set_label(
                        "The protected table was not opened; the current table is unchanged.",
                    );
                    present_protected_table_password_dialog(
                        &window,
                        &state,
                        &widgets,
                        path.clone(),
                        true,
                    );
                }
                Err(error) => widgets.address_summary.set_label(&format!(
                    "Could not open the protected table: {} ({})",
                    error.message, error.code
                )),
            }
        }
    });
    dialog.present(Some(window));
    password.grab_focus();
}

fn update_script_trust_button(state: &SessionState, widgets: &SessionWidgets) {
    let has_auto_assembler = state.table_contains_auto_assembler.get();
    let has_lua = state.table_contains_lua.get();
    let has_scripts = has_auto_assembler || has_lua;
    widgets.script_trust_button.set_visible(has_scripts);
    if !has_scripts {
        return;
    }
    let auto_assembler_trusted = state.table_scripts_trusted.get();
    let lua_trusted = state.table_lua_trusted.get();
    if auto_assembler_trusted || lua_trusted {
        widgets.script_trust_button.set_label("Manage script trust");
        widgets.script_trust_button.set_tooltip_text(Some(
            "Review payloads or independently revoke Auto Assembler and Lua trust",
        ));
    } else {
        widgets.script_trust_button.set_label("Review script trust");
        widgets
            .script_trust_button
            .set_tooltip_text(Some(if has_auto_assembler {
                "Review payloads before unlocking Auto Assembler or Lua"
            } else {
                "Review Lua payloads before granting explicit execution trust"
            }));
    }
}

fn change_table_script_trust(
    state: &SessionState,
    widgets: &SessionWidgets,
    trusted: bool,
) -> bool {
    let result = state
        .engine
        .borrow_mut()
        .as_mut()
        .expect("engine remains present while changing table trust")
        .set_table_scripts_trusted(trusted);
    match result {
        Ok(()) => {
            state.table_scripts_trusted.set(trusted);
            reload_address_list(state, widgets, state.attached.get());
            widgets.address_summary.set_label(if trusted {
                "Auto Assembler is trusted for this table and runs only when a record is enabled."
            } else {
                "Auto Assembler trust was revoked and active records were disabled."
            });
            true
        }
        Err(error) => {
            reload_address_list(state, widgets, false);
            widgets.address_summary.set_label(&format!(
                "Could not {} script trust safely: {} ({})",
                if trusted { "grant" } else { "revoke" },
                error.message,
                error.code
            ));
            false
        }
    }
}

fn change_table_lua_trust(state: &SessionState, widgets: &SessionWidgets, trusted: bool) -> bool {
    let result = state
        .engine
        .borrow_mut()
        .as_mut()
        .expect("engine remains present while changing Lua trust")
        .set_table_lua_trusted(trusted);
    match result {
        Ok(()) => {
            state.table_lua_trusted.set(trusted);
            reload_address_list(state, widgets, state.attached.get());
            widgets.address_summary.set_label(if trusted {
                "Lua is trusted for this table, but each payload still requires an explicit Run confirmation."
            } else {
                "Lua trust was revoked and its runtime state was discarded. Effects already made by a script cannot be undone automatically."
            });
            true
        }
        Err(error) => {
            widgets.address_summary.set_label(&format!(
                "Could not {} Lua trust safely: {} ({})",
                if trusted { "grant" } else { "revoke" },
                error.message,
                error.code
            ));
            false
        }
    }
}

fn table_script_kind_label(kind: TableScriptKind) -> &'static str {
    match kind {
        TableScriptKind::TableLua => "Table Lua",
        TableScriptKind::AutoAssembler => "Auto Assembler",
        TableScriptKind::RecordLua => "Record Lua",
        TableScriptKind::Unknown(_) => "Unknown script",
    }
}

fn present_script_review_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
) {
    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);

    let explanation = gtk::Label::builder()
        .label(
            "Reviewing is read-only: it never executes a payload or grants trust. Lua has separate consent and every run requires confirmation.",
        )
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&list)
        .build();
    let previous = gtk::Button::builder()
        .label("Previous")
        .sensitive(false)
        .build();
    let page_label = gtk::Label::builder()
        .label("Loading scripts…")
        .hexpand(true)
        .css_classes(["dim-label"])
        .build();
    let next = gtk::Button::builder()
        .label("Next")
        .sensitive(false)
        .build();
    let navigation = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    navigation.append(&previous);
    navigation.append(&page_label);
    navigation.append(&next);

    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&explanation);
    content.append(&scrolled);
    content.append(&navigation);

    let trust_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .halign(Align::End)
        .build();
    if state.table_contains_auto_assembler.get() {
        let trusted = state.table_scripts_trusted.get();
        let trust_button = gtk::Button::builder()
            .label(if trusted {
                "Revoke Auto Assembler trust"
            } else {
                "Trust Auto Assembler"
            })
            .build();
        if !trusted {
            trust_button.add_css_class("destructive-action");
        }
        trust_button.connect_clicked({
            let state = state.clone();
            let widgets = widgets.clone();
            move |button| {
                let next = !state.table_scripts_trusted.get();
                if change_table_script_trust(&state, &widgets, next) {
                    if next {
                        button.set_label("Revoke Auto Assembler trust");
                        button.remove_css_class("destructive-action");
                    } else {
                        button.set_label("Trust Auto Assembler");
                        button.add_css_class("destructive-action");
                    }
                }
            }
        });
        trust_actions.append(&trust_button);
    }
    if state.table_contains_lua.get() {
        let trusted = state.table_lua_trusted.get();
        let trust_button = gtk::Button::builder()
            .label(if trusted {
                "Revoke Lua trust"
            } else {
                "Trust Lua execution"
            })
            .build();
        if !trusted {
            trust_button.add_css_class("destructive-action");
        }
        trust_button.connect_clicked({
            let state = state.clone();
            let widgets = widgets.clone();
            move |button| {
                let next = !state.table_lua_trusted.get();
                if change_table_lua_trust(&state, &widgets, next) {
                    if next {
                        button.set_label("Revoke Lua trust");
                        button.remove_css_class("destructive-action");
                    } else {
                        button.set_label("Trust Lua execution");
                        button.add_css_class("destructive-action");
                    }
                }
            }
        });
        trust_actions.append(&trust_button);
    }
    if state.table_contains_auto_assembler.get() || state.table_contains_lua.get() {
        content.append(&trust_actions);
    }

    toolbar.set_content(Some(&content));
    let dialog = adw::Dialog::builder()
        .title("Review table scripts")
        .content_width(760)
        .content_height(600)
        .child(&toolbar)
        .build();
    let page_start = Rc::new(Cell::new(0_u64));
    previous.connect_clicked({
        let dialog = dialog.clone();
        let state = state.clone();
        let list = list.clone();
        let page_label = page_label.clone();
        let previous = previous.clone();
        let next = next.clone();
        let page_start = page_start.clone();
        move |_| {
            let start = page_start
                .get()
                .saturating_sub(u64::from(SCRIPT_REVIEW_PAGE_SIZE));
            load_script_review_page(
                &dialog,
                &state,
                &list,
                &page_label,
                &previous,
                &next,
                &page_start,
                start,
            );
        }
    });
    next.connect_clicked({
        let dialog = dialog.clone();
        let state = state.clone();
        let list = list.clone();
        let page_label = page_label.clone();
        let previous = previous.clone();
        let next = next.clone();
        let page_start = page_start.clone();
        move |_| {
            let start = page_start
                .get()
                .saturating_add(u64::from(SCRIPT_REVIEW_PAGE_SIZE));
            load_script_review_page(
                &dialog,
                &state,
                &list,
                &page_label,
                &previous,
                &next,
                &page_start,
                start,
            );
        }
    });
    load_script_review_page(
        &dialog,
        state,
        &list,
        &page_label,
        &previous,
        &next,
        &page_start,
        0,
    );
    dialog.present(Some(window));
}

#[allow(clippy::too_many_arguments)]
fn load_script_review_page(
    dialog: &adw::Dialog,
    state: &SessionState,
    list: &gtk::ListBox,
    page_label: &gtk::Label,
    previous: &gtk::Button,
    next: &gtk::Button,
    page_start: &Cell<u64>,
    start: u64,
) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
    let page = state
        .engine
        .borrow()
        .as_ref()
        .expect("engine remains present while reviewing table scripts")
        .table_scripts(start, SCRIPT_REVIEW_PAGE_SIZE);
    page_start.set(page.start);
    previous.set_sensitive(page.start > 0);
    next.set_sensitive(page.truncated);
    if page.total_count == 0 {
        page_label.set_label("No preserved scripts");
        return;
    }
    page_label.set_label(&format!(
        "{}–{} of {}",
        page.start + 1,
        page.next_start,
        page.total_count
    ));
    for script in page.rows {
        let record = if script.record_id == 0 {
            "Table-level".to_owned()
        } else {
            format!("Record #{}", script.record_id)
        };
        let row = adw::ActionRow::builder()
            .title(&script.description)
            .subtitle(format!(
                "{record} · {} · {} bytes",
                table_script_kind_label(script.kind),
                script.byte_count
            ))
            .build();
        let view = gtk::Button::builder()
            .label("View")
            .valign(Align::Center)
            .build();
        view.connect_clicked({
            let dialog = dialog.clone();
            let state = state.clone();
            move |_| present_script_payload_dialog(&dialog, &state, &script)
        });
        row.add_suffix(&view);
        row.set_activatable_widget(Some(&view));
        list.append(&row);
    }
}

fn present_script_payload_dialog(parent: &adw::Dialog, state: &SessionState, script: &TableScript) {
    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    let notice = gtk::Label::builder()
        .label("Read-only payload. Viewing it does not execute it or change table trust.")
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    let text = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::None)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .build();
    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&text)
        .build();
    let previous = gtk::Button::builder()
        .label("Previous")
        .sensitive(false)
        .build();
    let page_label = gtk::Label::builder()
        .label("Loading payload…")
        .hexpand(true)
        .css_classes(["dim-label"])
        .build();
    let next = gtk::Button::builder()
        .label("Next")
        .sensitive(false)
        .build();
    let navigation = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    navigation.append(&previous);
    navigation.append(&page_label);
    navigation.append(&next);
    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&notice);
    let run_button = matches!(
        script.kind,
        TableScriptKind::TableLua | TableScriptKind::RecordLua
    )
    .then(|| {
        gtk::Button::builder()
            .label(if state.table_lua_trusted.get() {
                "Run this Lua payload…"
            } else {
                "Lua blocked — grant trust in the review window"
            })
            .sensitive(state.table_lua_trusted.get())
            .halign(Align::End)
            .css_classes(["destructive-action"])
            .build()
    });
    if let Some(button) = &run_button {
        content.append(button);
    }
    content.append(&scrolled);
    content.append(&navigation);
    toolbar.set_content(Some(&content));
    let dialog = adw::Dialog::builder()
        .title(format!(
            "{} — {}",
            table_script_kind_label(script.kind),
            script.description
        ))
        .content_width(820)
        .content_height(640)
        .child(&toolbar)
        .build();
    if let Some(button) = run_button {
        button.connect_clicked({
            let dialog = dialog.clone();
            let state = state.clone();
            let script = script.clone();
            move |_| present_lua_execution_confirmation(&dialog, &state, &script)
        });
    }
    let current_offset = Rc::new(Cell::new(0_u64));
    let next_offset = Rc::new(Cell::new(0_u64));
    previous.connect_clicked({
        let state = state.clone();
        let script = script.clone();
        let text = text.clone();
        let page_label = page_label.clone();
        let previous = previous.clone();
        let next = next.clone();
        let current_offset = current_offset.clone();
        let next_offset = next_offset.clone();
        move |_| {
            let offset = current_offset
                .get()
                .saturating_sub(u64::from(SCRIPT_TEXT_PAGE_SIZE));
            load_script_payload_page(
                &state,
                &script,
                &text,
                &page_label,
                &previous,
                &next,
                &current_offset,
                &next_offset,
                offset,
            );
        }
    });
    next.connect_clicked({
        let state = state.clone();
        let script = script.clone();
        let text = text.clone();
        let page_label = page_label.clone();
        let previous = previous.clone();
        let next = next.clone();
        let current_offset = current_offset.clone();
        let next_offset = next_offset.clone();
        move |_| {
            load_script_payload_page(
                &state,
                &script,
                &text,
                &page_label,
                &previous,
                &next,
                &current_offset,
                &next_offset,
                next_offset.get(),
            );
        }
    });
    load_script_payload_page(
        state,
        script,
        &text,
        &page_label,
        &previous,
        &next,
        &current_offset,
        &next_offset,
        0,
    );
    dialog.present(Some(parent));
}

fn present_lua_execution_confirmation(
    parent: &adw::Dialog,
    state: &SessionState,
    script: &TableScript,
) {
    let dialog = adw::AlertDialog::builder()
        .heading("Run this reviewed Lua payload?")
        .body(format!(
            "{} can modify the target and access your system with this application's privileges. Pure Lua bytecode is instruction-limited, but native functions may block and completed side effects cannot be undone by revoking trust.",
            table_script_kind_label(script.kind)
        ))
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("run", "Run Lua");
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("run", adw::ResponseAppearance::Destructive);
    dialog.connect_response(Some("run"), {
        let parent = parent.clone();
        let state = state.clone();
        let script = script.clone();
        move |_, _| {
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while running reviewed Lua")
                .execute_table_lua(script.record_id, script.kind);
            match result {
                Ok(execution) => present_lua_execution_result(&parent, execution),
                Err(error) => {
                    let failure = adw::AlertDialog::builder()
                        .heading("Lua was not run")
                        .body(format!("{} ({})", error.message, error.code))
                        .build();
                    failure.add_response("close", "Close");
                    failure.set_close_response("close");
                    failure.present(Some(&parent));
                }
            }
        }
    });
    dialog.present(Some(parent));
}

fn present_lua_execution_result(parent: &adw::Dialog, execution: LuaExecution) {
    let succeeded = execution.runtime_error.is_empty();
    let status = gtk::Label::builder()
        .label(if succeeded {
            "Lua payload completed."
        } else {
            "Lua payload stopped with a runtime error."
        })
        .xalign(0.0)
        .css_classes([if succeeded { "success" } else { "error" }])
        .build();
    let mut report = String::new();
    report.push_str("Payload: ");
    report.push_str(table_script_kind_label(execution.kind));
    if execution.record_id != 0 {
        report.push_str(&format!(" · record #{}", execution.record_id));
    }
    report.push_str("\n\n");
    if !execution.runtime_error.is_empty() {
        report.push_str("Runtime error:\n");
        report.push_str(&execution.runtime_error);
        report.push_str("\n\n");
    }
    report.push_str("Print output:\n");
    if execution.output.is_empty() {
        report.push_str("(No output)");
    } else {
        report.push_str(&execution.output);
    }
    if execution.output_truncated {
        report.push_str("\n\n(Output truncated at 64 KiB.)");
    }
    let text = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .build();
    text.buffer().set_text(&report);
    let scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .child(&text)
        .build();
    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&status);
    content.append(&scrolled);
    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));
    let dialog = adw::Dialog::builder()
        .title(if succeeded {
            "Lua execution output"
        } else {
            "Lua execution error"
        })
        .content_width(720)
        .content_height(480)
        .child(&toolbar)
        .build();
    dialog.present(Some(parent));
}

#[allow(clippy::too_many_arguments)]
fn load_script_payload_page(
    state: &SessionState,
    script: &TableScript,
    text: &gtk::TextView,
    page_label: &gtk::Label,
    previous: &gtk::Button,
    next: &gtk::Button,
    current_offset: &Cell<u64>,
    next_offset: &Cell<u64>,
    offset: u64,
) {
    let result = state
        .engine
        .borrow()
        .as_ref()
        .expect("engine remains present while reading a table script")
        .table_script_text(script.record_id, script.kind, offset, SCRIPT_TEXT_PAGE_SIZE);
    match result {
        Ok(page) => {
            current_offset.set(page.offset);
            next_offset.set(page.next_offset);
            previous.set_sensitive(page.offset > 0);
            next.set_sensitive(page.truncated);
            text.buffer().set_text(&page.text);
            page_label.set_label(&format!(
                "Bytes {}–{} of {}",
                page.offset.saturating_add(1),
                page.next_offset,
                page.total_bytes
            ));
        }
        Err(error) => {
            previous.set_sensitive(false);
            next.set_sensitive(false);
            text.buffer().set_text("");
            page_label.set_label(&format!(
                "Could not read this payload: {} ({})",
                error.message, error.code
            ));
        }
    }
}

fn present_script_trust_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    action: &crate::bridge::TableAction,
) {
    let contents = match (action.contains_auto_assembler, action.contains_lua) {
        (true, true) => "Auto Assembler and Lua",
        (true, false) => "Auto Assembler",
        (false, true) => "Lua",
        (false, false) => "script",
    };
    let capability = if action.contains_auto_assembler {
        "Trusting unlocks Auto Assembler record switches for this loaded table. "
    } else {
        ""
    };
    let lua_notice = if action.contains_lua {
        "Lua has separate table-scoped trust and still runs only after confirming a specific reviewed payload. Revoking trust discards runtime state but cannot undo effects of code that already ran."
    } else {
        "Scripts run only when you explicitly enable their record."
    };
    let dialog = adw::AlertDialog::builder()
        .heading("This table contains executable scripts")
        .body(format!(
            "The table contains {contents}. Scripts can modify the target and Lua can access your system with this application's privileges. Only trust tables whose source and contents you have reviewed.\n\n{capability}{lua_notice}"
        ))
        .build();
    dialog.add_response("blocked", "Keep blocked");
    dialog.add_response("review", "Review scripts");
    dialog.set_default_response(Some("blocked"));
    dialog.set_close_response("blocked");
    dialog.connect_response(Some("review"), {
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |_, _| present_script_review_dialog(&window, &state, &widgets)
    });
    if action.contains_auto_assembler {
        let trusted = state.table_scripts_trusted.get();
        let response = if trusted { "revoke-aa" } else { "trust-aa" };
        dialog.add_response(
            response,
            if trusted {
                "Revoke Auto Assembler"
            } else {
                "Trust Auto Assembler"
            },
        );
        if !trusted {
            dialog.set_response_appearance(response, adw::ResponseAppearance::Destructive);
        }
        dialog.connect_response(Some(response), {
            let state = state.clone();
            let widgets = widgets.clone();
            move |_, _| {
                change_table_script_trust(&state, &widgets, !trusted);
            }
        });
    }
    if action.contains_lua {
        let trusted = state.table_lua_trusted.get();
        let response = if trusted { "revoke-lua" } else { "trust-lua" };
        dialog.add_response(
            response,
            if trusted {
                "Revoke Lua trust"
            } else {
                "Trust Lua execution"
            },
        );
        if !trusted {
            dialog.set_response_appearance(response, adw::ResponseAppearance::Destructive);
        }
        dialog.connect_response(Some(response), {
            let state = state.clone();
            let widgets = widgets.clone();
            move |_, _| {
                change_table_lua_trust(&state, &widgets, !trusted);
            }
        });
    }
    dialog.present(Some(window));
}

fn present_save_table_dialog(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
) {
    let dialog = gtk::FileDialog::builder()
        .title("Save Cheat Table")
        .modal(true)
        .initial_name("table.CT")
        .build();
    let window = window.clone();
    dialog.save(Some(&window), gtk::gio::Cancellable::NONE, {
        let window = window.clone();
        let state = state.clone();
        let widgets = widgets.clone();
        move |result| {
            let Ok(file) = result else {
                return;
            };
            let Some(path) = file.path() else {
                widgets
                    .address_summary
                    .set_label("Only local cheat-table files can be saved.");
                return;
            };
            let Some(path_text) = path.to_str() else {
                widgets
                    .address_summary
                    .set_label("This destination path is not valid UTF-8.");
                return;
            };
            let json = path_text.to_ascii_lowercase().ends_with(".json");
            let issues = state
                .engine
                .borrow()
                .as_ref()
                .expect("engine remains present while saving a table")
                .table_compatibility_issues(json);
            if issues.iter().any(|issue| !issue.preserved) {
                present_lossy_table_save_confirmation(
                    &window, &state, &widgets, path, json, issues,
                );
            } else {
                perform_table_save(&state, &widgets, &path, json);
            }
        }
    });
}

fn present_lossy_table_save_confirmation(
    window: &adw::ApplicationWindow,
    state: &SessionState,
    widgets: &SessionWidgets,
    path: PathBuf,
    json: bool,
    issues: Vec<TableCompatibilityIssue>,
) {
    let losses = issues
        .iter()
        .filter(|issue| !issue.preserved)
        .cloned()
        .collect::<Vec<_>>();
    let scrolled = build_compatibility_issue_list(&losses);
    let dialog = adw::AlertDialog::builder()
        .heading("Save with known data loss?")
        .body(format!(
            "The selected format cannot represent every modeled feature in this table. Continuing writes {}, while the current in-memory table remains unchanged.",
            path.display()
        ))
        .extra_child(&scrolled)
        .build();
    dialog.add_response("cancel", "Cancel");
    dialog.add_response("save", "Save anyway");
    dialog.set_default_response(Some("cancel"));
    dialog.set_close_response("cancel");
    dialog.set_response_appearance("save", adw::ResponseAppearance::Destructive);
    dialog.connect_response(Some("save"), {
        let state = state.clone();
        let widgets = widgets.clone();
        move |_, _| perform_table_save(&state, &widgets, &path, json)
    });
    dialog.present(Some(window));
}

fn perform_table_save(state: &SessionState, widgets: &SessionWidgets, path: &Path, json: bool) {
    let Some(path_text) = path.to_str() else {
        widgets
            .address_summary
            .set_label("This destination path is not valid UTF-8.");
        return;
    };
    let result = state
        .engine
        .borrow()
        .as_ref()
        .expect("engine remains present while saving a table")
        .save_table(path_text, json);
    match result {
        Ok(action) => {
            let known_losses = action
                .compatibility_issues
                .iter()
                .filter(|issue| !issue.preserved)
                .count();
            *state.table_compatibility_issues.borrow_mut() = action.compatibility_issues;
            update_table_compatibility_button(state, widgets);
            widgets.address_summary.set_label(&format!(
                "Saved {} record{} to {}.{}",
                action.record_count,
                if action.record_count == 1 { "" } else { "s" },
                path.display(),
                if known_losses == 0 {
                    ""
                } else {
                    " The output has known format loss; review the loss report."
                }
            ));
        }
        Err(error) => widgets.address_summary.set_label(&format!(
            "Could not save the cheat table: {} ({})",
            error.message, error.code
        )),
    }
}

fn append_lua_console_output(state: &SessionState, message: &str) {
    if message.is_empty() {
        return;
    }
    if let Some(output) = state.lua_console_output.borrow().clone() {
        let buffer = output.buffer();
        let mut end = buffer.end_iter();
        if buffer.char_count() > 0 {
            buffer.insert(&mut end, "\n");
        }
        buffer.insert(&mut end, message);
        let excess = buffer
            .char_count()
            .saturating_sub(LUA_CONSOLE_TRANSCRIPT_LIMIT);
        if excess > 0 {
            let mut start = buffer.start_iter();
            let mut trim_end = buffer.iter_at_offset(excess);
            buffer.delete(&mut start, &mut trim_end);
        }
        let mut end = buffer.end_iter();
        output.scroll_to_iter(&mut end, 0.0, false, 0.0, 1.0);
        return;
    }

    let mut backlog = state.lua_console_backlog.borrow_mut();
    if !backlog.is_empty() {
        backlog.push('\n');
    }
    backlog.push_str(message);
    let count = backlog.chars().count();
    if count > LUA_CONSOLE_TRANSCRIPT_LIMIT as usize {
        *backlog = backlog
            .chars()
            .skip(count - LUA_CONSOLE_TRANSCRIPT_LIMIT as usize)
            .collect();
    }
}

fn execute_lua_console_command(
    state: &SessionState,
    input: &gtk::Entry,
    status: &gtk::Label,
    history_index: &Cell<usize>,
) {
    let source = input.text().to_string();
    if source.trim().is_empty() {
        return;
    }

    {
        let mut history = state.lua_console_history.borrow_mut();
        if source.len() <= LUA_CONSOLE_HISTORY_BYTES_LIMIT && history.last() != Some(&source) {
            history.push(source.clone());
            while history.len() > LUA_CONSOLE_HISTORY_LIMIT
                || history.iter().map(String::len).sum::<usize>() > LUA_CONSOLE_HISTORY_BYTES_LIMIT
            {
                history.remove(0);
            }
        }
        history_index.set(history.len());
    }
    input.set_text("");
    append_lua_console_output(state, &format!("> {source}"));

    let result = {
        let mut engine_slot = state.engine.borrow_mut();
        let Some(engine) = engine_slot.as_mut() else {
            append_lua_console_output(
                state,
                "REJECTED: the engine is busy changing process sessions",
            );
            status.set_label("Wait for the process operation to finish");
            return;
        };
        engine.execute_lua_console(&source)
    };
    match result {
        Ok(execution) => {
            state
                .lua_runtime_generation
                .set(execution.runtime_generation);
            if !execution.output.is_empty() {
                append_lua_console_output(state, &execution.output);
            }
            if execution.output_truncated {
                append_lua_console_output(state, "[Print output truncated at 64 KiB]");
            }
            if execution.runtime_error.is_empty() {
                status.set_label(&format!(
                    "Runtime generation {} · command completed",
                    execution.runtime_generation
                ));
            } else {
                append_lua_console_output(state, &format!("ERROR: {}", execution.runtime_error));
                status.set_label(&format!(
                    "Runtime generation {} · command stopped",
                    execution.runtime_generation
                ));
            }
        }
        Err(error) => {
            append_lua_console_output(
                state,
                &format!("REJECTED: {} ({})", error.message, error.code),
            );
            status.set_label("Command was not executed");
        }
    }
}

fn present_lua_console_dialog(window: &adw::ApplicationWindow, state: &SessionState) {
    if let Some(dialog) = state.lua_console_dialog.borrow().clone() {
        dialog.present(Some(window));
        return;
    }

    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    let warning = gtk::Label::builder()
        .label(
            "Commands run only when you press Run or Enter. They share the current Lua state with explicitly executed table scripts and can modify the target or access the system with this application's privileges. Pure Lua is instruction-limited; native functions may still block.",
        )
        .wrap(true)
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    let output = gtk::TextView::builder()
        .editable(false)
        .cursor_visible(false)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::WordChar)
        .top_margin(12)
        .bottom_margin(12)
        .left_margin(12)
        .right_margin(12)
        .build();
    output
        .buffer()
        .set_text(&state.lua_console_backlog.borrow());
    let output_scrolled = gtk::ScrolledWindow::builder()
        .vexpand(true)
        .hexpand(true)
        .min_content_height(300)
        .child(&output)
        .build();
    let input = gtk::Entry::builder()
        .placeholder_text("Enter Lua code; use Up/Down for history")
        .max_length(1 << 20)
        .hexpand(true)
        .build();
    let run = gtk::Button::builder()
        .label("Run")
        .tooltip_text("Execute this command in the current Lua runtime")
        .css_classes(["destructive-action"])
        .build();
    let clear = gtk::Button::builder()
        .label("Clear")
        .tooltip_text("Clear the visible console transcript")
        .build();
    let input_row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .build();
    input_row.append(&input);
    input_row.append(&run);
    input_row.append(&clear);
    let status = gtk::Label::builder()
        .label(format!(
            "Runtime generation {} · 0 timers",
            state.lua_runtime_generation.get()
        ))
        .xalign(0.0)
        .css_classes(["dim-label"])
        .build();
    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(18)
        .margin_bottom(18)
        .margin_start(18)
        .margin_end(18)
        .build();
    content.append(&warning);
    content.append(&output_scrolled);
    content.append(&input_row);
    content.append(&status);
    toolbar.set_content(Some(&content));
    let dialog = adw::Dialog::builder()
        .title("Lua Console")
        .content_width(780)
        .content_height(560)
        .child(&toolbar)
        .build();

    let history_index = Rc::new(Cell::new(state.lua_console_history.borrow().len()));
    run.connect_clicked({
        let state = state.clone();
        let input = input.clone();
        let status = status.clone();
        let history_index = history_index.clone();
        move |_| execute_lua_console_command(&state, &input, &status, &history_index)
    });
    input.connect_activate({
        let state = state.clone();
        let status = status.clone();
        let history_index = history_index.clone();
        move |input| execute_lua_console_command(&state, input, &status, &history_index)
    });
    let key_controller = gtk::EventControllerKey::new();
    key_controller.connect_key_pressed({
        let state = state.clone();
        let input = input.clone();
        let history_index = history_index.clone();
        move |_, key, _, _| match key {
            gtk::gdk::Key::Up => {
                let history = state.lua_console_history.borrow();
                if history_index.get() > 0 {
                    history_index.set(history_index.get() - 1);
                    input.set_text(&history[history_index.get()]);
                    input.set_position(-1);
                }
                adw::glib::Propagation::Stop
            }
            gtk::gdk::Key::Down => {
                let history = state.lua_console_history.borrow();
                if history_index.get() + 1 < history.len() {
                    history_index.set(history_index.get() + 1);
                    input.set_text(&history[history_index.get()]);
                    input.set_position(-1);
                } else {
                    history_index.set(history.len());
                    input.set_text("");
                }
                adw::glib::Propagation::Stop
            }
            gtk::gdk::Key::Escape => {
                history_index.set(state.lua_console_history.borrow().len());
                input.set_text("");
                adw::glib::Propagation::Stop
            }
            _ => adw::glib::Propagation::Proceed,
        }
    });
    input.add_controller(key_controller);
    clear.connect_clicked({
        let state = state.clone();
        let output = output.clone();
        move |_| {
            output.buffer().set_text("");
            state.lua_console_backlog.borrow_mut().clear();
        }
    });
    dialog.connect_closed({
        let state = state.clone();
        let output = output.clone();
        move |_| {
            let buffer = output.buffer();
            let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), true);
            *state.lua_console_backlog.borrow_mut() = text.to_string();
            *state.lua_console_output.borrow_mut() = None;
            *state.lua_console_status.borrow_mut() = None;
            *state.lua_console_dialog.borrow_mut() = None;
        }
    });
    *state.lua_console_output.borrow_mut() = Some(output);
    *state.lua_console_status.borrow_mut() = Some(status.clone());
    *state.lua_console_dialog.borrow_mut() = Some(dialog.clone());
    if std::env::var_os("CE_GTK_LUA_CONSOLE_SMOKE").is_some() {
        input.set_text(
            "print('gtk-lua-console-smoke'); smoke_timer=createTimer(1); timer_onTimer(smoke_timer, function() print('gtk-lua-timer-smoke'); object_destroy(smoke_timer) end)",
        );
        execute_lua_console_command(state, &input, &status, &history_index);
    }
    dialog.present(Some(window));
    input.grab_focus();
}

fn install_runtime_tick(state: &SessionState, widgets: &SessionWidgets) {
    let state = state.clone();
    let widgets = widgets.clone();
    adw::glib::timeout_add_local(RUNTIME_TICK_INTERVAL, move || {
        let tick = {
            let mut engine_slot = state.engine.borrow_mut();
            let Some(engine) = engine_slot.as_mut() else {
                return adw::glib::ControlFlow::Continue;
            };
            engine.periodic_tick()
        };

        if tick.runtime_generation != state.lua_runtime_generation.get() {
            state.lua_runtime_generation.set(tick.runtime_generation);
            append_lua_console_output(
                &state,
                &format!(
                    "-- Lua runtime reset to generation {}; globals, callbacks, and timers were discarded --",
                    tick.runtime_generation
                ),
            );
        }
        if !tick.output.is_empty() {
            append_lua_console_output(&state, &tick.output);
        }
        if tick.output_truncated {
            append_lua_console_output(&state, "[Timer output truncated at 64 KiB]");
        }
        if let Some(status) = state.lua_console_status.borrow().clone() {
            let mut summary = format!(
                "Runtime generation {} · {} timer{}",
                tick.runtime_generation,
                tick.timer_count,
                if tick.timer_count == 1 { "" } else { "s" }
            );
            if tick.timer_errors > 0 {
                summary.push_str(&format!(" · {} stopped with errors", tick.timer_errors));
            }
            if tick.timers_deferred > 0 {
                summary.push_str(&format!(" · {} deferred", tick.timers_deferred));
            }
            status.set_label(&summary);
        }
        if tick.address_generation != widgets.address_list_model.generation() {
            reload_address_list(&state, &widgets, state.attached.get());
        } else if state.attached.get() && tick.address_refresh_due {
            let page_starts: Vec<_> = state
                .address_visible_pages
                .borrow()
                .keys()
                .copied()
                .collect();
            let refreshed = widgets.address_list_model.refresh_pages(&page_starts);
            update_visible_address_values(&state, &refreshed);
        }
        adw::glib::ControlFlow::Continue
    });
}

fn configure_address_list_factory(
    factory: &gtk::SignalListItemFactory,
    state: &SessionState,
    widgets: &SessionWidgets,
    window: &adw::ApplicationWindow,
) {
    factory.connect_setup(|_, object| {
        let list_item = object
            .downcast_ref::<gtk::ListItem>()
            .expect("address factory receives list items");
        let slot = gtk::Box::new(Orientation::Vertical, 0);
        list_item.set_child(Some(&slot));
    });
    factory.connect_bind({
        let state = state.clone();
        let widgets = widgets.clone();
        let window = window.clone();
        move |_, object| {
            let list_item = object
                .downcast_ref::<gtk::ListItem>()
                .expect("address factory receives list items");
            let slot = list_item
                .child()
                .and_downcast::<gtk::Box>()
                .expect("address row slot");
            while let Some(child) = slot.first_child() {
                slot.remove(&child);
            }
            let item = list_item
                .item()
                .and_downcast::<adw::glib::BoxedAnyObject>()
                .expect("virtual address item");
            let virtual_row = item.borrow::<VirtualAddressRow>().clone();
            let row: gtk::Widget = match virtual_row {
                VirtualAddressRow::Loading { index } => build_address_status_row(
                    &format!("Loading address record #{}…", index + 1),
                    "Fetching this visible hierarchy page",
                )
                .upcast(),
                VirtualAddressRow::Loaded { record, .. } => {
                    build_address_record_row(&state, &widgets, &window, &record).upcast()
                }
                VirtualAddressRow::Error { index, message } => build_address_status_row(
                    &format!("Address record #{} is unavailable", index + 1),
                    &message,
                )
                .upcast(),
            };
            slot.append(&row);

            let position = list_item.position();
            if position != u32::MAX {
                let page_start = widgets.address_list_model.page_start(position);
                *state
                    .address_visible_pages
                    .borrow_mut()
                    .entry(page_start)
                    .or_default() += 1;
            }
        }
    });
    factory.connect_unbind({
        let state = state.clone();
        let widgets = widgets.clone();
        move |_, object| {
            let list_item = object
                .downcast_ref::<gtk::ListItem>()
                .expect("address factory receives list items");
            if let Some(item) = list_item.item().and_downcast::<adw::glib::BoxedAnyObject>()
                && let VirtualAddressRow::Loaded { record, .. } =
                    &*item.borrow::<VirtualAddressRow>()
            {
                state.address_value_entries.borrow_mut().remove(&record.id);
            }
            let position = list_item.position();
            if position != u32::MAX {
                let page_start = widgets.address_list_model.page_start(position);
                let mut pages = state.address_visible_pages.borrow_mut();
                if let Some(count) = pages.get_mut(&page_start) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        pages.remove(&page_start);
                    }
                }
            }
            let slot = list_item
                .child()
                .and_downcast::<gtk::Box>()
                .expect("address row slot");
            while let Some(child) = slot.first_child() {
                slot.remove(&child);
            }
        }
    });
}

fn reload_address_list(state: &SessionState, widgets: &SessionWidgets, refresh_values: bool) {
    let (metadata, scripts_trusted, lua_trusted) = {
        let mut engine_slot = state.engine.borrow_mut();
        let Some(engine) = engine_slot.as_mut() else {
            return;
        };
        (
            engine.visible_address_rows(0, 0, false),
            engine.table_scripts_trusted(),
            engine.table_lua_trusted(),
        )
    };
    state.table_scripts_trusted.set(scripts_trusted);
    state.table_lua_trusted.set(lua_trusted);
    update_script_trust_button(state, widgets);
    state.address_value_entries.borrow_mut().clear();
    state.address_visible_pages.borrow_mut().clear();

    if !metadata.error_message.is_empty() {
        widgets.address_list_model.clear();
        widgets.address_empty_hint.set_visible(true);
        widgets.address_summary.set_label(&metadata.error_message);
        return;
    }
    widgets
        .address_empty_hint
        .set_visible(metadata.raw_total_count == 0);
    let engine = Rc::downgrade(&state.engine);
    let load_live_values = refresh_values;
    let loader: AddressPageLoader = Rc::new(move |generation, start, limit, refresh| {
        let Some(engine) = engine.upgrade() else {
            return Err("The address-list engine is no longer available.".to_owned());
        };
        let mut engine_slot = engine
            .try_borrow_mut()
            .map_err(|_| "The address-list engine is busy.".to_owned())?;
        let Some(engine) = engine_slot.as_mut() else {
            return Err("The address-list engine is temporarily unavailable.".to_owned());
        };
        let page = engine.visible_address_rows(start, limit, refresh || load_live_values);
        if page.generation != generation {
            return Ok(page);
        }
        Ok(page)
    });
    let address_summary = widgets.address_summary.clone();
    let issue_handler: AddressIssueHandler = Rc::new(move |issue| match issue {
        AddressModelIssue::Page(message) => address_summary.set_label(&message),
        AddressModelIssue::Stale(message) => {
            address_summary.set_label(&format!("{message} Refreshing the list…"));
        }
    });
    widgets.address_list_model.configure(
        metadata.generation,
        metadata.total_count,
        metadata.raw_total_count,
        loader,
        issue_handler,
    );

    if metadata.raw_total_count == 0 {
        state.selected_address_ids.borrow_mut().clear();
        widgets.group_selected_button.set_sensitive(false);
        widgets
            .address_summary
            .set_label("Add a scan result to edit or freeze its live value.");
        return;
    }
    widgets
        .group_selected_button
        .set_sensitive(!state.selected_address_ids.borrow().is_empty());
    let hidden_count = metadata
        .raw_total_count
        .saturating_sub(metadata.total_count);
    let hierarchy = if hidden_count > 0 {
        format!(" · {} hidden by collapsed groups", hidden_count)
    } else {
        String::new()
    };
    let displayed_count = u64::from(widgets.address_list_model.displayed_count());
    let gtk_limit = if metadata.total_count > displayed_count {
        format!(" · GTK exposes the first {displayed_count}")
    } else {
        String::new()
    };
    widgets.address_summary.set_label(&format!(
        "{} record{} · {} visible{}{} · cache up to {} rows{}",
        metadata.raw_total_count,
        if metadata.raw_total_count == 1 {
            ""
        } else {
            "s"
        },
        widgets.address_list_model.total_count(),
        hierarchy,
        gtk_limit,
        widgets.address_list_model.cached_row_capacity(),
        if state.attached.get() {
            " · live values refresh automatically"
        } else {
            " · attach to refresh values"
        }
    ));
}

fn build_address_status_row(title: &str, detail: &str) -> gtk::Box {
    let title = gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .build();
    let detail = gtk::Label::builder()
        .label(detail)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .css_classes(["dim-label"])
        .build();
    let row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .build();
    row.append(&title);
    row.append(&detail);
    row
}

fn build_address_record_row(
    state: &SessionState,
    widgets: &SessionWidgets,
    window: &adw::ApplicationWindow,
    record: &AddressRecord,
) -> gtk::Box {
    let indent = "\u{00a0}\u{00a0}".repeat(record.indent.max(0) as usize);
    let scripts_trusted = state.table_scripts_trusted.get();
    let lua_trusted = state.table_lua_trusted.get();
    let address = if record.is_group {
        "Group".to_owned()
    } else if record.has_auto_assembler && record.has_lua {
        match (scripts_trusted, lua_trusted) {
            (true, true) => "Auto Assembler trusted; Lua runnable from review".to_owned(),
            (true, false) => "Auto Assembler trusted; Lua blocked".to_owned(),
            (false, true) => "Auto Assembler blocked; Lua runnable from review".to_owned(),
            (false, false) => "Auto Assembler and Lua preserved; execution blocked".to_owned(),
        }
    } else if record.has_auto_assembler {
        if scripts_trusted {
            "Auto Assembler trusted; enable explicitly".to_owned()
        } else {
            "Auto Assembler preserved; execution blocked".to_owned()
        }
    } else if record.has_lua {
        if lua_trusted {
            "Lua trusted; run explicitly from script review".to_owned()
        } else {
            "Lua preserved; execution blocked".to_owned()
        }
    } else if record.address_expression.is_empty() {
        format!("0x{:016X}", record.address)
    } else {
        format!("{} → 0x{:016X}", record.address_expression, record.address)
    };
    let subtitle = if record.error_message.is_empty() {
        format!("{address} · {}", record.type_name)
    } else {
        format!(
            "{address} · {} · {}",
            record.type_name, record.error_message
        )
    };
    let description = gtk::Label::builder()
        .label(format!("{indent}{}", record.description))
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .tooltip_text(&record.description)
        .build();
    let address_details = gtk::Label::builder()
        .label(&subtitle)
        .xalign(0.0)
        .width_chars(28)
        .max_width_chars(36)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .tooltip_text(&subtitle)
        .css_classes(["monospace", "caption"])
        .build();

    let selected = gtk::CheckButton::builder()
        .active(state.selected_address_ids.borrow().contains(&record.id))
        .tooltip_text("Select for grouping")
        .valign(Align::Center)
        .build();
    selected.connect_toggled({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |button| {
            if button.is_active() {
                state.selected_address_ids.borrow_mut().insert(id);
            } else {
                state.selected_address_ids.borrow_mut().remove(&id);
            }
            widgets
                .group_selected_button
                .set_sensitive(!state.selected_address_ids.borrow().is_empty());
        }
    });
    let collapse = if record.is_group {
        let collapse = gtk::Button::builder()
            .icon_name(if record.collapsed {
                "pan-end-symbolic"
            } else {
                "pan-down-symbolic"
            })
            .tooltip_text(if record.collapsed {
                "Expand group"
            } else {
                "Collapse group"
            })
            .valign(Align::Center)
            .css_classes(["flat"])
            .build();
        collapse.connect_clicked({
            let state = state.clone();
            let widgets = widgets.clone();
            let id = record.id;
            let collapsed = record.collapsed;
            move |_| {
                let result = state
                    .engine
                    .borrow_mut()
                    .as_mut()
                    .expect("engine remains present while collapsing a group")
                    .set_address_collapsed(id, !collapsed);
                match result {
                    Ok(()) => reload_address_list(&state, &widgets, false),
                    Err(error) => widgets.address_summary.set_label(&format!(
                        "Could not change the group: {} ({})",
                        error.message, error.code
                    )),
                }
            }
        });
        Some(collapse)
    } else {
        None
    };

    let value_entry = gtk::Entry::builder()
        .text(&record.value)
        .placeholder_text("Value")
        .width_chars(12)
        .max_width_chars(22)
        .valign(Align::Center)
        .sensitive(state.attached.get() && !record.is_group && !record.has_script)
        .css_classes(["monospace"])
        .build();
    if !record.readable {
        value_entry.add_css_class("error");
    }
    if !record.error_message.is_empty() {
        value_entry.set_tooltip_text(Some(&record.error_message));
    }
    value_entry.connect_activate({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |entry| {
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while editing an address")
                .set_address_value(id, &entry.text());
            match result {
                Ok(()) => {
                    state.selected_address_ids.borrow_mut().clear();
                    widgets.group_selected_button.set_sensitive(false);
                    reload_address_list(&state, &widgets, true);
                }
                Err(error) => {
                    widgets.address_summary.set_label(&format!(
                        "Could not write the value: {} ({})",
                        error.message, error.code
                    ));
                    entry.add_css_class("error");
                    entry.set_tooltip_text(Some(&error.message));
                }
            }
        }
    });

    let freeze_mode = gtk::DropDown::from_strings(&FreezeMode::LABELS);
    freeze_mode.set_selected(record.freeze_mode as u32);
    freeze_mode.set_tooltip_text(Some("Freeze mode"));
    freeze_mode.set_valign(Align::Center);
    freeze_mode.set_sensitive(state.attached.get() && !record.is_group && !record.has_script);
    freeze_mode.connect_selected_notify({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |dropdown| {
            let Some(mode) = FreezeMode::from_index(dropdown.selected()) else {
                return;
            };
            if let Err(error) = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while changing a freeze mode")
                .set_address_freeze_mode(id, mode)
            {
                widgets.address_summary.set_label(&format!(
                    "Could not change the freeze mode: {} ({})",
                    error.message, error.code
                ));
            }
        }
    });

    let can_toggle = state.attached.get()
        && !record.is_group
        && (!record.has_script || (record.has_auto_assembler && scripts_trusted));
    let freeze_tooltip = if record.has_auto_assembler {
        if scripts_trusted {
            "Enable or disable this trusted Auto Assembler record"
        } else {
            "Trust this table before enabling Auto Assembler"
        }
    } else if record.has_lua {
        "Lua record execution is not available yet"
    } else {
        "Freeze this value"
    };
    let freeze = gtk::CheckButton::builder()
        .active(record.active)
        .tooltip_text(freeze_tooltip)
        .valign(Align::Center)
        .sensitive(can_toggle)
        .build();
    freeze.connect_toggled({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        let is_script = record.has_script;
        move |button| {
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while freezing an address")
                .set_address_active(id, button.is_active());
            match result {
                Ok(()) if is_script => {
                    reload_address_list(&state, &widgets, false);
                    widgets.address_summary.set_label(if button.is_active() {
                        "The trusted Auto Assembler record is enabled."
                    } else {
                        "The Auto Assembler record is disabled."
                    });
                }
                Ok(()) => {}
                Err(error) => {
                    widgets.address_summary.set_label(&format!(
                        "Could not change the record state: {} ({})",
                        error.message, error.code
                    ));
                    reload_address_list(&state, &widgets, true);
                }
            }
        }
    });

    let delete = gtk::Button::builder()
        .icon_name("user-trash-symbolic")
        .tooltip_text("Remove from the address list")
        .valign(Align::Center)
        .css_classes(["flat"])
        .build();
    delete.connect_clicked({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |_| {
            let result = state
                .engine
                .borrow_mut()
                .as_mut()
                .expect("engine remains present while deleting an address")
                .delete_address(id);
            match result {
                Ok(()) => reload_address_list(&state, &widgets, true),
                Err(error) => {
                    reload_address_list(&state, &widgets, false);
                    widgets.address_summary.set_label(&format!(
                        "Could not remove the record: {} ({})",
                        error.message, error.code
                    ));
                }
            }
        }
    });

    let browse = gtk::Button::builder()
        .icon_name("document-properties-symbolic")
        .tooltip_text("Browse this address in Memory View")
        .valign(Align::Center)
        .sensitive(state.attached.get() && !record.is_group && !record.has_script)
        .css_classes(["flat"])
        .build();
    browse.connect_clicked({
        let engine = state.engine.clone();
        let window = window.clone();
        let address = record.address;
        move |_| crate::memory_view::present(&window, engine.clone(), address)
    });

    let move_up = gtk::Button::builder()
        .icon_name("go-up-symbolic")
        .tooltip_text("Move up")
        .valign(Align::Center)
        .css_classes(["flat"])
        .build();
    move_up.connect_clicked({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |_| move_address_record(&state, &widgets, id, -1)
    });
    let move_down = gtk::Button::builder()
        .icon_name("go-down-symbolic")
        .tooltip_text("Move down")
        .valign(Align::Center)
        .css_classes(["flat"])
        .build();
    move_down.connect_clicked({
        let state = state.clone();
        let widgets = widgets.clone();
        let id = record.id;
        move |_| move_address_record(&state, &widgets, id, 1)
    });
    let move_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(0)
        .valign(Align::Center)
        .build();
    move_actions.append(&move_up);
    move_actions.append(&move_down);

    selected.set_size_request(38, -1);
    freeze.set_size_request(44, -1);
    if record.is_group {
        freeze.set_opacity(0.0);
        freeze.set_can_target(false);
    }

    let description_cell = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(2)
        .hexpand(true)
        .build();
    if let Some(collapse) = collapse {
        description_cell.append(&collapse);
    } else {
        let indent_spacer = gtk::Box::new(Orientation::Horizontal, 0);
        indent_spacer.set_size_request(34, -1);
        description_cell.append(&indent_spacer);
    }
    description_cell.append(&description);

    let value_cell: gtk::Widget = if record.is_group {
        let empty_value = gtk::Label::builder().label("").width_chars(12).build();
        empty_value.upcast()
    } else {
        value_entry.clone().upcast()
    };

    let action_cell = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(2)
        .valign(Align::Center)
        .build();
    if !record.is_group {
        action_cell.append(&freeze_mode);
        action_cell.append(&browse);
        state
            .address_value_entries
            .borrow_mut()
            .insert(record.id, value_entry.clone());
    }
    action_cell.append(&move_actions);
    action_cell.append(&delete);

    let row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(12)
        .margin_end(12)
        .build();
    row.append(&selected);
    row.append(&freeze);
    row.append(&description_cell);
    row.append(&address_details);
    row.append(&value_cell);
    row.append(&action_cell);
    row
}

fn move_address_record(state: &SessionState, widgets: &SessionWidgets, id: i32, direction: i32) {
    let result = state
        .engine
        .borrow_mut()
        .as_mut()
        .expect("engine remains present while moving an address")
        .move_address(id, direction);
    match result {
        Ok(()) => reload_address_list(state, widgets, state.attached.get()),
        Err(error) if error.code == "move_boundary" => {
            widgets.address_summary.set_label(&error.message);
        }
        Err(error) => widgets.address_summary.set_label(&format!(
            "Could not move the record: {} ({})",
            error.message, error.code
        )),
    }
}

fn update_visible_address_values(state: &SessionState, records: &[AddressRecord]) {
    let entries = state.address_value_entries.borrow();
    for record in records {
        if record.is_group {
            continue;
        }
        let Some(entry) = entries.get(&record.id) else {
            continue;
        };
        if !entry.has_focus() {
            entry.set_text(&record.value);
        }
        if record.readable {
            entry.remove_css_class("error");
            entry.set_tooltip_text(None);
        } else {
            entry.add_css_class("error");
            entry.set_tooltip_text(Some(&record.error_message));
        }
    }
}

fn reset_scan_ui(state: &SessionState, widgets: &SessionWidgets) {
    state.scanning.set(false);
    set_scan_inputs_sensitive(widgets, true);
    widgets.first_scan_button.set_sensitive(false);
    widgets.next_scan_button.set_sensitive(false);
    widgets.undo_scan_button.set_sensitive(false);
    widgets.cancel_scan_button.set_sensitive(false);
    widgets.cancel_scan_button.set_visible(false);
    widgets.scan_progress.set_fraction(0.0);
    widgets.scan_progress.set_text(Some("Ready"));
    widgets.scan_progress.set_visible(false);
    widgets
        .scan_summary
        .set_label("Attach to a process to begin scanning memory.");
    widgets.scan_summary.set_visible(false);
    reset_scan_pages(state, widgets);
}

fn reset_scan_pages(state: &SessionState, widgets: &SessionWidgets) {
    state.scan_generation.set(0);
    widgets.scan_result_model.clear();
    widgets.scan_empty_hint.set_visible(true);
    widgets.page_label.set_label("Found: 0");
    widgets.page_label.set_tooltip_text(None);
}

fn show_message(window: &adw::ApplicationWindow, heading: &str, body: &str) {
    let dialog = adw::AlertDialog::builder()
        .heading(heading)
        .body(body)
        .build();
    dialog.add_response("close", "Close");
    dialog.present(Some(window));
}

fn add_main_action<F>(group: &gtk::gio::SimpleActionGroup, name: &str, callback: F)
where
    F: Fn() + 'static,
{
    let action = gtk::gio::SimpleAction::new(name, None);
    action.connect_activate(move |_, _| callback());
    group.add_action(&action);
}

fn add_main_button_action(group: &gtk::gio::SimpleActionGroup, name: &str, button: &gtk::Button) {
    let action = gtk::gio::SimpleAction::new(name, None);
    action.set_enabled(button.is_sensitive());
    action.connect_activate({
        let button = button.clone();
        move |_, _| button.emit_clicked()
    });
    button.connect_sensitive_notify({
        let action = action.clone();
        move |button| action.set_enabled(button.is_sensitive())
    });
    group.add_action(&action);
}
