use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use adw::prelude::*;
use gtk::{Align, Orientation};

use crate::bridge::{DisassemblyRow, Engine, MemoryView, ScanValueType};

const PAGE_BYTES: u32 = 512;
const INSTRUCTION_LIMIT: u32 = 128;
static MEMORY_VIEW_SMOKE_OK: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct Viewer {
    engine: Rc<RefCell<Option<Engine>>>,
    address_entry: gtk::Entry,
    back_button: gtk::Button,
    forward_button: gtk::Button,
    bookmark_button: gtk::Button,
    bookmarks_box: gtk::Box,
    status: gtk::Label,
    instruction_status: gtk::Label,
    data_inspector: gtk::Label,
    follow_button: gtk::Button,
    copy_button: gtk::Button,
    add_button: gtk::Button,
    disassembly: gtk::ListBox,
    hex_buffer: gtk::TextBuffer,
    current_address: Rc<Cell<u64>>,
    next_address: Rc<Cell<u64>>,
    instructions: Rc<RefCell<Vec<DisassemblyRow>>>,
    bytes: Rc<RefCell<Vec<u8>>>,
    selected_instruction: Rc<Cell<Option<usize>>>,
    back_stack: Rc<RefCell<Vec<u64>>>,
    forward_stack: Rc<RefCell<Vec<u64>>>,
    bookmarks: Rc<RefCell<BTreeSet<u64>>>,
}

impl Viewer {
    fn load(&self, requested_address: u64) -> bool {
        self.status.remove_css_class("error");
        self.status.set_label("Reading process memory…");

        let result = {
            let engine_slot = self.engine.borrow();
            let Some(engine) = engine_slot.as_ref() else {
                self.show_error("The memory engine is temporarily busy.");
                return false;
            };
            engine.memory_view(requested_address, PAGE_BYTES, INSTRUCTION_LIMIT)
        };

        match result {
            Ok(view) => {
                self.show_view(view);
                true
            }
            Err(error) => {
                self.show_error(&format!("{} ({})", error.message, error.code));
                false
            }
        }
    }

    fn navigate(&self, requested_address: u64) {
        let previous = self.current_address.get();
        if self.load(requested_address) {
            let current = self.current_address.get();
            if previous != 0 && previous != current {
                self.back_stack.borrow_mut().push(previous);
                self.forward_stack.borrow_mut().clear();
            }
            self.update_navigation();
        }
    }

    fn go_back(&self) {
        let Some(target) = self.back_stack.borrow_mut().pop() else {
            return;
        };
        let current = self.current_address.get();
        if self.load(target) {
            if current != 0 {
                self.forward_stack.borrow_mut().push(current);
            }
        } else {
            self.back_stack.borrow_mut().push(target);
        }
        self.update_navigation();
    }

    fn go_forward(&self) {
        let Some(target) = self.forward_stack.borrow_mut().pop() else {
            return;
        };
        let current = self.current_address.get();
        if self.load(target) {
            if current != 0 {
                self.back_stack.borrow_mut().push(current);
            }
        } else {
            self.forward_stack.borrow_mut().push(target);
        }
        self.update_navigation();
    }

    fn show_view(&self, view: MemoryView) {
        clear_list(&self.disassembly);
        for instruction in &view.instructions {
            self.disassembly.append(&disassembly_row(
                instruction.address,
                &instruction.bytes,
                &instruction.mnemonic,
                &instruction.operands,
            ));
        }

        *self.instructions.borrow_mut() = view.instructions;
        *self.bytes.borrow_mut() = view.bytes;
        self.hex_buffer
            .set_text(&format_hex_dump(view.address, &self.bytes.borrow()));
        self.address_entry
            .set_text(&format!("0x{:016X}", view.address));
        self.current_address.set(view.address);
        self.next_address.set(view.next_address);
        self.status.set_label(&format!(
            "{} · {} bytes · {} instructions · {}",
            view.arch,
            self.bytes.borrow().len(),
            self.instructions.borrow().len(),
            view.region
        ));
        self.selected_instruction.set(None);
        self.instruction_status
            .set_label("Select an instruction; activate it to follow its operand.");
        self.follow_button.set_sensitive(false);
        self.copy_button.set_sensitive(false);
        self.add_button.set_sensitive(false);
        if let Some(row) = self.disassembly.row_at_index(0) {
            self.disassembly.select_row(Some(&row));
        }
        if !self.bytes.borrow().is_empty() {
            if let Some(iter) = self.hex_buffer.iter_at_line_offset(0, 18) {
                self.hex_buffer.place_cursor(&iter);
            }
            self.inspect_hex_cursor();
        } else {
            self.data_inspector.set_label("No readable bytes.");
        }
        self.update_navigation();
        self.update_bookmark_button();

        if std::env::var_os("CE_GTK_MEMORY_VIEW_SMOKE").is_some()
            && !self.bytes.borrow().is_empty()
            && !self.instructions.borrow().is_empty()
            && self.selected_instruction.get().is_some()
            && self.copy_button.is_sensitive()
            && self.data_inspector.label().contains("byte=0x")
        {
            MEMORY_VIEW_SMOKE_OK.store(true, Ordering::SeqCst);
        }
    }

    fn update_navigation(&self) {
        self.back_button
            .set_sensitive(!self.back_stack.borrow().is_empty());
        self.forward_button
            .set_sensitive(!self.forward_stack.borrow().is_empty());
    }

    fn select_instruction(&self, index: Option<usize>) {
        self.selected_instruction.set(index);
        let instructions = self.instructions.borrow();
        let Some(instruction) = index.and_then(|index| instructions.get(index)) else {
            self.instruction_status
                .set_label("Select an instruction; activate it to follow its operand.");
            self.follow_button.set_sensitive(false);
            self.copy_button.set_sensitive(false);
            self.add_button.set_sensitive(false);
            return;
        };
        let text = instruction_text(instruction);
        let follow = if instruction.follow_target == 0 {
            String::new()
        } else {
            format!(" · target 0x{:016X}", instruction.follow_target)
        };
        self.instruction_status.set_label(&format!(
            "0x{:016X} · {} byte{} · {text}{follow}",
            instruction.address,
            instruction.size,
            if instruction.size == 1 { "" } else { "s" }
        ));
        self.follow_button
            .set_sensitive(instruction.follow_target != 0);
        self.copy_button.set_sensitive(true);
        self.add_button.set_sensitive(true);
    }

    fn follow_selected(&self) {
        let target = self
            .selected_instruction
            .get()
            .and_then(|index| self.instructions.borrow().get(index).cloned())
            .map_or(0, |instruction| instruction.follow_target);
        if target == 0 {
            self.instruction_status
                .set_label("The selected instruction has no direct target to follow.");
            return;
        }
        self.navigate(target);
    }

    fn copy_selected(&self) {
        let Some(instruction) = self
            .selected_instruction
            .get()
            .and_then(|index| self.instructions.borrow().get(index).cloned())
        else {
            return;
        };
        let line = format!(
            "0x{:016X} - {} - {}",
            instruction.address,
            instruction.bytes,
            instruction_text(&instruction)
        );
        if let Some(display) = gtk::gdk::Display::default() {
            display.clipboard().set_text(&line);
            self.instruction_status
                .set_label("The selected instruction was copied to the clipboard.");
        }
    }

    fn add_selected_address(&self) {
        let Some(instruction) = self
            .selected_instruction
            .get()
            .and_then(|index| self.instructions.borrow().get(index).cloned())
        else {
            return;
        };
        let result = {
            let mut engine_slot = self.engine.borrow_mut();
            let Some(engine) = engine_slot.as_mut() else {
                self.instruction_status
                    .set_label("The memory engine is temporarily busy.");
                return;
            };
            engine.add_address(
                instruction.address,
                ScanValueType::Int32,
                &format!("Memory View 0x{:016X}", instruction.address),
                0,
                false,
            )
        };
        match result {
            Ok(_) => self
                .instruction_status
                .set_label("Address added to the table as a 4-byte value."),
            Err(error) => self.instruction_status.set_label(&format!(
                "Could not add the address: {} ({})",
                error.message, error.code
            )),
        }
    }

    fn inspect_hex_cursor(&self) {
        let mark = self.hex_buffer.get_insert();
        let iter = self.hex_buffer.iter_at_mark(&mark);
        let Some(offset) = byte_offset_for_text_position(
            iter.line() as usize,
            iter.line_offset() as usize,
            self.bytes.borrow().len(),
        ) else {
            return;
        };
        self.data_inspector.set_label(&format_data_inspector(
            self.current_address.get(),
            &self.bytes.borrow(),
            offset,
        ));
    }

    fn toggle_bookmark(&self) {
        let address = self.current_address.get();
        if address == 0 {
            return;
        }
        let mut bookmarks = self.bookmarks.borrow_mut();
        if !bookmarks.insert(address) {
            bookmarks.remove(&address);
        }
        drop(bookmarks);
        self.rebuild_bookmarks();
        self.update_bookmark_button();
    }

    fn update_bookmark_button(&self) {
        let bookmarked = self
            .bookmarks
            .borrow()
            .contains(&self.current_address.get());
        self.bookmark_button.set_icon_name(if bookmarked {
            "starred-symbolic"
        } else {
            "non-starred-symbolic"
        });
        self.bookmark_button.set_tooltip_text(Some(if bookmarked {
            "Remove bookmark (Ctrl+B)"
        } else {
            "Bookmark this address (Ctrl+B)"
        }));
    }

    fn rebuild_bookmarks(&self) {
        while let Some(child) = self.bookmarks_box.first_child() {
            self.bookmarks_box.remove(&child);
        }
        let bookmarks: Vec<_> = self.bookmarks.borrow().iter().copied().collect();
        if bookmarks.is_empty() {
            self.bookmarks_box.append(
                &gtk::Label::builder()
                    .label("No bookmarks yet")
                    .margin_top(12)
                    .margin_bottom(12)
                    .margin_start(16)
                    .margin_end(16)
                    .css_classes(["dim-label"])
                    .build(),
            );
            return;
        }
        for address in bookmarks {
            let button = gtk::Button::builder()
                .label(format!("0x{address:016X}"))
                .halign(Align::Fill)
                .css_classes(["flat", "monospace"])
                .build();
            button.connect_clicked({
                let viewer = self.clone();
                move |_| viewer.navigate(address)
            });
            self.bookmarks_box.append(&button);
        }
    }

    fn show_error(&self, message: &str) {
        clear_list(&self.disassembly);
        self.instructions.borrow_mut().clear();
        self.bytes.borrow_mut().clear();
        self.hex_buffer.set_text("");
        self.selected_instruction.set(None);
        self.follow_button.set_sensitive(false);
        self.copy_button.set_sensitive(false);
        self.add_button.set_sensitive(false);
        self.instruction_status
            .set_label("No instruction selected.");
        self.data_inspector.set_label("No readable bytes.");
        self.status.add_css_class("error");
        self.status.set_label(message);
    }
}

pub fn smoke_ok() -> bool {
    MEMORY_VIEW_SMOKE_OK.load(Ordering::SeqCst)
}

pub fn present(
    parent: &adw::ApplicationWindow,
    engine: Rc<RefCell<Option<Engine>>>,
    initial_address: u64,
) {
    let header = adw::HeaderBar::new();
    let title = adw::WindowTitle::builder()
        .title("Memory View")
        .subtitle("Disassembler and hex dump")
        .build();
    header.set_title_widget(Some(&title));

    let back_button = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text("Back (Alt+Left)")
        .sensitive(false)
        .build();
    let forward_button = gtk::Button::builder()
        .icon_name("go-next-symbolic")
        .tooltip_text("Forward (Alt+Right)")
        .sensitive(false)
        .build();
    let address_entry = gtk::Entry::builder()
        .placeholder_text("Address in hexadecimal")
        .text(format!("0x{initial_address:016X}"))
        .hexpand(true)
        .css_classes(["monospace"])
        .build();
    let go_button = gtk::Button::builder()
        .label("Go")
        .icon_name("go-jump-symbolic")
        .css_classes(["suggested-action"])
        .build();
    let refresh_button = gtk::Button::builder()
        .icon_name("view-refresh-symbolic")
        .tooltip_text("Refresh this memory page")
        .build();
    let previous_page_button = gtk::Button::builder()
        .label("−512")
        .tooltip_text("Previous memory page (Page Up)")
        .build();
    let next_page_button = gtk::Button::builder()
        .label("+512")
        .tooltip_text("Next memory page (Page Down)")
        .build();
    let bookmark_button = gtk::Button::builder()
        .icon_name("non-starred-symbolic")
        .tooltip_text("Bookmark this address (Ctrl+B)")
        .build();
    let bookmarks_box = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(2)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(6)
        .margin_end(6)
        .build();
    let bookmarks_popover = gtk::Popover::builder().child(&bookmarks_box).build();
    let bookmarks_menu = gtk::MenuButton::builder()
        .icon_name("view-list-symbolic")
        .tooltip_text("Open bookmarks")
        .popover(&bookmarks_popover)
        .build();

    let navigation = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    navigation.append(&back_button);
    navigation.append(&forward_button);
    navigation.append(&address_entry);
    navigation.append(&go_button);
    navigation.append(&refresh_button);
    navigation.append(&gtk::Separator::new(Orientation::Vertical));
    navigation.append(&previous_page_button);
    navigation.append(&next_page_button);
    navigation.append(&bookmark_button);
    navigation.append(&bookmarks_menu);

    let disassembly_header = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(6)
        .margin_bottom(6)
        .margin_start(12)
        .margin_end(12)
        .css_classes(["dim-label"])
        .build();
    disassembly_header.append(&column_header("Address", 20, false));
    disassembly_header.append(&column_header("Bytes", 32, false));
    let instruction_header = column_header("Instruction", 24, true);
    disassembly_header.append(&instruction_header);

    let disassembly = gtk::ListBox::new();
    disassembly.set_selection_mode(gtk::SelectionMode::Single);
    disassembly.add_css_class("boxed-list");
    let disassembly_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .child(&disassembly)
        .build();
    let instruction_status = gtk::Label::builder()
        .label("Select an instruction; activate it to follow its operand.")
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .selectable(true)
        .css_classes(["caption", "dim-label", "monospace"])
        .build();
    let follow_button = gtk::Button::builder()
        .label("Follow")
        .icon_name("go-jump-symbolic")
        .tooltip_text("Follow the selected branch or memory operand (Enter)")
        .sensitive(false)
        .css_classes(["flat"])
        .build();
    let copy_button = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text("Copy selected instruction (Ctrl+C)")
        .sensitive(false)
        .css_classes(["flat"])
        .build();
    let add_button = gtk::Button::builder()
        .icon_name("list-add-symbolic")
        .tooltip_text("Add this instruction address to the table")
        .sensitive(false)
        .css_classes(["flat"])
        .build();
    let instruction_actions = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(12)
        .margin_end(6)
        .build();
    instruction_actions.append(&instruction_status);
    instruction_actions.append(&follow_button);
    instruction_actions.append(&copy_button);
    instruction_actions.append(&add_button);
    let disassembly_panel = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .build();
    disassembly_panel.append(&disassembly_header);
    disassembly_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    disassembly_panel.append(&disassembly_scrolled);
    disassembly_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    disassembly_panel.append(&instruction_actions);
    let disassembly_frame = gtk::Frame::builder()
        .label("Disassembler")
        .child(&disassembly_panel)
        .build();

    let hex_buffer = gtk::TextBuffer::new(None);
    let hex_view = gtk::TextView::builder()
        .buffer(&hex_buffer)
        .editable(false)
        .cursor_visible(true)
        .monospace(true)
        .wrap_mode(gtk::WrapMode::None)
        .top_margin(8)
        .bottom_margin(8)
        .left_margin(12)
        .right_margin(12)
        .build();
    let hex_scrolled = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Automatic)
        .vexpand(true)
        .child(&hex_view)
        .build();
    let data_inspector = gtk::Label::builder()
        .label("Select a byte to inspect its value.")
        .xalign(0.0)
        .selectable(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .css_classes(["caption", "dim-label", "monospace"])
        .margin_top(5)
        .margin_bottom(5)
        .margin_start(12)
        .margin_end(12)
        .build();
    let hex_panel = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .build();
    hex_panel.append(&hex_scrolled);
    hex_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    hex_panel.append(&data_inspector);
    let hex_frame = gtk::Frame::builder()
        .label("Hex dump")
        .child(&hex_panel)
        .build();

    let panes = gtk::Paned::new(Orientation::Vertical);
    panes.set_wide_handle(true);
    panes.set_start_child(Some(&disassembly_frame));
    panes.set_end_child(Some(&hex_frame));
    panes.set_resize_start_child(true);
    panes.set_resize_end_child(true);
    panes.set_shrink_start_child(false);
    panes.set_shrink_end_child(false);
    panes.set_position(390);

    let status = gtk::Label::builder()
        .label("Attach to a process and enter an address.")
        .xalign(0.0)
        .ellipsize(gtk::pango::EllipsizeMode::Middle)
        .selectable(true)
        .css_classes(["dim-label"])
        .margin_top(6)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();

    let content = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .margin_start(8)
        .margin_end(8)
        .build();
    content.append(&navigation);
    content.append(&panes);
    content.append(&status);

    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    toolbar.set_content(Some(&content));
    let window = adw::Window::builder()
        .title("Memory View")
        .transient_for(parent)
        .modal(false)
        .default_width(980)
        .default_height(720)
        .content(&toolbar)
        .build();

    let viewer = Viewer {
        engine,
        address_entry: address_entry.clone(),
        back_button: back_button.clone(),
        forward_button: forward_button.clone(),
        bookmark_button: bookmark_button.clone(),
        bookmarks_box,
        status,
        instruction_status,
        data_inspector,
        follow_button: follow_button.clone(),
        copy_button: copy_button.clone(),
        add_button: add_button.clone(),
        disassembly: disassembly.clone(),
        hex_buffer: hex_buffer.clone(),
        current_address: Rc::new(Cell::new(initial_address)),
        next_address: Rc::new(Cell::new(initial_address)),
        instructions: Rc::new(RefCell::new(Vec::new())),
        bytes: Rc::new(RefCell::new(Vec::new())),
        selected_instruction: Rc::new(Cell::new(None)),
        back_stack: Rc::new(RefCell::new(Vec::new())),
        forward_stack: Rc::new(RefCell::new(Vec::new())),
        bookmarks: Rc::new(RefCell::new(BTreeSet::new())),
    };
    viewer.rebuild_bookmarks();

    let navigate_to_entry = {
        let viewer = viewer.clone();
        move || match parse_address(&viewer.address_entry.text()) {
            Ok(address) => viewer.navigate(address),
            Err(message) => viewer.show_error(&message),
        }
    };
    address_entry.connect_activate({
        let navigate_to_entry = navigate_to_entry.clone();
        move |_| navigate_to_entry()
    });
    go_button.connect_clicked({
        let navigate_to_entry = navigate_to_entry.clone();
        move |_| navigate_to_entry()
    });
    refresh_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| {
            viewer.load(viewer.current_address.get());
        }
    });
    back_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.go_back()
    });
    forward_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.go_forward()
    });
    previous_page_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| {
            viewer.navigate(
                viewer
                    .current_address
                    .get()
                    .saturating_sub(u64::from(PAGE_BYTES)),
            )
        }
    });
    next_page_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.navigate(viewer.next_address.get())
    });
    bookmark_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.toggle_bookmark()
    });
    disassembly.connect_row_selected({
        let viewer = viewer.clone();
        move |_, row| viewer.select_instruction(row.map(|row| row.index() as usize))
    });
    disassembly.connect_row_activated({
        let viewer = viewer.clone();
        move |_, row| {
            viewer.select_instruction(Some(row.index() as usize));
            viewer.follow_selected();
        }
    });
    follow_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.follow_selected()
    });
    copy_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.copy_selected()
    });
    add_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.add_selected_address()
    });
    hex_buffer.connect_cursor_position_notify({
        let viewer = viewer.clone();
        move |_| viewer.inspect_hex_cursor()
    });

    let key_controller = gtk::EventControllerKey::new();
    key_controller.connect_key_pressed({
        let viewer = viewer.clone();
        move |_, key, _, modifiers| {
            let alt = modifiers.contains(gtk::gdk::ModifierType::ALT_MASK);
            let control = modifiers.contains(gtk::gdk::ModifierType::CONTROL_MASK);
            match key {
                gtk::gdk::Key::Left if alt => {
                    viewer.go_back();
                    adw::glib::Propagation::Stop
                }
                gtk::gdk::Key::Right if alt => {
                    viewer.go_forward();
                    adw::glib::Propagation::Stop
                }
                gtk::gdk::Key::Page_Up => {
                    viewer.navigate(
                        viewer
                            .current_address
                            .get()
                            .saturating_sub(u64::from(PAGE_BYTES)),
                    );
                    adw::glib::Propagation::Stop
                }
                gtk::gdk::Key::Page_Down => {
                    viewer.navigate(viewer.next_address.get());
                    adw::glib::Propagation::Stop
                }
                gtk::gdk::Key::b | gtk::gdk::Key::B if control => {
                    viewer.toggle_bookmark();
                    adw::glib::Propagation::Stop
                }
                gtk::gdk::Key::c | gtk::gdk::Key::C if control => {
                    viewer.copy_selected();
                    adw::glib::Propagation::Stop
                }
                _ => adw::glib::Propagation::Proceed,
            }
        }
    });
    window.add_controller(key_controller);

    window.present();
    viewer.load(initial_address);
}

fn parse_address(text: &str) -> Result<u64, String> {
    let trimmed = text.trim();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if digits.is_empty() {
        return Err("Enter a hexadecimal address.".to_owned());
    }
    u64::from_str_radix(digits, 16)
        .map_err(|_| "The address must contain hexadecimal digits (0–9, A–F).".to_owned())
}

fn clear_list(list: &gtk::ListBox) {
    while let Some(child) = list.first_child() {
        list.remove(&child);
    }
}

fn column_header(title: &str, width_chars: i32, expand: bool) -> gtk::Label {
    gtk::Label::builder()
        .label(title)
        .xalign(0.0)
        .width_chars(width_chars)
        .hexpand(expand)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .css_classes(["caption", "heading", "monospace"])
        .build()
}

fn disassembly_row(address: u64, bytes: &str, mnemonic: &str, operands: &str) -> gtk::Box {
    let address = gtk::Label::builder()
        .label(format!("0x{address:016X}"))
        .xalign(0.0)
        .width_chars(20)
        .css_classes(["monospace"])
        .build();
    let bytes = gtk::Label::builder()
        .label(bytes)
        .xalign(0.0)
        .width_chars(32)
        .max_width_chars(32)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .tooltip_text(bytes)
        .css_classes(["monospace", "dim-label"])
        .build();
    let instruction_text = if operands.is_empty() {
        mnemonic.to_owned()
    } else {
        format!("{mnemonic} {operands}")
    };
    let instruction = gtk::Label::builder()
        .label(&instruction_text)
        .xalign(0.0)
        .hexpand(true)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .tooltip_text(&instruction_text)
        .css_classes(["monospace"])
        .build();
    let row = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(12)
        .margin_top(4)
        .margin_bottom(4)
        .margin_start(12)
        .margin_end(12)
        .valign(Align::Center)
        .build();
    row.append(&address);
    row.append(&bytes);
    row.append(&instruction);
    row
}

fn instruction_text(instruction: &DisassemblyRow) -> String {
    if instruction.operands.is_empty() {
        instruction.mnemonic.clone()
    } else {
        format!("{} {}", instruction.mnemonic, instruction.operands)
    }
}

fn byte_offset_for_text_position(line: usize, column: usize, byte_len: usize) -> Option<usize> {
    let byte_in_line = if (18..=66).contains(&column) {
        if column == 42 {
            return None;
        }
        let adjusted = if column >= 43 { column - 1 } else { column };
        let relative = adjusted.saturating_sub(18);
        if relative % 3 == 2 {
            return None;
        }
        relative / 3
    } else if (70..=85).contains(&column) {
        column - 70
    } else {
        return None;
    };
    if byte_in_line >= 16 {
        return None;
    }
    let offset = line.checked_mul(16)?.checked_add(byte_in_line)?;
    (offset < byte_len).then_some(offset)
}

fn format_data_inspector(base: u64, bytes: &[u8], offset: usize) -> String {
    let Some(byte) = bytes.get(offset) else {
        return "Select a byte to inspect its value.".to_owned();
    };
    let address = base.saturating_add(offset as u64);
    let remaining = &bytes[offset..];
    let mut result = format!(
        "0x{address:016X} · byte=0x{byte:02X} · i8={} · u8={byte}",
        *byte as i8
    );
    if remaining.len() >= 2 {
        let raw: [u8; 2] = remaining[..2].try_into().expect("two-byte slice");
        let _ = write!(
            result,
            " · i16={} · u16={}",
            i16::from_le_bytes(raw),
            u16::from_le_bytes(raw)
        );
    }
    if remaining.len() >= 4 {
        let raw: [u8; 4] = remaining[..4].try_into().expect("four-byte slice");
        let _ = write!(
            result,
            " · i32={} · u32={} · float={:.7}",
            i32::from_le_bytes(raw),
            u32::from_le_bytes(raw),
            f32::from_le_bytes(raw)
        );
    }
    if remaining.len() >= 8 {
        let raw: [u8; 8] = remaining[..8].try_into().expect("eight-byte slice");
        let _ = write!(
            result,
            " · i64={} · u64={} · double={:.10}",
            i64::from_le_bytes(raw),
            u64::from_le_bytes(raw),
            f64::from_le_bytes(raw)
        );
    }
    result
}

fn format_hex_dump(address: u64, bytes: &[u8]) -> String {
    let mut dump = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let line_address = address.saturating_add((line * 16) as u64);
        let _ = write!(dump, "{line_address:016X}  ");
        for index in 0..16 {
            if let Some(byte) = chunk.get(index) {
                let _ = write!(dump, "{byte:02X} ");
            } else {
                dump.push_str("   ");
            }
            if index == 7 {
                dump.push(' ');
            }
        }
        dump.push_str(" | ");
        for byte in chunk {
            dump.push(if (0x20..=0x7e).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            });
        }
        dump.push('\n');
    }
    dump
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cheat_engine_style_hex_addresses() {
        assert_eq!(parse_address("7ff0").unwrap(), 0x7ff0);
        assert_eq!(parse_address("0xABCD").unwrap(), 0xabcd);
        assert!(parse_address("not-an-address").is_err());
    }

    #[test]
    fn formats_hex_and_ascii_columns() {
        let dump = format_hex_dump(0x1000, b"Hello\0world");
        assert!(dump.contains("0000000000001000"));
        assert!(dump.contains("48 65 6C 6C 6F 00 77 6F"));
        assert!(dump.contains("Hello.world"));
    }

    #[test]
    fn maps_hex_and_ascii_cursor_columns_to_the_same_byte() {
        assert_eq!(byte_offset_for_text_position(0, 18, 32), Some(0));
        assert_eq!(byte_offset_for_text_position(0, 39, 32), Some(7));
        assert_eq!(byte_offset_for_text_position(0, 42, 32), None);
        assert_eq!(byte_offset_for_text_position(0, 43, 32), Some(8));
        assert_eq!(byte_offset_for_text_position(1, 70, 32), Some(16));
        assert_eq!(byte_offset_for_text_position(1, 85, 32), Some(31));
        assert_eq!(byte_offset_for_text_position(2, 70, 32), None);
    }

    #[test]
    fn formats_scalar_values_from_the_selected_byte() {
        let bytes = [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0];
        let inspector = format_data_inspector(0x1000, &bytes, 0);
        assert!(inspector.contains("0x0000000000001000"));
        assert!(inspector.contains("byte=0x78"));
        assert!(inspector.contains("u16=22136"));
        assert!(inspector.contains("i32=305419896"));
    }
}
