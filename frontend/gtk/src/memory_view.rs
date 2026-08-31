use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use adw::prelude::*;
use gtk::{Align, Orientation};

use crate::bridge::{Engine, MemoryView};

const PAGE_BYTES: u32 = 512;
const INSTRUCTION_LIMIT: u32 = 128;
static MEMORY_VIEW_SMOKE_OK: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct Viewer {
    engine: Rc<RefCell<Option<Engine>>>,
    address_entry: gtk::Entry,
    previous_button: gtk::Button,
    next_button: gtk::Button,
    status: gtk::Label,
    disassembly: gtk::ListBox,
    hex_buffer: gtk::TextBuffer,
    current_address: Rc<Cell<u64>>,
    next_address: Rc<Cell<u64>>,
}

impl Viewer {
    fn load(&self, requested_address: u64) {
        self.status.remove_css_class("error");
        self.status.set_label("Reading process memory…");

        let result = {
            let engine_slot = self.engine.borrow();
            let Some(engine) = engine_slot.as_ref() else {
                self.show_error("The memory engine is temporarily busy.");
                return;
            };
            engine.memory_view(requested_address, PAGE_BYTES, INSTRUCTION_LIMIT)
        };

        match result {
            Ok(view) => self.show_view(view),
            Err(error) => self.show_error(&format!("{} ({})", error.message, error.code)),
        }
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

        self.hex_buffer
            .set_text(&format_hex_dump(view.address, &view.bytes));
        self.address_entry
            .set_text(&format!("0x{:016X}", view.address));
        self.current_address.set(view.address);
        self.next_address.set(view.next_address);
        self.previous_button
            .set_sensitive(view.address >= u64::from(PAGE_BYTES));
        self.next_button
            .set_sensitive(view.next_address > view.address);
        self.status.set_label(&format!(
            "{} · {} bytes · {} instructions · {}",
            view.arch,
            view.bytes.len(),
            view.instructions.len(),
            view.region
        ));

        if std::env::var_os("CE_GTK_MEMORY_VIEW_SMOKE").is_some()
            && !view.bytes.is_empty()
            && !view.instructions.is_empty()
        {
            MEMORY_VIEW_SMOKE_OK.store(true, Ordering::SeqCst);
        }
    }

    fn show_error(&self, message: &str) {
        clear_list(&self.disassembly);
        self.hex_buffer.set_text("");
        self.previous_button.set_sensitive(false);
        self.next_button.set_sensitive(false);
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

    let previous_button = gtk::Button::builder()
        .icon_name("go-previous-symbolic")
        .tooltip_text("Previous 512-byte page")
        .sensitive(false)
        .build();
    let next_button = gtk::Button::builder()
        .icon_name("go-next-symbolic")
        .tooltip_text("Next 512-byte page")
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

    let navigation = gtk::Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .margin_top(8)
        .margin_bottom(8)
        .margin_start(8)
        .margin_end(8)
        .build();
    navigation.append(&previous_button);
    navigation.append(&next_button);
    navigation.append(&address_entry);
    navigation.append(&go_button);
    navigation.append(&refresh_button);

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
    let disassembly_panel = gtk::Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(0)
        .build();
    disassembly_panel.append(&disassembly_header);
    disassembly_panel.append(&gtk::Separator::new(Orientation::Horizontal));
    disassembly_panel.append(&disassembly_scrolled);
    let disassembly_frame = gtk::Frame::builder()
        .label("Disassembler")
        .child(&disassembly_panel)
        .build();

    let hex_buffer = gtk::TextBuffer::new(None);
    let hex_view = gtk::TextView::builder()
        .buffer(&hex_buffer)
        .editable(false)
        .cursor_visible(false)
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
    let hex_frame = gtk::Frame::builder()
        .label("Hex dump")
        .child(&hex_scrolled)
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
        previous_button: previous_button.clone(),
        next_button: next_button.clone(),
        status,
        disassembly,
        hex_buffer,
        current_address: Rc::new(Cell::new(initial_address)),
        next_address: Rc::new(Cell::new(initial_address)),
    };

    let navigate_to_entry = {
        let viewer = viewer.clone();
        move || match parse_address(&viewer.address_entry.text()) {
            Ok(address) => viewer.load(address),
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
        move |_| viewer.load(viewer.current_address.get())
    });
    previous_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| {
            viewer.load(
                viewer
                    .current_address
                    .get()
                    .saturating_sub(u64::from(PAGE_BYTES)),
            )
        }
    });
    next_button.connect_clicked({
        let viewer = viewer.clone();
        move |_| viewer.load(viewer.next_address.get())
    });

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
        .selectable(true)
        .css_classes(["monospace"])
        .build();
    let bytes = gtk::Label::builder()
        .label(bytes)
        .xalign(0.0)
        .width_chars(32)
        .max_width_chars(32)
        .ellipsize(gtk::pango::EllipsizeMode::End)
        .tooltip_text(bytes)
        .selectable(true)
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
        .selectable(true)
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
}
