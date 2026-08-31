use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use gtk::gio;
use gtk::gio::subclass::prelude::*;
use gtk::glib;
use gtk::prelude::*;

use crate::bridge::{AddressPage, AddressRecord};

pub const MAX_ADDRESS_PAGE_SIZE: u32 = 256;
pub const DEFAULT_ADDRESS_CACHE_PAGES: usize = 8;

pub type PageLoader = Rc<dyn Fn(u64, u64, u32, bool) -> Result<AddressPage, String>>;
pub type IssueHandler = Rc<dyn Fn(ModelIssue)>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelIssue {
    Page(String),
    Stale(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VirtualAddressRow {
    Loading { index: u64 },
    Loaded { index: u64, record: AddressRecord },
    Error { index: u64, message: String },
}

struct CachedPage(Vec<glib::BoxedAnyObject>);

struct PageCache {
    max_pages: usize,
    pages: HashMap<u64, CachedPage>,
    lru: VecDeque<u64>,
}

impl PageCache {
    fn new(max_pages: usize) -> Self {
        Self {
            max_pages: max_pages.max(1),
            pages: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    fn clear(&mut self) {
        self.pages.clear();
        self.lru.clear();
    }

    fn contains(&self, page_start: u64) -> bool {
        self.pages.contains_key(&page_start)
    }

    fn item(&mut self, page_start: u64, offset: usize) -> Option<glib::BoxedAnyObject> {
        let item = self.pages.get(&page_start)?.0.get(offset).cloned();
        if item.is_some() {
            self.touch(page_start);
        }
        item
    }

    fn page_items(&mut self, page_start: u64) -> Option<Vec<glib::BoxedAnyObject>> {
        let items = self.pages.get(&page_start)?.0.clone();
        self.touch(page_start);
        Some(items)
    }

    fn insert(&mut self, page_start: u64, page: CachedPage) -> Vec<u64> {
        self.pages.insert(page_start, page);
        self.touch(page_start);
        let mut evicted = Vec::new();
        while self.pages.len() > self.max_pages {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if oldest != page_start && self.pages.remove(&oldest).is_some() {
                evicted.push(oldest);
            }
        }
        evicted
    }

    fn touch(&mut self, page_start: u64) {
        if let Some(position) = self.lru.iter().position(|start| *start == page_start) {
            self.lru.remove(position);
        }
        self.lru.push_back(page_start);
    }
}

mod imp {
    use super::*;

    pub struct AddressListModel {
        pub generation: Cell<u64>,
        pub total_count: Cell<u64>,
        pub raw_total_count: Cell<u64>,
        pub visible_count: Cell<u32>,
        pub page_size: Cell<u32>,
        pub cache_pages: Cell<usize>,
        pub(super) cache: RefCell<PageCache>,
        pub pending: RefCell<HashMap<(u64, u64), Vec<glib::BoxedAnyObject>>>,
        pub loader: RefCell<Option<PageLoader>>,
        pub issue_handler: RefCell<Option<IssueHandler>>,
    }

    impl Default for AddressListModel {
        fn default() -> Self {
            Self {
                generation: Cell::new(0),
                total_count: Cell::new(0),
                raw_total_count: Cell::new(0),
                visible_count: Cell::new(0),
                page_size: Cell::new(MAX_ADDRESS_PAGE_SIZE),
                cache_pages: Cell::new(DEFAULT_ADDRESS_CACHE_PAGES),
                cache: RefCell::new(PageCache::new(DEFAULT_ADDRESS_CACHE_PAGES)),
                pending: RefCell::new(HashMap::new()),
                loader: RefCell::new(None),
                issue_handler: RefCell::new(None),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AddressListModel {
        const NAME: &'static str = "CeGtkAddressListModel";
        type Type = super::AddressListModel;
        type Interfaces = (gio::ListModel,);
    }

    impl ObjectImpl for AddressListModel {}

    impl ListModelImpl for AddressListModel {
        fn item_type(&self) -> glib::Type {
            glib::BoxedAnyObject::static_type()
        }

        fn n_items(&self) -> u32 {
            self.visible_count.get()
        }

        fn item(&self, position: u32) -> Option<glib::Object> {
            if position >= self.visible_count.get() {
                return None;
            }
            let page_size = self.page_size.get();
            let page_start = u64::from((position / page_size) * page_size);
            let offset = (position % page_size) as usize;
            if let Some(item) = self.cache.borrow_mut().item(page_start, offset) {
                return Some(item.upcast());
            }

            let pending_key = (self.generation.get(), page_start);
            let mut pending = self.pending.borrow_mut();
            let schedule_load = !pending.contains_key(&pending_key);
            let items = pending.entry(pending_key).or_insert_with(|| {
                let visible_count = u64::from(self.visible_count.get());
                let count = u64::from(page_size).min(visible_count - page_start);
                (0..count)
                    .map(|offset| {
                        glib::BoxedAnyObject::new(VirtualAddressRow::Loading {
                            index: page_start + offset,
                        })
                    })
                    .collect()
            });
            let item = items
                .get(offset)
                .cloned()
                .expect("visible address position belongs to its pending page");
            drop(pending);
            if schedule_load {
                let model = self.obj().clone();
                let generation = self.generation.get();
                glib::idle_add_local_once(move || model.load_page(generation, page_start));
            }
            Some(item.upcast())
        }
    }
}

glib::wrapper! {
    pub struct AddressListModel(ObjectSubclass<imp::AddressListModel>)
        @implements gio::ListModel;
}

enum RefreshUpdate {
    Updated,
    Replace,
    Stale,
}

impl AddressListModel {
    pub fn new(page_size: u32, cache_pages: usize) -> Self {
        let model: Self = glib::Object::new();
        let imp = model.imp();
        imp.page_size.set(page_size.clamp(1, MAX_ADDRESS_PAGE_SIZE));
        imp.cache_pages.set(cache_pages.max(1));
        *imp.cache.borrow_mut() = PageCache::new(cache_pages);
        model
    }

    pub fn configure(
        &self,
        generation: u64,
        total_count: u64,
        raw_total_count: u64,
        loader: PageLoader,
        issue_handler: IssueHandler,
    ) {
        let imp = self.imp();
        let old_count = imp.visible_count.get();
        let visible_count = total_count.min(u64::from(u32::MAX)) as u32;
        imp.generation.set(generation);
        imp.total_count.set(total_count);
        imp.raw_total_count.set(raw_total_count);
        imp.visible_count.set(visible_count);
        imp.pending.borrow_mut().clear();
        imp.cache.borrow_mut().clear();
        *imp.loader.borrow_mut() = Some(loader);
        *imp.issue_handler.borrow_mut() = Some(issue_handler);
        if old_count > 0 || visible_count > 0 {
            self.items_changed(0, old_count, visible_count);
        }
    }

    pub fn clear(&self) {
        let imp = self.imp();
        let old_count = imp.visible_count.replace(0);
        imp.generation.set(0);
        imp.total_count.set(0);
        imp.raw_total_count.set(0);
        imp.pending.borrow_mut().clear();
        imp.cache.borrow_mut().clear();
        imp.loader.borrow_mut().take();
        imp.issue_handler.borrow_mut().take();
        if old_count > 0 {
            self.items_changed(0, old_count, 0);
        }
    }

    pub fn generation(&self) -> u64 {
        self.imp().generation.get()
    }

    pub fn total_count(&self) -> u64 {
        self.imp().total_count.get()
    }

    pub fn raw_total_count(&self) -> u64 {
        self.imp().raw_total_count.get()
    }

    pub fn displayed_count(&self) -> u32 {
        self.imp().visible_count.get()
    }

    pub fn cached_row_capacity(&self) -> u64 {
        u64::from(self.imp().page_size.get()) * self.imp().cache_pages.get() as u64
    }

    pub fn page_start(&self, position: u32) -> u64 {
        let page_size = self.imp().page_size.get();
        u64::from((position / page_size) * page_size)
    }

    pub fn is_loaded(&self, position: u32) -> bool {
        if position >= self.imp().visible_count.get() {
            return false;
        }
        let page_size = self.imp().page_size.get();
        let page_start = u64::from((position / page_size) * page_size);
        let offset = (position % page_size) as usize;
        let Some(item) = self.imp().cache.borrow_mut().item(page_start, offset) else {
            return false;
        };
        matches!(
            &*item.borrow::<VirtualAddressRow>(),
            VirtualAddressRow::Loaded { .. }
        )
    }

    pub fn refresh_pages(&self, page_starts: &[u64]) -> Vec<AddressRecord> {
        let imp = self.imp();
        let generation = imp.generation.get();
        let Some(loader) = imp.loader.borrow().clone() else {
            return Vec::new();
        };
        let page_size = imp.page_size.get();
        let mut starts = page_starts.to_vec();
        starts.sort_unstable();
        starts.dedup();
        let mut refreshed = Vec::new();

        for page_start in starts {
            if imp.generation.get() != generation || !imp.cache.borrow().contains(page_start) {
                continue;
            }
            let result = loader(generation, page_start, page_size, true);
            if imp.generation.get() != generation {
                break;
            }
            let rows = match result {
                Ok(page) => match self.validate_page(generation, page_start, page_size, page) {
                    Ok(rows) => rows,
                    Err(ModelIssue::Page(message)) => {
                        self.report_issue(ModelIssue::Page(message));
                        continue;
                    }
                    Err(issue @ ModelIssue::Stale(_)) => {
                        self.invalidate(issue);
                        break;
                    }
                },
                Err(message) => {
                    self.report_issue(ModelIssue::Page(message));
                    continue;
                }
            };

            match self.update_page_in_place(page_start, &rows) {
                RefreshUpdate::Updated => refreshed.extend(rows),
                RefreshUpdate::Replace => {
                    self.insert_loaded_page(page_start, rows.clone());
                    refreshed.extend(rows);
                }
                RefreshUpdate::Stale => {
                    self.invalidate(ModelIssue::Stale(
                        "The visible address hierarchy changed without a new generation."
                            .to_owned(),
                    ));
                    break;
                }
            }
        }
        refreshed
    }

    fn load_page(&self, expected_generation: u64, page_start: u64) {
        let imp = self.imp();
        if imp.generation.get() != expected_generation || expected_generation == 0 {
            imp.pending
                .borrow_mut()
                .remove(&(expected_generation, page_start));
            return;
        }
        let Some(loader) = imp.loader.borrow().clone() else {
            imp.pending
                .borrow_mut()
                .remove(&(expected_generation, page_start));
            return;
        };
        let page_size = imp.page_size.get();
        let result = loader(expected_generation, page_start, page_size, false);
        if imp.generation.get() != expected_generation {
            imp.pending
                .borrow_mut()
                .remove(&(expected_generation, page_start));
            return;
        }
        imp.pending
            .borrow_mut()
            .remove(&(expected_generation, page_start));

        match result {
            Ok(page) => {
                match self.validate_page(expected_generation, page_start, page_size, page) {
                    Ok(rows) => self.insert_loaded_page(page_start, rows),
                    Err(ModelIssue::Page(message)) => self.cache_page_error(page_start, message),
                    Err(issue @ ModelIssue::Stale(_)) => self.invalidate(issue),
                }
            }
            Err(message) => self.cache_page_error(page_start, message),
        }
    }

    fn validate_page(
        &self,
        expected_generation: u64,
        page_start: u64,
        page_size: u32,
        page: AddressPage,
    ) -> Result<Vec<AddressRecord>, ModelIssue> {
        let imp = self.imp();
        if page.generation != expected_generation {
            return Err(ModelIssue::Stale(
                "The address list changed while a visible page was loading.".to_owned(),
            ));
        }
        if !page.error_message.is_empty() {
            return Err(ModelIssue::Page(page.error_message));
        }
        if page.start != page_start
            || page.total_count != imp.total_count.get()
            || page.raw_total_count != imp.raw_total_count.get()
        {
            return Err(ModelIssue::Stale(
                "The address-list generation changed its paging contract.".to_owned(),
            ));
        }
        let expected_end = page_start
            .saturating_add(u64::from(page_size))
            .min(page.total_count);
        if page_start.saturating_add(page.rows.len() as u64) != expected_end {
            return Err(ModelIssue::Page(
                "The engine returned an unexpected address-list page length.".to_owned(),
            ));
        }
        Ok(page.rows)
    }

    fn insert_loaded_page(&self, page_start: u64, rows: Vec<AddressRecord>) {
        let items = rows
            .into_iter()
            .enumerate()
            .map(|(offset, record)| {
                glib::BoxedAnyObject::new(VirtualAddressRow::Loaded {
                    index: page_start + offset as u64,
                    record,
                })
            })
            .collect();
        self.insert_page(page_start, CachedPage(items));
    }

    fn update_page_in_place(&self, page_start: u64, rows: &[AddressRecord]) -> RefreshUpdate {
        let Some(items) = self.imp().cache.borrow_mut().page_items(page_start) else {
            return RefreshUpdate::Replace;
        };
        if items.len() != rows.len() {
            return RefreshUpdate::Stale;
        }
        let mut replace = false;
        for (item, record) in items.iter().zip(rows) {
            let mut current = item.borrow_mut::<VirtualAddressRow>();
            match &mut *current {
                VirtualAddressRow::Loaded {
                    record: current_record,
                    ..
                } if current_record.id == record.id => *current_record = record.clone(),
                VirtualAddressRow::Error { .. } => replace = true,
                _ => return RefreshUpdate::Stale,
            }
        }
        if replace {
            RefreshUpdate::Replace
        } else {
            RefreshUpdate::Updated
        }
    }

    fn cache_page_error(&self, page_start: u64, message: String) {
        let imp = self.imp();
        let visible_count = u64::from(imp.visible_count.get());
        let count = if page_start < visible_count {
            u64::from(imp.page_size.get()).min(visible_count - page_start)
        } else {
            0
        };
        let items = (0..count)
            .map(|offset| {
                glib::BoxedAnyObject::new(VirtualAddressRow::Error {
                    index: page_start + offset,
                    message: message.clone(),
                })
            })
            .collect();
        self.insert_page(page_start, CachedPage(items));
        self.report_issue(ModelIssue::Page(message));
    }

    fn insert_page(&self, page_start: u64, page: CachedPage) {
        let imp = self.imp();
        let evicted = imp.cache.borrow_mut().insert(page_start, page);
        self.notify_page(page_start);
        for evicted_start in evicted {
            self.notify_page(evicted_start);
        }
    }

    fn notify_page(&self, page_start: u64) {
        let imp = self.imp();
        let visible_count = u64::from(imp.visible_count.get());
        if page_start >= visible_count {
            return;
        }
        let count = u64::from(imp.page_size.get()).min(visible_count - page_start) as u32;
        self.items_changed(page_start as u32, count, count);
    }

    fn report_issue(&self, issue: ModelIssue) {
        if let Some(handler) = self.imp().issue_handler.borrow().clone() {
            handler(issue);
        }
    }

    fn invalidate(&self, issue: ModelIssue) {
        let handler = self.imp().issue_handler.borrow().clone();
        self.clear();
        if let Some(handler) = handler {
            handler(issue);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{FreezeMode, ScanValueType};

    fn record(id: i32, value: &str) -> AddressRecord {
        AddressRecord {
            id,
            description: format!("Record {id}"),
            address: 0x1000 + id as u64,
            address_expression: String::new(),
            value_type: ScanValueType::Int32,
            type_name: "4 Bytes".to_owned(),
            value: value.to_owned(),
            error_message: String::new(),
            readable: true,
            active: false,
            freeze_mode: FreezeMode::Normal,
            show_as_hex: false,
            byte_count: 4,
            is_group: false,
            collapsed: false,
            has_script: false,
            has_auto_assembler: false,
            has_lua: false,
            indent: 0,
        }
    }

    fn page(
        generation: u64,
        start: u64,
        total: u64,
        raw_total: u64,
        rows: Vec<AddressRecord>,
    ) -> AddressPage {
        AddressPage {
            generation,
            start,
            total_count: total,
            raw_total_count: raw_total,
            error_message: String::new(),
            rows,
        }
    }

    fn cached_page(start: u64, count: usize) -> CachedPage {
        CachedPage(
            (0..count)
                .map(|offset| {
                    let index = start + offset as u64;
                    glib::BoxedAnyObject::new(VirtualAddressRow::Loaded {
                        index,
                        record: record(index as i32 + 1, "old"),
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn bounded_cache_evicts_the_least_recently_used_page() {
        let mut cache = PageCache::new(2);
        assert!(cache.insert(0, cached_page(0, 2)).is_empty());
        assert!(cache.insert(2, cached_page(2, 2)).is_empty());
        assert!(cache.item(0, 0).is_some());
        assert_eq!(cache.insert(4, cached_page(4, 2)), vec![2]);
        assert!(cache.item(2, 0).is_none());
        assert!(cache.item(0, 0).is_some());
        assert!(cache.item(4, 0).is_some());
    }

    #[test]
    fn model_caps_positions_and_preserves_visible_and_raw_totals() {
        let model = AddressListModel::new(128, 3);
        model.configure(
            9,
            u64::from(u32::MAX) + 27,
            u64::from(u32::MAX) + 99,
            Rc::new(|_, _, _, _| Err("not loaded".to_owned())),
            Rc::new(|_| {}),
        );
        assert_eq!(model.n_items(), u32::MAX);
        assert_eq!(model.total_count(), u64::from(u32::MAX) + 27);
        assert_eq!(model.raw_total_count(), u64::from(u32::MAX) + 99);
        assert_eq!(model.cached_row_capacity(), 384);
    }

    #[test]
    fn refresh_updates_loaded_objects_in_place_and_rejects_stale_pages() {
        let model = AddressListModel::new(2, 2);
        model.configure(
            7,
            2,
            3,
            Rc::new(|generation, start, _, refresh| {
                let value = if refresh { "fresh" } else { "old" };
                Ok(page(
                    generation,
                    start,
                    2,
                    3,
                    vec![record(1, value), record(2, value)],
                ))
            }),
            Rc::new(|_| {}),
        );
        model.load_page(7, 0);
        let object = model.item(0).expect("loaded row object");
        assert_eq!(model.refresh_pages(&[0]).len(), 2);
        assert_eq!(object, model.item(0).expect("stable refreshed object"));
        let item = object
            .downcast::<glib::BoxedAnyObject>()
            .expect("boxed address row");
        assert!(matches!(
            &*item.borrow::<VirtualAddressRow>(),
            VirtualAddressRow::Loaded { record, .. } if record.value == "fresh"
        ));

        *model.imp().loader.borrow_mut() = Some(Rc::new(|generation, start, _, _| {
            Ok(page(generation + 1, start, 2, 3, vec![record(1, "bad")]))
        }));
        assert!(model.refresh_pages(&[0]).is_empty());
        assert_eq!(model.n_items(), 0);
        assert_eq!(model.total_count(), 0);
    }
}
