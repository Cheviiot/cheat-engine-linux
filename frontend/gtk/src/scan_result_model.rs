use std::cell::{Cell, RefCell};
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use gtk::gio;
use gtk::gio::subclass::prelude::*;
use gtk::glib;
use gtk::prelude::*;

use crate::bridge::ScanPage;

pub const MAX_BRIDGE_PAGE_SIZE: u32 = 256;
pub const DEFAULT_CACHE_PAGES: usize = 8;

pub type PageLoader = Rc<dyn Fn(u64, u64, u32) -> Result<ScanPage, String>>;
pub type IssueHandler = Rc<dyn Fn(ModelIssue)>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelIssue {
    Page(String),
    Stale(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VirtualScanRow {
    Loading {
        index: u64,
    },
    Loaded {
        index: u64,
        address: u64,
        value: String,
    },
    Error {
        index: u64,
        message: String,
    },
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

    fn item(&mut self, page_start: u64, offset: usize) -> Option<glib::BoxedAnyObject> {
        let item = self.pages.get(&page_start)?.0.get(offset).cloned();
        if item.is_some() {
            self.touch(page_start);
        }
        item
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

    pub struct ScanResultModel {
        pub generation: Cell<u64>,
        pub total_count: Cell<u64>,
        pub visible_count: Cell<u32>,
        pub page_size: Cell<u32>,
        pub cache_pages: Cell<usize>,
        pub(super) cache: RefCell<PageCache>,
        pub pending: RefCell<HashMap<(u64, u64), Vec<glib::BoxedAnyObject>>>,
        pub loader: RefCell<Option<PageLoader>>,
        pub issue_handler: RefCell<Option<IssueHandler>>,
    }

    impl Default for ScanResultModel {
        fn default() -> Self {
            Self {
                generation: Cell::new(0),
                total_count: Cell::new(0),
                visible_count: Cell::new(0),
                page_size: Cell::new(MAX_BRIDGE_PAGE_SIZE),
                cache_pages: Cell::new(DEFAULT_CACHE_PAGES),
                cache: RefCell::new(PageCache::new(DEFAULT_CACHE_PAGES)),
                pending: RefCell::new(HashMap::new()),
                loader: RefCell::new(None),
                issue_handler: RefCell::new(None),
            }
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ScanResultModel {
        const NAME: &'static str = "CeGtkScanResultModel";
        type Type = super::ScanResultModel;
        type Interfaces = (gio::ListModel,);
    }

    impl ObjectImpl for ScanResultModel {}

    impl ListModelImpl for ScanResultModel {
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
            let item = self.cache.borrow_mut().item(page_start, offset);
            if let Some(item) = item {
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
                        glib::BoxedAnyObject::new(VirtualScanRow::Loading {
                            index: page_start + offset,
                        })
                    })
                    .collect()
            });
            let item = items
                .get(offset)
                .cloned()
                .expect("visible scan position belongs to its pending page");
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
    pub struct ScanResultModel(ObjectSubclass<imp::ScanResultModel>)
        @implements gio::ListModel;
}

impl ScanResultModel {
    pub fn new(page_size: u32, cache_pages: usize) -> Self {
        let model: Self = glib::Object::new();
        let imp = model.imp();
        imp.page_size.set(page_size.clamp(1, MAX_BRIDGE_PAGE_SIZE));
        imp.cache_pages.set(cache_pages.max(1));
        *imp.cache.borrow_mut() = PageCache::new(cache_pages);
        model
    }

    pub fn configure(
        &self,
        generation: u64,
        total_count: u64,
        loader: PageLoader,
        issue_handler: IssueHandler,
    ) {
        let imp = self.imp();
        let old_count = imp.visible_count.get();
        let visible_count = total_count.min(u64::from(u32::MAX)) as u32;
        imp.generation.set(generation);
        imp.total_count.set(total_count);
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
        imp.pending.borrow_mut().clear();
        imp.cache.borrow_mut().clear();
        imp.loader.borrow_mut().take();
        imp.issue_handler.borrow_mut().take();
        if old_count > 0 {
            self.items_changed(0, old_count, 0);
        }
    }

    pub fn total_count(&self) -> u64 {
        self.imp().total_count.get()
    }

    pub fn displayed_count(&self) -> u32 {
        self.imp().visible_count.get()
    }

    pub fn cached_row_capacity(&self) -> u64 {
        u64::from(self.imp().page_size.get()) * self.imp().cache_pages.get() as u64
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
        let result = loader(expected_generation, page_start, page_size);
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
            Ok(page) => self.accept_page(expected_generation, page_start, page_size, page),
            Err(message) => self.cache_page_error(page_start, message),
        }
    }

    fn accept_page(
        &self,
        expected_generation: u64,
        page_start: u64,
        page_size: u32,
        page: ScanPage,
    ) {
        let imp = self.imp();
        if page.stale || page.generation != expected_generation {
            self.invalidate(ModelIssue::Stale(
                "Scan results changed while a visible page was loading.".to_owned(),
            ));
            return;
        }
        if !page.error_message.is_empty() {
            self.cache_page_error(page_start, page.error_message);
            return;
        }
        if page.start != page_start || page.total_count != imp.total_count.get() {
            self.invalidate(ModelIssue::Stale(
                "The scan result generation changed its paging contract.".to_owned(),
            ));
            return;
        }
        let returned = page.rows.len() as u64;
        let expected_end = page_start
            .saturating_add(u64::from(page_size))
            .min(page.total_count);
        if page_start.saturating_add(returned) != expected_end {
            self.cache_page_error(
                page_start,
                "The engine returned an unexpected scan-result page length.".to_owned(),
            );
            return;
        }
        let items = page
            .rows
            .into_iter()
            .enumerate()
            .map(|(offset, hit)| {
                glib::BoxedAnyObject::new(VirtualScanRow::Loaded {
                    index: page_start + offset as u64,
                    address: hit.address,
                    value: hit.value,
                })
            })
            .collect();
        self.insert_page(page_start, CachedPage(items));
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
                glib::BoxedAnyObject::new(VirtualScanRow::Error {
                    index: page_start + offset,
                    message: message.clone(),
                })
            })
            .collect();
        self.insert_page(page_start, CachedPage(items));
        if let Some(handler) = self.imp().issue_handler.borrow().clone() {
            handler(ModelIssue::Page(message));
        }
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
    use std::cell::Cell;

    use super::*;
    use crate::bridge::ScanHit;

    fn page(generation: u64, start: u64, total: u64, count: usize) -> ScanPage {
        ScanPage {
            generation,
            start,
            total_count: total,
            stale: false,
            error_message: String::new(),
            rows: (0..count)
                .map(|offset| ScanHit {
                    address: 0x1000 + start + offset as u64,
                    value: (start + offset as u64).to_string(),
                })
                .collect(),
        }
    }

    fn cached_page(generation: u64, start: u64, total: u64, count: usize) -> CachedPage {
        CachedPage(
            page(generation, start, total, count)
                .rows
                .into_iter()
                .enumerate()
                .map(|(offset, hit)| {
                    glib::BoxedAnyObject::new(VirtualScanRow::Loaded {
                        index: start + offset as u64,
                        address: hit.address,
                        value: hit.value,
                    })
                })
                .collect(),
        )
    }

    #[test]
    fn bounded_page_cache_evicts_the_least_recently_used_page() {
        let mut cache = PageCache::new(2);
        assert!(cache.insert(0, cached_page(1, 0, 6, 2)).is_empty());
        assert!(cache.insert(2, cached_page(1, 2, 6, 2)).is_empty());
        let item = cache.item(0, 0).expect("cached first item");
        assert!(matches!(
            &*item.borrow::<VirtualScanRow>(),
            VirtualScanRow::Loaded { index: 0, .. }
        ));
        assert_eq!(cache.insert(4, cached_page(1, 4, 6, 2)), vec![2]);
        assert!(cache.item(2, 0).is_none());
        assert!(cache.item(0, 0).is_some());
        assert!(cache.item(4, 0).is_some());
    }

    #[test]
    fn model_caps_positions_but_preserves_the_real_total() {
        let model = ScanResultModel::new(128, 3);
        model.configure(
            9,
            u64::from(u32::MAX) + 27,
            Rc::new(|_, _, _| Err("not loaded".to_owned())),
            Rc::new(|_| {}),
        );
        assert_eq!(model.n_items(), u32::MAX);
        assert_eq!(model.total_count(), u64::from(u32::MAX) + 27);
        assert_eq!(model.cached_row_capacity(), 384);
    }

    #[test]
    fn loading_replaces_placeholders_and_stale_pages_invalidate_the_model() {
        let model = ScanResultModel::new(2, 2);
        let stale = Rc::new(Cell::new(false));
        model.configure(
            7,
            3,
            Rc::new(|generation, start, _| Ok(page(generation, start, 3, 2))),
            {
                let stale = stale.clone();
                Rc::new(move |issue| stale.set(matches!(issue, ModelIssue::Stale(_))))
            },
        );
        model.load_page(7, 0);
        let object = model.item(0).expect("loaded row object");
        let repeated = model.item(0).expect("same loaded row object");
        assert_eq!(object, repeated, "loaded row identity must remain stable");
        let item = object
            .downcast::<glib::BoxedAnyObject>()
            .expect("loaded boxed row");
        assert!(matches!(
            &*item.borrow::<VirtualScanRow>(),
            VirtualScanRow::Loaded {
                index: 0,
                address: 0x1000,
                ..
            }
        ));

        *model.imp().loader.borrow_mut() = Some(Rc::new(|generation, start, _| {
            let mut result = page(generation, start, 3, 1);
            result.stale = true;
            Ok(result)
        }));
        model.load_page(7, 2);
        assert!(stale.get());
        assert_eq!(model.n_items(), 0);
        assert_eq!(model.total_count(), 0);
    }
}
