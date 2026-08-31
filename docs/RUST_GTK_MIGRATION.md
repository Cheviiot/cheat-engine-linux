# Rust GTK4/libadwaita migration plan

Status: implementation started, 2026-08-31.  The product name, application ID,
and final visual identity are intentionally left open until the naming review.

## Implementation progress

Completed in the foundation and first vertical slices:

- reproducible `lch-rust-gtk-dev` Ubuntu 24.04 Distrobox and pinned Rust 1.92;
- independent Qt and GTK frontend CMake options;
- Cargo workspace imported into CMake through pinned Corrosion 0.6.1;
- a CXX `EngineFacade` connected to the real shared `libcecore` version API;
- a bounded process-list bridge endpoint (maximum 512 rows and bounded query);
- an Adwaita application shell and asynchronous, searchable process chooser;
- a persistent attach/detach session with architecture, runtime, namespace, and
  tracer diagnostics plus an actual target-memory readability probe;
- stable, actionable errors for missing processes, restricted `/proc`, Yama/
  `CAP_SYS_PTRACE` denial, already-traced targets, and unreadable mappings;
- a validated, toolkit-neutral `ScanRequest` covering every existing value
  type and comparison plus address range, alignment, region/protection filters,
  integer hex mode, float rounding/tolerance/percentage options, string
  encoding/case mode, and explicit variable-width snapshots;
- GTK scan controls for that request, including a compact default workflow and
  a collapsed advanced-options panel;
- asynchronous first/next scans backed by the existing `MemoryScanner`, with
  progress, cancellation, one-level undo, result count, type-aware value
  formatting, write-error state, and generation-aware result paging (128-row
  GTK pages, 256-row bridge cap);
- deterministic bridge tests for self attach, child-process attach, failed
  reattach state preservation, bounded Int32 paging, float ranges,
  case-insensitive text plus Next Scan, AOB wildcards, variable-width
  Unknown/Changed scans, and All-type ranges/snapshots;
- a toolkit-neutral `AddressListController` in `libcecore` with stable record
  IDs, bounded snapshots, live scalar/text/AOB reads and writes, pointer-address
  expression resolution, safe session changes, five freeze modes, and group-aware
  deletion;
- bounded address-list endpoints in the CXX facade plus a GTK address list that
  accepts scan results and manual addresses, refreshes live values, edits on
  Enter, freezes at 100 ms, selects directional freeze policy, and removes
  records;
- shared hierarchy operations with stable IDs: multi-selection grouping,
  subtree-aware deletion and up/down reordering, group collapse state, and
  bounded GTK rendering of collapsed trees;
- a lossless `AddressRecordState` adapter covering pointer metadata, codecs,
  endianness, group policy, Lua/Auto Assembler content, hotkeys, dropdowns, and
  every display/freeze flag; imports are transactional and reject duplicate or
  invalid stable IDs without disturbing the current list;
- the legacy Qt hierarchy actions now run through `AddressListController`:
  grouping, subtree deletion, sibling/block moves, collapse, indent/outdent,
  and drag/drop all import complete record state, apply the shared operation,
  and restore Qt-only Auto Assembler disable state by stable ID;
- the Qt `IAddressList` adapter now also delegates bounded snapshots, stable-ID
  lookup, record/group creation and deletion, safe metadata edits, address/type
  changes, live reads, numeric writes, and numeric activation to the shared
  controller; changing the attached target raw-disables stale active state;
- `disableWithoutExecute()` is now a real per-record core operation: both it and
  the all-record variant clear active/frozen state without invoking activation
  callbacks or accidentally executing an imported disable script;
- transactional `.CT`/native-JSON load and save through the existing
  `CheatTable` parser, preserving pointer expressions, table metadata,
  structures, disassembler comments, hotkeys, dropdowns, entry Lua, Auto
  Assembler, table-level Lua, record length, group options, big-endian mode,
  and value codecs; XML `.CT` round trips also retain embedded form definitions;
- native GTK file dialogs and address-list actions for opening/saving tables,
  adding empty groups, grouping selected records, moving complete subtrees, and
  collapsing groups;
- an explicit, table-scoped GTK trust boundary: imported records are always
  inactive, Lua and Auto Assembler are identified separately, and Auto
  Assembler record switches unlock only after a default-deny warning; trust can
  be revoked at any time and no script runs merely because trust was granted;
- a read-only script-review workflow reachable from the default-deny warning:
  table Lua, record Lua, and Auto Assembler payloads are listed separately with
  stable record IDs and byte counts, and opened through explicit summary/text
  pages (256-item core/bridge cap, 64-item GTK page, 64 KiB text cap); review
  text is UTF-8-sanitized and viewing it neither executes code nor grants trust;
- an independent, table-scoped Lua consent path: Lua never runs on import,
  review, or trust alone; each selected table/record payload needs a destructive
  Run confirmation, is reconstructed only up to a 1 MiB execution cap, runs
  with a 2-million VM-instruction ceiling, and returns at most 64 KiB of
  UTF-8-sanitized print output; revocation recreates the Lua state and detaches
  its address-list callbacks, while the UI explicitly warns that completed
  native/target/system side effects cannot be rolled back;
- a GTK Lua Console sharing that resettable runtime without granting table
  trust: commands run only from the visible Run/Enter action, retain bounded
  command history and a bounded transcript, and use the same 1 MiB input,
  2-million VM-instruction, and 64 KiB output caps as explicit table payloads;
- toolkit-neutral periodic scheduling through `EngineFacade::periodic_tick`:
  GTK now drives address freezing, visible-row refresh cadence, and CE-style Lua
  timers from one 30 ms GLib source; due timers are round-robin fair, capped at
  32 callbacks per tick and 200,000 VM instructions per callback, with failing
  callbacks disabled and asynchronous output returned through a bounded DTO;
- runtime Auto Assembler disable state stays behind the CXX facade and is used
  to restore original target bytes before trust revocation, record/subtree
  deletion, target replacement, detach, or normal facade destruction; failed
  cleanup prevents an interactive detach or target change instead of silently
  losing the restoration state;
- table-level and per-record Lua are visibly preserved and executable only by
  the reviewed, separately trusted, per-payload GTK workflow; password-protected
  CETRAINER input still returns an explicit unsupported error;
- bridge tests that exercise real self-process writes, normal and directional
  freeze, stale scan generations, detach safety, and float/UTF-8/UTF-16/AOB
  codecs, plus group/subtree semantics, `.CT` hierarchy round trips, atomic
  failure behavior, protected-table rejection, script non-execution before
  trust, complete script enumeration/paging, hard payload limits with lossless
  multi-page reconstruction, review without execution/trust, separately gated
  Lua execution, output/instruction limits, Lua-state reset, real trusted AA
  enable/disable, trust revocation, reattach/detach cleanup, and deletion cleanup;
- CXX contract, Rust unit, GTK/Xvfb startup and Lua-console smokes, Qt smoke, and
  core regression tests.

The application ID and window title are explicitly development placeholders.
The current pager deliberately keeps only one bounded page in GTK.  A later
performance slice can replace the explicit Previous/Next controls with a
virtualized `gio::ListModel` and bounded LRU cache without changing the C++ page
contract.  The address-list controller is now the GTK source of truth and the
Qt model delegates hierarchy plus the safe `IAddressList` surface through a
lossless adapter.  Qt still owns its own periodic refresh/freeze/Lua pump,
inline value-editor verification, and its legacy Auto Assembler adapter. GTK now has
a bounded read-only review UI plus separately explicit-trust Auto Assembler and
Lua paths, an interactive bounded console, and toolkit-neutral periodic address/
Lua timer scheduling. Imported Lua is intentionally per-payload rather than
automatic, and VM instruction ceilings do not interrupt a blocking native
binding. Broader Lua GUI/form parity remains advanced work. The GTK frontend does not yet open
password-protected CETRAINER files, expose a loss report, or virtualize address
rows beyond its bounded first page. No product identifier should be published
before the branding decision.

## Goal

Replace the Qt presentation layer with a native Rust UI built on gtk4-rs and
libadwaita-rs while preserving the mature C++ engine.  The Qt application stays
buildable during the migration and is removed only after the replacement passes
an explicit parity gate.

The first usable release covers the everyday scan loop:

- process discovery, filtering, attach, detach, and actionable permission errors;
- new/first, next, undo, and cancel scan, with all existing scan value types,
  comparison modes, region filters, and progress reporting;
- a virtualized, paged result list with live value refresh;
- adding results to the address list, editing values, freezing, grouping, and
  reordering records;
- loading and saving `.CT` tables without silently losing supported data;
- an explicit trust prompt before executing table Lua or Auto Assembler scripts.

Advanced tools such as the memory browser, debugger, structure dissector,
pointer scanner, Lua GUI/forms, and script editor move in later vertical slices.
The foundational Lua console and CE-style timer lifecycle have already moved.
Until each slice reaches parity, the legacy Qt binary remains available as a
separate application.  The two frontends must not attempt to share live process
state across processes.

## What the audit found

- `libcecore` is already a Qt-free shared C++ library.  Only
  `scripting/lua_gui.cpp` and `scripting/lua_bitmap.cpp` outside `gui/` depend on
  Qt, and they are linked into the Qt application rather than the core.
- The GUI is about 19k lines.  `gui/mainwindow.cpp` is both presentation and
  application controller, and owns the process handle, scanner, results, Lua,
  Auto Assembler, and debugger state.
- The C++ public surface uses `std::expected`, `std::function`, virtual classes,
  `std::filesystem`, and smart pointers.  Generating bindings directly over the
  entire header tree would create a large and unstable interface.
- `ScanResult` is disk-backed and may represent millions of rows.  Copying a
  complete result set into Rust is not acceptable.
- `AddressListModel` contains substantial non-Qt behavior: live reads, writes,
  freezing, expression resolution, script activation, grouping, and table
  serialization.  `SimpleAddressList` only stores basic metadata, so it cannot
  replace that behavior yet.
- The C++ test suite and Qt smoke tests provide a useful regression net and must
  remain in CI throughout the transition.

## Target architecture

```text
Rust GTK4/libadwaita application
  views + actions + navigation
  Rust view models and bounded row caches
                 |
                 | CXX: small DTOs, opaque handles, Result
                 v
C++ EngineFacade / controllers
  session + asynchronous scan jobs
  paged scan-result access
  toolkit-neutral address-list controller
  cheat-table policy and serialization
                 |
                 v
existing libcecore
  process access, scanner, AA, Lua, debugger, analysis, CT format
```

### Interop boundary

Use CXX as the primary Rust/C++ bridge.  Do not expose the existing header tree
directly.  Introduce a narrow C++ facade that translates engine types into
bridge-safe data-transfer objects.

Boundary rules:

- C++ owns process handles, scan jobs, scan results, Lua, Auto Assembler, and
  debugger objects.
- Rust owns GTK objects, navigation, actions, transient UI state, and display
  caches.
- No Qt, GTK, C++ templates, exceptions, `std::expected`, `std::filesystem`, or
  raw owning pointers cross the bridge.
- Object references cross as opaque CXX types; scalar snapshots cross as small
  structs and vectors.  Errors cross as `Result` with stable error codes and a
  human-readable message.
- C++ worker threads never call GTK.  Rust polls job state on the GLib main loop
  and updates the UI on the main thread.
- Every collection endpoint has a maximum page size.  No bridge call may return
  an unbounded scan result, process list, table-script list, or script payload.

The first bridge API should stay close to this shape:

```text
EngineFacade
  list_processes(query, cursor, limit) -> ProcessPage
  attach(pid) / detach() -> SessionInfo
  start_first_scan(ScanRequest) -> JobId
  start_next_scan(ScanRequest) -> JobId
  undo_scan() -> ScanSummary
  cancel_job(JobId)
  job_status(JobId) -> JobStatus
  scan_rows(generation, start, count) -> ScanRowPage
  address_rows(start, count) -> AddressRowPage
  add_scan_result(row) / update_address(...) / delete_addresses(...)
  load_table(path, execution_policy) -> TableLoadReport
  table_scripts(start, count) -> TableScriptPage
  table_script_text(record_id, kind, offset, count) -> TableScriptTextPage
  set_table_lua_trusted(bool) / execute_table_lua(record_id, kind)
  execute_lua_console(source) -> LuaConsoleResult
  periodic_tick() -> RuntimeTickResult
  save_table(path) -> TableSaveReport
```

`generation` changes whenever the active result set changes.  It lets Rust drop
stale asynchronous page responses instead of showing rows from a previous scan.

### Scan results and GTK models

Keep the disk-backed `ScanResult` in C++.  The Rust side implements a bounded
page cache for the visible range and exposes rows to `gtk::ColumnView` through a
custom `gio::ListModel`.  Visible pages are fetched on demand; old pages are
evicted with an LRU policy.  Live values refresh only for visible rows and at a
rate that does not starve scanning.

The initial performance budgets are:

- attaching and opening an existing result set must not copy the full set;
- UI actions remain responsive during a scan;
- each page request is capped (initially 256 rows);
- the cache is bounded (initially 16 pages, configurable after profiling);
- cancellation reaches a terminal state promptly and never leaves a detached
  worker touching a destroyed process handle.

### Address-list extraction

Before implementing the GTK address table, extract the non-visual behavior from
`AddressListModel` into a toolkit-neutral `AddressListController` in the core.
It should implement `IAddressList` and own stable record IDs, hierarchy, address
expressions, value codecs, live read/write, freeze modes, script activation, and
CT conversion.

The Qt model becomes an adapter over this controller.  This is the migration
safety mechanism: existing Qt smoke tests exercise the new shared controller
before the Rust UI depends on it.  `SimpleAddressList` remains the lightweight
headless implementation for tests and CLI uses that do not need live behavior.

## Build integration

CMake remains the top-level build for `libcecore` and the legacy Qt frontend.
Cargo owns the Rust application.  The intended integration is:

- a pinned Rust toolchain with a documented MSRV;
- `cxx-build` in the Rust crate for the CXX-generated bridge code;
- Corrosion only to import and orchestrate the Cargo target from CMake and link
  it with the native targets;
- no dependency on Corrosion's experimental CXX bridge generator;
- CMake options `CECORE_BUILD_QT_GUI` and `CECORE_BUILD_GTK_GUI`, both enabled in
  migration CI until the retirement gate is met.

Provisional layout (names may change with the brand):

```text
bridge/
  engine_facade.hpp
  engine_facade.cpp
  scan_controller.*
  address_list_controller.*
frontend/gtk/
  Cargo.toml
  build.rs
  src/bridge.rs
  src/application.rs
  src/models/
  src/views/
```

## Reproducible development environment

Development dependencies must live in a dedicated Distrobox rather than on the
ALT Workstation host.  Create `lch-rust-gtk-dev` from Ubuntu 24.04 so local work
matches GitHub Actions.  Install the current C/C++ build dependencies plus GTK4,
libadwaita, GtkSourceView, Rust tooling, and Xvfb inside that container.  Pin the
Rust toolchain with `rust-toolchain.toml`; do not rely on Ubuntu's older Rust
package.

The exact setup commands are recorded in `docs/DEVELOPMENT.md`.  The container
must be able to build both frontends, run non-GUI tests, and run GTK/Qt smoke
tests under a virtual display.

## Delivery phases and gates

### Phase 0 — trustworthy baseline

1. Fix the test target dependency so `cecore_test` builds `speedhack` before the
   dlopen injection test.
2. Make the ARM64 disassembler test accept the canonical instruction and valid
   Capstone alias instead of comparing one spelling only.
3. Add the two frontend build options without changing default behavior.
4. Create and document the Distrobox; reproduce the upstream build and test
   suite inside it.

Gate: a clean checkout has a reproducible green baseline in the documented
container and CI.

### Phase 1 — bridge spike and session shell

1. Add the Rust workspace, gtk4-rs/libadwaita-rs application shell, and CMake to
   Cargo integration.
2. Add `EngineFacade` with version reporting, bounded process listing, attach,
   detach, and target diagnostics.
3. Add C++ facade tests, a CXX contract test, and a GTK startup smoke test.
4. Prove clean shutdown while attached and while an asynchronous job is being
   cancelled.

Gate: the GTK app can choose a real process, attach, show target information,
detach, and exit without leaks or use-after-free under sanitizers.

### Phase 2 — shared address-list controller

1. Extract record storage and non-visual operations from `AddressListModel`.
2. Adapt the Qt model to the shared controller without visible regressions.
3. Add focused tests for hierarchy, reordering, expressions, codecs, live
   reads/writes, every freeze mode, script activation, and CT round trips.

Gate: the existing Qt tests pass against the extracted controller and a headless
controller test covers live behavior.

### Phase 3 — first complete GTK scan workflow

1. Implement the asynchronous scan job state machine and cancellation.
2. Implement the virtualized result model and live visible-row refresh.
3. Build the Adwaita main window, scan controls, process chooser, address list,
   empty/error/progress states, shortcuts, and responsive layout.
4. Add `.CT` load/save with a loss report and explicit Lua/AA execution consent.
5. Add an end-to-end test against the repository's sample target.

Gate: a user can complete the first/next/undo scan loop, edit and freeze an
address, save it, reload it, and continue working without opening Qt.

### Phase 4 — vertical feature migration

Move one feature at a time, keeping its controller toolkit-neutral and adding a
parity test before marking it complete.  Proposed order:

1. memory browser, disassembler, and assembler;
2. Auto Assembler/script editor and Lua console (console/timer foundation complete);
3. debugger, breakpoints, find-what-writes/accesses, and tracer;
4. pointer scanner and structure dissector;
5. remaining analysis tools, settings, hotkeys, overlay, and trainer workflow.

Gate: each feature leaves Qt only after its supported Linux behavior is present,
tested, and recorded in a new GTK parity matrix.

### Phase 5 — branding, packaging, and Qt retirement

Brand selection can run in parallel, but the final name must be chosen before
freezing the application ID, executable, icon, AppStream metadata, MIME labels,
and package names.  Keep the internal `cecore` target name initially to reduce
upstream merge conflicts; rebrand user-visible surfaces first.

Ship native DEB, RPM, and TGZ packages first.  Add AppImage only after native
packaging is reliable.  Flatpak is not a primary target because sandbox/PID
namespace constraints conflict with ptrace-based process access.

Retire Qt only when:

- the GTK parity matrix has no release-blocking gaps;
- all CT round-trip fixtures pass without unintended data loss;
- CI and sanitizer jobs are green;
- startup, attach, scan, freeze, debugger detach, and shutdown tests pass;
- installation, desktop integration, MIME handling, and permissions have been
  validated on the supported distributions;
- at least one release has shipped with both frontends for rollback safety.

## Test strategy

- C++ unit tests for facade state machines and controllers, using fake process
  handles wherever possible.
- Rust unit tests for request validation, view-model reducers, page-cache
  invalidation, and error mapping.
- Cross-language contract tests for every CXX DTO and error path.
- GTK smoke tests under Xvfb for startup, navigation, dialogs, themes, keyboard
  access, and clean shutdown.
- Cross-process end-to-end tests for attach, scan, write, freeze, and detach.
- CT fixture tests for XML, JSON, groups, hotkeys, annotations, forms, Lua, and
  Auto Assembler records, including a structured loss report.
- Existing Qt tests remain mandatory until Qt retirement.

## Branding constraints

The working pattern is `<Distinctive word> Engine`, but no candidate is approved
yet.  A candidate must pass, at minimum:

- exact and confusingly similar searches on GitHub, major Linux package indexes,
  Flathub/AppStream, search engines, and common social/developer handles;
- domain and application-ID availability checks;
- a trademark screening in intended release regions;
- pronunciation and transliteration checks in English and Russian;
- an icon test at 16, 32, 64, and 128 pixels and in symbolic monochrome form.

Searches can reduce collision risk but cannot prove that a name is legally
unique.  The approved name, rationale, search date, and checked sources should be
recorded in a short decision note before public release.

## Upstream and Git workflow

- `origin`: the product fork under the maintainer's GitHub account.
- `upstream`: `wleeaf/cheat-engine-linux`.
- Migration branch: `rewrite/rust-gtk-foundation`.
- Keep core fixes small and separable so useful changes can be proposed upstream.
- Avoid broad core renames during migration; they make upstream synchronization
  unnecessarily expensive.
- Rebase or merge upstream deliberately, run both frontend suites, and record any
  facade adaptation in the same integration pull request.

## Immediate implementation queue

1. ~~Phase 0 baseline fixes and Distrobox bootstrap documentation.~~
2. ~~Minimal Cargo/GTK application and CXX/Corrosion version spike.~~
3. ~~Bounded process list, attach/detach, and target diagnostics.~~
4. ~~Asynchronous Int32 first-scan spike with progress and cancellation.~~
5. ~~Replace the preview with generation-aware, bounded result paging.~~
6. ~~Add exact Int32 next scan and one-level undo.~~
7. ~~Add the complete scan request/value-type/comparison surface.~~
8. Replace the explicit pager with a virtualized bounded-cache GTK model.
9. Extract the toolkit-neutral address-list controller and adapt Qt to it
   (controller, GTK ownership, hierarchy, and the safe live `IAddressList`
   surface complete; Qt's periodic refresh/freeze timers remain).
10. ~~Connect scan/manual addresses to live edit, freeze modes, and removal in GTK.~~
11. ~~Grouping/reordering, lossless modeled-field `.CT`/JSON persistence, GTK
    trust/review, trusted Auto Assembler activation/cleanup, and separately
    consented per-payload Lua execution with bounded input/VM/output, periodic
    scheduling, and Lua console/timer parity.~~ Next replace the explicit result
    pager with a virtualized bounded-cache model and continue Lua GUI/form parity.
