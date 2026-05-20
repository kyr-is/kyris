// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Menu-bar (tray) icon for `kyrisd`.
//!
//! The `TrayState` enum + the three `set_*` setters are compiled
//! unconditionally so callers in `server.rs`, `reconcile_watcher.rs`,
//! `sync/daemon_sync.rs`, and the server poller can push status updates
//! without cfg-attribute noise. The actual GUI plumbing is gated behind
//! `--features tray` (on by default) and split by target OS:
//!
//!   macOS   — native objc2: `NSApplication` + `NSStatusItem` + `NSMenu`
//!   Windows — stub (Win32 `Shell_NotifyIcon` planned for phase 2)
//!   Linux   — stub (GTK4 / ksni planned for phase 2)
//!
//! Menu layout (small footprint, mirrors Docker/1Password/BTT):
//!
//!   Status: Running                ← disabled, dynamic
//!   ─────────────────────
//!   Continue Routing               ← greyed unless circuit breaker tripped
//!   Open Logs                      ← always enabled
//!   ─────────────────────
//!   Quit Kyris                     ← always enabled, runs launchctl bootout
//!
//! There is no "Pending Approvals" menu entry: with the always-on-top
//! approval popup (`notify_macos::show_approval_alert`) handling each ask
//! synchronously, the user never needs a separate queue surface in the
//! tray. The internal pending queue still exists (it backs the async
//! popup lifecycle, timeouts, and the `kyris pending` CLI fallback for
//! no-TTY shell-hook flows) — it just isn't a tray-visible concept.
//!
//! Status/tripped state is pushed from the tokio side via atomics
//! and polled by a 250ms `NSTimer` on the main thread (macOS).  The
//! daemon's main thread calls [`run_event_loop`] while Tokio runs on a
//! background thread; see `kyrisd::main`.
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TrayState {
    Normal = 0,
    Degraded = 1,
    RelayDisconnected = 2,
}

impl std::fmt::Display for TrayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Normal => f.write_str("normal"),
            Self::Degraded => f.write_str("degraded"),
            Self::RelayDisconnected => f.write_str("relay_disconnected"),
        }
    }
}

impl TrayState {
    #[cfg(any(feature = "tray", test))]
    fn tooltip(self) -> &'static str {
        match self {
            Self::Normal => "Kyris daemon: running",
            Self::Degraded => "Kyris daemon: degraded",
            Self::RelayDisconnected => "Kyris daemon: relay disconnected",
        }
    }

    #[cfg(any(feature = "tray", test))]
    fn status_label(self) -> &'static str {
        match self {
            Self::Normal => "Status: Running",
            Self::Degraded => "Status: Degraded",
            Self::RelayDisconnected => "Status: Relay disconnected",
        }
    }

    #[cfg(test)]
    fn label(self) -> &'static str {
        match self {
            Self::Normal => "Kyris ●",
            Self::Degraded => "Kyris ◐",
            Self::RelayDisconnected => "Kyris ○",
        }
    }
}

static CURRENT_STATE: AtomicU8 = AtomicU8::new(0);
static CIRCUIT_BREAKER_TRIPPED: AtomicBool = AtomicBool::new(false);
// Number of approval requests currently held in kyrisd's pending queue
// that the user hasn't responded to. When > 0, the menu-bar tray switches
// to an attention state (status label shows the count, tooltip changes,
// icon becomes the degraded/amber variant) so the user has a persistent
// visual signal even when an NSAlert popup failed to surface.
static PENDING_APPROVAL_COUNT: AtomicUsize = AtomicUsize::new(0);

pub fn set_state(state: TrayState) {
    CURRENT_STATE.store(state as u8, Ordering::Relaxed);
}

pub fn current_state() -> TrayState {
    match CURRENT_STATE.load(Ordering::Relaxed) {
        1 => TrayState::Degraded,
        2 => TrayState::RelayDisconnected,
        _ => TrayState::Normal,
    }
}

/// Push whether any session has tripped the circuit breaker. Same
/// poller in `server::run` reads `state.circuit_breaker.any_tripped()`.
pub fn set_circuit_breaker_tripped(tripped: bool) {
    CIRCUIT_BREAKER_TRIPPED.store(tripped, Ordering::Relaxed);
}

/// Push the current count of held pending approvals. Called by the
/// permission/hold paths in `server.rs` after every transition so the
/// menu-bar tray's 250ms refresh picks up the change.
pub fn set_pending_approval_count(count: usize) {
    PENDING_APPROVAL_COUNT.store(count, Ordering::Relaxed);
}

// --- Feature-gated GUI plumbing -------------------------------------------
//
// The native icon + event loop are only compiled when the `tray` feature is
// enabled. With the feature off the daemon updates the atomics for free but
// no UI is drawn and no main-thread run loop is needed.
//
// Platform split:
//   macOS   — native objc2: NSApplication + NSStatusItem + NSMenu
//   Windows — stub (Win32 Shell_NotifyIcon planned for phase 2)
//   Linux   — stub (GTK4 / ksni planned for phase 2)

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(all(feature = "tray", target_os = "windows"))]
mod gui {
    use std::thread::JoinHandle;

    /// Ask the user to approve an action.
    /// TODO: Windows notification/dialog — returns `Yes` for now.
    pub async fn ask_approval(
        _title: &str,
        _body: &str,
        _code: Option<&str>,
    ) -> crate::notify::ApprovalOutcome {
        crate::notify::ApprovalOutcome::Yes
    }

    /// Run the UI event loop. TODO: Win32 Shell_NotifyIcon tray icon.
    /// For now, waits for tokio to finish and exits cleanly.
    pub fn run_event_loop(tokio_handle: JoinHandle<()>) -> ! {
        let _ = tokio_handle.join();
        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------
// Linux / other stub
// ---------------------------------------------------------------------------

#[cfg(all(feature = "tray", not(any(target_os = "macos", target_os = "windows"))))]
mod gui {
    use std::thread::JoinHandle;

    /// Ask the user to approve an action.
    /// TODO: Linux desktop notification/dialog — returns `Yes` for now.
    pub async fn ask_approval(
        _title: &str,
        _body: &str,
        _code: Option<&str>,
    ) -> crate::notify::ApprovalOutcome {
        crate::notify::ApprovalOutcome::Yes
    }

    /// Run the UI event loop. TODO: GTK4 / ksni tray icon for Linux.
    /// For now, waits for tokio to finish and exits cleanly.
    pub fn run_event_loop(tokio_handle: JoinHandle<()>) -> ! {
        let _ = tokio_handle.join();
        std::process::exit(0);
    }
}

// ---------------------------------------------------------------------------
// macOS native implementation
// ---------------------------------------------------------------------------

#[cfg(all(feature = "tray", target_os = "macos"))]
#[allow(unsafe_code)]
mod gui {
    use super::{CIRCUIT_BREAKER_TRIPPED, PENDING_APPROVAL_COUNT, TrayState, current_state};
    use block2::RcBlock;
    use core::ffi::c_uchar;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    // AnyThread as _ brings the `alloc()` method into scope for AnyThread classes
    // (NSBitmapImageRep, NSImage).  MainThreadOnly brings `alloc(mtm)` for
    // MainThreadOnly classes (our MenuActionHandler, NSStatusItem, etc.).
    use objc2::{AnyThread as _, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
    use objc2_app_kit::{
        NSApplication, NSBitmapImageRep, NSDeviceRGBColorSpace, NSImage, NSMenu, NSMenuItem,
        NSStatusBar,
    };
    use objc2_foundation::{NSObject, NSSize, NSString, NSTimer};
    use std::cell::RefCell;
    use std::process::Command;
    use std::ptr::NonNull;
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;
    use std::thread::JoinHandle;

    const TRAY_ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
    // Pixel dimensions of the rasterized RGBA buffer.
    const TRAY_ICON_PIXEL_SIZE: isize = 44;
    // Logical point size for NSImage — half the pixel size so macOS treats
    // this as a @2x Retina representation of a 22×22-point menu-bar icon.
    const TRAY_ICON_LOGICAL_PTS: f64 = 22.0;

    // -----------------------------------------------------------------------
    // Cross-thread work queue — replaces tao's EventLoopProxy
    //
    // Background threads push `FnOnce` closures into this queue; the 250ms
    // NSTimer drains it on the main thread.  `wake_main_run_loop()` signals
    // the run loop to break its wait immediately so the timer fires within a
    // single quantum rather than at the next 250ms boundary.
    // -----------------------------------------------------------------------

    static PENDING_MAIN_WORK: Mutex<Vec<Box<dyn FnOnce() + Send>>> = Mutex::new(Vec::new());

    fn push_main_work(f: impl FnOnce() + Send + 'static) {
        PENDING_MAIN_WORK.lock().unwrap().push(Box::new(f));
    }

    fn drain_main_work() {
        let work: Vec<_> = PENDING_MAIN_WORK.lock().unwrap().drain(..).collect();
        for f in work {
            f();
        }
    }

    /// Signal the main `CFRunLoop` to break its current wait immediately.
    /// Two `extern "C"` declarations — both symbols live in CoreFoundation,
    /// which is always linked on macOS.  No new crate dep required.
    fn wake_main_run_loop() {
        unsafe extern "C" {
            fn CFRunLoopGetMain() -> *mut std::ffi::c_void;
            fn CFRunLoopWakeUp(rl: *mut std::ffi::c_void);
        }
        unsafe { CFRunLoopWakeUp(CFRunLoopGetMain()) };
    }

    // -----------------------------------------------------------------------
    // Snapshot — same as before, unchanged logic
    // -----------------------------------------------------------------------

    #[derive(PartialEq, Eq, Clone, Copy)]
    struct Snapshot {
        tray_state: TrayState,
        circuit_breaker_tripped: bool,
        pending_approval_count: usize,
    }

    impl Snapshot {
        fn read() -> Self {
            Self {
                tray_state: current_state(),
                circuit_breaker_tripped: CIRCUIT_BREAKER_TRIPPED.load(Ordering::Relaxed),
                pending_approval_count: PENDING_APPROVAL_COUNT.load(Ordering::Relaxed),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Persistent UI state — thread_local because NSStatusItem / NSMenuItem
    // are MainThreadOnly and cannot be stored in a Mutex (not Send/Sync).
    // The timer callback and all AppKit calls are on the main thread, so
    // RefCell gives safe interior mutability here.
    // -----------------------------------------------------------------------

    struct TrayUi {
        status_item: Retained<objc2_app_kit::NSStatusItem>,
        /// Retained to prevent deallocation — `NSMenuItem`'s `target` is a
        /// weak (unretained) reference in `AppKit`; we must keep the handler
        /// alive ourselves for the lifetime of the menu.
        _handler: Retained<MenuActionHandler>,
        status_label: Retained<NSMenuItem>,
        continue_item: Retained<NSMenuItem>,
        last_snapshot: Snapshot,
        // The icon set in build_tray_ui runs before [NSApp run] — at that
        // point macOS may not have finished resolving the bundle identity
        // with LaunchServices, and NSStatusItem can paint the template
        // image as raw alpha (visible as scattered dots in the menu bar).
        // The first timer tick after the run loop starts re-applies the
        // icon unconditionally so the render lands correctly.
        needs_initial_paint: bool,
    }

    thread_local! {
        static TRAY_UI: RefCell<Option<TrayUi>> = const { RefCell::new(None) };
    }

    // -----------------------------------------------------------------------
    // ObjC class: target for NSMenuItem actions
    //
    // Each visible menu item gets `.setTarget(&handler)` + a unique
    // `.setAction(sel!(name:))`.  NSMenuItem's target is a weak/unretained
    // reference so `TrayUi._handler` keeps this alive.
    // -----------------------------------------------------------------------

    define_class!(
        // SAFETY: NSObject has no subclassing requirements; MenuActionHandler
        // has no Drop impl that would conflict with the generated dealloc.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        struct MenuActionHandler;

        impl MenuActionHandler {
            #[unsafe(method(continueRouting:))]
            fn continue_routing_action(&self, _: Option<&AnyObject>) {
                continue_routing();
            }

            #[unsafe(method(openLogs:))]
            fn open_logs_action(&self, _: Option<&AnyObject>) {
                open_logs();
            }

            #[unsafe(method(quitDaemon:))]
            fn quit_daemon_action(&self, _: Option<&AnyObject>) {
                quit_daemon();
            }
        }
    );

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Dispatch an `NSAlert` approval dialog to the main thread and await
    /// the user's response.  The work queue delivers the call within 250ms
    /// (next timer tick); `wake_main_run_loop` reduces that to the next
    /// run-loop iteration.  Returns `CouldNotShow` if the channel is dropped
    /// (sender panicked / main run loop ended), so the caller can route to
    /// another channel instead of treating the silence as a denial.
    ///
    /// `code`, when `Some`, is rendered in the popup's accessoryView as
    /// monospaced text — for shell commands and file paths the user needs
    /// to read clearly to make the decision.
    pub async fn ask_approval(
        title: &str,
        body: &str,
        code: Option<&str>,
    ) -> crate::notify::ApprovalOutcome {
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::notify::ApprovalOutcome>();
        let title = title.to_string();
        let body = body.to_string();
        let code = code.map(str::to_string);
        push_main_work(move || {
            let result = crate::notify_macos::show_approval_alert(&title, &body, code.as_deref());
            let _ = tx.send(result);
        });
        wake_main_run_loop();
        // If the channel is dropped (sender panicked / main loop ended),
        // surface that as CouldNotShow rather than a silent Yes — the
        // caller can then escalate to another channel.
        rx.await.unwrap_or(crate::notify::ApprovalOutcome::CouldNotShow)
    }

    /// Run the `AppKit` event loop on the calling thread (must be the process
    /// main thread).  Constructs the tray icon and `NSMenu`, then calls
    /// `[NSApp run]` which never returns.  Tokio runs on a background thread;
    /// a watchdog thread joins it and schedules `[NSApp terminate]` via the
    /// work queue so shutdown is clean.
    ///
    /// Why `[NSApp run]` and not `CFRunLoop`:
    /// `AppKit`'s event dispatch (`nextEventMatchingMask:` + `sendEvent:`) is
    /// required for `NSMenu`, `NSStatusBarButton` mouse events, and `NSAlert` modals.
    /// `CFRunLoop::run()` alone does not drain the `AppKit` event queue.
    pub fn run_event_loop(tokio_handle: JoinHandle<()>) -> ! {
        let mtm = MainThreadMarker::new().expect("must be called from the main thread");

        // LSUIElement=true in Info.plist sets Accessory at bundle load time;
        // setting it here is belt-and-suspenders for the launchd-spawned case
        // where the bundle identity may not be resolved before this point.
        let app = NSApplication::sharedApplication(mtm);
        unsafe {
            let _: () = msg_send![
                &*app,
                setActivationPolicy:
                    objc2_app_kit::NSApplicationActivationPolicy::Accessory
            ];
        }

        // Build the tray icon.  Store in thread_local so the timer can update it.
        TRAY_UI.with(|cell| *cell.borrow_mut() = Some(build_tray_ui(mtm)));

        // Request notification permission on the first timer tick.
        // UN center only registers from a LaunchServices-recognized app process,
        // which only holds after [NSApp run] has started. See Apple Forums
        // thread 679326 and notify_macos::request_authorization_if_needed.
        push_main_work(crate::notify::request_authorization_if_needed);

        // 250ms repeating timer: drains the work queue + refreshes menu state.
        let timer_block = RcBlock::new(|_: NonNull<NSTimer>| {
            drain_main_work();
            refresh_snapshot(MainThreadMarker::new().expect("timer fires on main thread"));
        });
        // `scheduledTimer...` auto-adds to the current run loop in the default
        // mode.  We keep it in a local so it isn't immediately deallocated.
        let _timer = unsafe {
            NSTimer::scheduledTimerWithTimeInterval_repeats_block(0.25, true, &timer_block)
        };

        // Watchdog: a separate OS thread blocks on the tokio JoinHandle.
        // When tokio exits (after graceful shutdown or SIGTERM handling), it
        // pushes `[NSApp terminate]` to the work queue and wakes the run loop.
        std::thread::Builder::new()
            .name("kyrisd-tokio-watchdog".to_string())
            .spawn(move || {
                let _ = tokio_handle.join();
                tracing::info!("tokio thread finished; scheduling NSApplication termination");
                push_main_work(|| {
                    let mtm = MainThreadMarker::new().expect("main thread");
                    let app = NSApplication::sharedApplication(mtm);
                    // terminate: nil — the standard AppKit quit idiom.
                    unsafe {
                        let _: () = msg_send![&*app, terminate: None::<&AnyObject>];
                    }
                });
                wake_main_run_loop();
            })
            .expect("spawn watchdog thread");

        app.run();
        unreachable!()
    }

    // -----------------------------------------------------------------------
    // Build the tray icon and menu
    // -----------------------------------------------------------------------

    fn build_tray_ui(mtm: MainThreadMarker) -> TrayUi {
        // Instantiate the menu action handler.  We retain it in TrayUi so it
        // outlives the menu items that hold a weak reference to it as target.
        let handler: Retained<MenuActionHandler> =
            unsafe { msg_send![MenuActionHandler::alloc(mtm), init] };

        let menu = NSMenu::new(mtm);

        // 1. Status label — always disabled, text updated by refresh_snapshot.
        let status_label = make_item(mtm, TrayState::Normal.status_label(), false, None, None);
        menu.addItem(&status_label);
        menu.addItem(&NSMenuItem::separatorItem(mtm));

        // 2. Continue routing — enabled only when circuit breaker is tripped.
        let continue_item = make_item(
            mtm,
            "Continue Routing",
            false,
            Some(&handler),
            Some(sel!(continueRouting:)),
        );
        menu.addItem(&continue_item);

        // 3. Open logs — always enabled.
        menu.addItem(&make_item(
            mtm,
            "Open Logs",
            true,
            Some(&handler),
            Some(sel!(openLogs:)),
        ));

        menu.addItem(&NSMenuItem::separatorItem(mtm));

        // 4. Quit — always enabled.
        menu.addItem(&make_item(
            mtm,
            "Quit Kyris",
            true,
            Some(&handler),
            Some(sel!(quitDaemon:)),
        ));

        // NSStatusItem
        let status_bar = NSStatusBar::systemStatusBar();
        // NSVariableStatusItemLength = -1.0
        let status_item = status_bar.statusItemWithLength(-1.0);
        status_item.setMenu(Some(&menu));

        // Initial icon (normal, template so macOS auto-tints for dark/light).
        set_status_item_icon(&status_item, mtm, false);

        // Initial tooltip.
        unsafe {
            let tip = NSString::from_str(TrayState::Normal.tooltip());
            let _: () = msg_send![&*status_item, setToolTip: &*tip];
        }

        TrayUi {
            status_item,
            _handler: handler,
            status_label,
            continue_item,
            last_snapshot: Snapshot::read(),
            needs_initial_paint: true,
        }
    }

    fn make_item(
        mtm: MainThreadMarker,
        title: &str,
        enabled: bool,
        handler: Option<&MenuActionHandler>,
        action: Option<objc2::runtime::Sel>,
    ) -> Retained<NSMenuItem> {
        let item = unsafe {
            NSMenuItem::initWithTitle_action_keyEquivalent(
                NSMenuItem::alloc(mtm),
                &NSString::from_str(title),
                action,
                &NSString::from_str(""),
            )
        };
        item.setEnabled(enabled);
        if let Some(h) = handler {
            unsafe {
                let _: () = msg_send![&*item, setTarget: h];
            }
        }
        item
    }

    // -----------------------------------------------------------------------
    // Snapshot refresh — called from the 250ms NSTimer
    // -----------------------------------------------------------------------

    fn refresh_snapshot(mtm: MainThreadMarker) {
        TRAY_UI.with(|cell| {
            let mut opt = cell.borrow_mut();
            let Some(ui) = opt.as_mut() else { return };
            let now = Snapshot::read();
            if now == ui.last_snapshot && !ui.needs_initial_paint {
                return;
            }
            ui.needs_initial_paint = false;

            // Pending approvals override the normal status display — the
            // user needs to know there's something waiting for them, even
            // if the daemon itself is healthy. Falls back to tray_state's
            // label/tooltip when no approvals are pending.
            let needs_attention = now.pending_approval_count > 0
                || !matches!(now.tray_state, TrayState::Normal);

            let status_text: String = if now.pending_approval_count > 0 {
                format!(
                    "Pending Approvals: {} (run `kyris pending` to resolve)",
                    now.pending_approval_count
                )
            } else {
                now.tray_state.status_label().to_string()
            };
            let tooltip_text: String = if now.pending_approval_count > 0 {
                format!(
                    "Kyris: {} pending approval{}",
                    now.pending_approval_count,
                    if now.pending_approval_count == 1 {
                        ""
                    } else {
                        "s"
                    }
                )
            } else {
                now.tray_state.tooltip().to_string()
            };

            unsafe {
                let t = NSString::from_str(&status_text);
                let _: () = msg_send![&*ui.status_label, setTitle: &*t];
            }
            unsafe {
                let t = NSString::from_str(&tooltip_text);
                let _: () = msg_send![&*ui.status_item, setToolTip: &*t];
            }

            // Icon: template (auto-tint) only when nothing needs attention.
            // Pending approvals reuse the existing amber/degraded variant —
            // a separate "pending" art asset can come later; for now the
            // status-label text + tooltip carry the specifics.
            set_status_item_icon(&ui.status_item, mtm, needs_attention);

            // Continue routing.
            unsafe {
                let _: () = msg_send![
                    &*ui.continue_item,
                    setEnabled: now.circuit_breaker_tripped
                ];
            }

            ui.last_snapshot = now;
        });
    }

    // -----------------------------------------------------------------------
    // Icon helpers
    // -----------------------------------------------------------------------

    /// Build an `NSImage` from the rasterized icon RGBA bytes.
    /// Template = true makes macOS auto-tint for dark/light mode.
    /// Degraded = true applies an amber overlay to signal status.
    fn set_status_item_icon(
        status_item: &objc2_app_kit::NSStatusItem,
        mtm: MainThreadMarker,
        degraded: bool,
    ) {
        let rgba = if degraded {
            degraded_icon_rgba()
        } else {
            TRAY_ICON_RGBA.to_vec()
        };
        let Some(image) = build_ns_image(&rgba, TRAY_ICON_PIXEL_SIZE, TRAY_ICON_LOGICAL_PTS) else {
            return;
        };
        // Template tinting auto-colours for menu-bar appearance only when NOT degraded.
        unsafe {
            let _: () = msg_send![&*image, setTemplate: !degraded];
        }
        if let Some(btn) = status_item.button(mtm) {
            unsafe {
                let _: () = msg_send![&*btn, setImage: &*image];
            }
        }
    }

    /// Build an `NSImage` from raw RGBA bytes.
    ///
    /// `pixel_size` is the width/height of the RGBA buffer in actual pixels.
    /// `logical_pts` is the size `NSImage` advertises to `AppKit` in logical points.
    /// Setting `logical_pts = pixel_size / 2` tells macOS this is a @2x Retina
    /// representation of a (pixel_size/2)-point icon — the standard for menu-bar
    /// status items, which are 22 logical points on all current macOS hardware.
    fn build_ns_image(
        rgba: &[u8],
        pixel_size: isize,
        logical_pts: f64,
    ) -> Option<Retained<NSImage>> {
        let mut owned = rgba.to_vec();
        let rep = unsafe {
            let mut planes = [
                owned.as_mut_ptr().cast::<c_uchar>(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ];
            NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
                NSBitmapImageRep::alloc(),
                planes.as_mut_ptr(),
                pixel_size, pixel_size,
                8, 4,
                true, false,
                NSDeviceRGBColorSpace,
                pixel_size * 4,
                32,
            )
        }?;
        let image = NSImage::initWithSize(
            NSImage::alloc(),
            NSSize {
                width: logical_pts,
                height: logical_pts,
            },
        );
        image.addRepresentation(&rep);
        Some(image)
    }

    fn degraded_icon_rgba() -> Vec<u8> {
        let mut rgba = TRAY_ICON_RGBA.to_vec();
        for pixel in rgba.chunks_exact_mut(4) {
            if pixel[3] == 0 {
                continue;
            }
            pixel[0] = ((u16::from(pixel[0]) * 2) / 5 + (255_u16 * 3) / 5) as u8;
            pixel[1] = ((u16::from(pixel[1]) * 2) / 5 + (191_u16 * 3) / 5) as u8;
            pixel[2] = (u16::from(pixel[2]) / 3) as u8;
        }
        rgba
    }

    // -----------------------------------------------------------------------
    // Platform-specific OS operations — same as before, unchanged
    // -----------------------------------------------------------------------

    mod platform {
        use std::process::{Child, Command};

        #[cfg(target_os = "macos")]
        pub fn open_log_file(path: &str) -> std::io::Result<Child> {
            Command::new("open").args(["-a", "Console", path]).spawn()
        }
        #[cfg(target_os = "linux")]
        pub fn open_log_file(path: &str) -> std::io::Result<Child> {
            Command::new("xdg-open").arg(path).spawn()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        pub fn open_log_file(_path: &str) -> std::io::Result<Child> {
            Err(std::io::Error::other("open_log_file: unsupported platform"))
        }

        #[cfg(target_os = "macos")]
        pub fn stop_daemon_service() -> std::io::Result<Child> {
            let uid = nix::unistd::getuid().as_raw();
            let target = format!("gui/{uid}/is.kyr.kyrisd");
            Command::new("launchctl").args(["bootout", &target]).spawn()
        }
        #[cfg(target_os = "linux")]
        pub fn stop_daemon_service() -> std::io::Result<Child> {
            Command::new("systemctl")
                .args(["--user", "stop", "kyrisd"])
                .spawn()
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        pub fn stop_daemon_service() -> std::io::Result<Child> {
            Err(std::io::Error::other(
                "stop_daemon_service: unsupported platform",
            ))
        }
    }

    fn continue_routing() {
        if let Err(e) = Command::new("kyris").arg("continue").spawn() {
            tracing::warn!(error = %e, "failed to invoke `kyris continue`");
        }
    }

    fn open_logs() {
        let path = kyris_core::paths::stderr_log_path();
        let path_str = path.to_string_lossy();
        if let Err(e) = platform::open_log_file(&path_str) {
            tracing::warn!(error = %e, path = %path_str, "failed to open logs");
        }
    }

    fn quit_daemon() {
        if let Err(e) = platform::stop_daemon_service() {
            tracing::warn!(error = %e, "failed to stop kyrisd service");
        }
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn testDegradedIconRgbaLengthMatches() {
            assert_eq!(degraded_icon_rgba().len(), TRAY_ICON_RGBA.len());
        }

        #[test]
        fn testTrayIconPixelSizeIsDoubleLogicalPts() {
            // @2x invariant: pixel buffer must be exactly 2× the logical point size.
            // Both constants are small (literal-sized), so f64 conversion is exact and
            // exact float equality is the contract being asserted.
            #[allow(clippy::cast_precision_loss, clippy::float_cmp)]
            let lhs = TRAY_ICON_PIXEL_SIZE as f64;
            let rhs = TRAY_ICON_LOGICAL_PTS * 2.0;
            #[allow(clippy::float_cmp)]
            let equal = lhs == rhs;
            assert!(
                equal,
                "pixel size must be 2× logical points for @2x Retina rendering ({lhs} vs {rhs})"
            );
        }

        #[test]
        fn testDegradedIconDiffersFromNormal() {
            // The amber overlay must change at least one byte for a non-transparent icon.
            let has_opaque = TRAY_ICON_RGBA.chunks_exact(4).any(|px| px[3] > 0);
            if has_opaque {
                assert_ne!(
                    degraded_icon_rgba().as_slice(),
                    TRAY_ICON_RGBA,
                    "degraded icon should differ from normal"
                );
            }
        }
    }
}

#[cfg(feature = "tray")]
pub use gui::ask_approval;
#[cfg(feature = "tray")]
pub use gui::run_event_loop;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testTrayStateDisplay() {
        assert_eq!(TrayState::Normal.to_string(), "normal");
        assert_eq!(TrayState::Degraded.to_string(), "degraded");
        assert_eq!(
            TrayState::RelayDisconnected.to_string(),
            "relay_disconnected"
        );
    }

    #[test]
    fn testTrayStateLabel() {
        assert!(TrayState::Normal.label().contains('●'));
        assert!(TrayState::Degraded.label().contains('◐'));
        assert!(TrayState::RelayDisconnected.label().contains('○'));
    }

    #[test]
    fn testSetAndGetState() {
        set_state(TrayState::Normal);
        assert_eq!(current_state(), TrayState::Normal);
        set_state(TrayState::Degraded);
        assert_eq!(current_state(), TrayState::Degraded);
        set_state(TrayState::RelayDisconnected);
        assert_eq!(current_state(), TrayState::RelayDisconnected);
        set_state(TrayState::Normal);
    }

    #[test]
    fn testTrayStateStatusLabel() {
        assert!(TrayState::Normal.status_label().contains("Running"));
        assert!(TrayState::Degraded.status_label().contains("Degraded"));
        assert!(
            TrayState::RelayDisconnected
                .status_label()
                .contains("Relay")
        );
    }

    #[test]
    fn testTrayStateTooltipDistinctPerState() {
        let normal = TrayState::Normal.tooltip();
        let degraded = TrayState::Degraded.tooltip();
        let relay = TrayState::RelayDisconnected.tooltip();
        assert_ne!(normal, degraded);
        assert_ne!(normal, relay);
        assert_ne!(degraded, relay);
    }

    #[test]
    fn testSetCircuitBreakerTrippedIsObservable() {
        set_circuit_breaker_tripped(true);
        assert!(CIRCUIT_BREAKER_TRIPPED.load(Ordering::Relaxed));
        set_circuit_breaker_tripped(false);
        assert!(!CIRCUIT_BREAKER_TRIPPED.load(Ordering::Relaxed));
    }
}
