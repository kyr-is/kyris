// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Menu-bar (tray) icon for `kyrisd`.
//!
//! The tray is intentionally a passive indicator: no clickable menu, no
//! tooltip, no per-action affordances. Subsystems report problems to it
//! via [`report_issue`] / [`clear_issue`]; when the issue set is
//! non-empty the icon shows a warning overlay, otherwise the normal
//! kyris template glyph. All actionable surfaces (logs, doctor,
//! continue, disable/enable, uninstall) live in the `kyris` CLI.
//!
//! The issue-set API + helper accessors are compiled unconditionally
//! so callers in `server.rs`, `reconcile_watcher.rs`, and
//! `sync/daemon_sync.rs` can push status updates without
//! cfg-attribute noise. The actual GUI plumbing is gated behind
//! `--features tray` (on by default) and split by target OS:
//!
//!   macOS   — native objc2: `NSApplication` + `NSStatusItem`
//!   Windows — stub (Win32 `Shell_NotifyIcon` planned for phase 2)
//!   Linux   — stub (GTK4 / ksni planned for phase 2)
//!
//! Issue state is mutated from tokio tasks (e.g. the health poller)
//! and read by a 250ms `NSTimer` on the main thread. The daemon's main
//! thread calls [`run_event_loop`] while Tokio runs on a background
//! thread; see `kyrisd::main`.
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Subsystem -> human-readable reason. Empty map means "all good"; a
/// non-empty map means the tray shows the warning overlay. Keys are
/// `&'static str` so callers don't allocate on every report; values
/// are owned strings so a subsystem can describe its current failure
/// in detail (e.g. "socket not accepting connections at /foo/bar").
static ISSUES: Mutex<BTreeMap<&'static str, String>> = Mutex::new(BTreeMap::new());

/// `true` when agentpactd's effective user policy is `mode: log` —
/// commands are recorded but not mediated. The tray paints a red
/// horizontal bar across the kyris glyph so the non-enforcing state
/// is visible at all times. Updated from kyrisd's policy poller (see
/// `server::policy_mode_poller`); read every tray refresh tick.
static LOG_MODE: AtomicBool = AtomicBool::new(false);

/// Push the current "is the user policy in log mode?" state. Called by
/// kyrisd's policy poller after every `~/.config/agentpact/policy/pact.yaml`
/// read. Idempotent; the tray refresh picks up changes on its next tick.
pub fn set_log_mode(active: bool) {
    LOG_MODE.store(active, Ordering::Relaxed);
}

/// Whether the tray is currently representing log-mode.
#[must_use]
pub fn log_mode() -> bool {
    LOG_MODE.load(Ordering::Relaxed)
}

/// Record a problem from a subsystem. Idempotent — repeated calls with
/// the same key just update the reason. Cleared by [`clear_issue`].
pub fn report_issue(key: &'static str, reason: impl Into<String>) {
    let mut issues = ISSUES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    issues.insert(key, reason.into());
}

/// Clear a previously-reported issue. No-op if the key isn't present
/// — every health poller can call `clear_issue` unconditionally after
/// a successful probe.
pub fn clear_issue(key: &'static str) {
    let mut issues = ISSUES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    issues.remove(key);
}

/// Snapshot of the current issue set, suitable for `kyris doctor`
/// rendering. Returns key/reason pairs in deterministic order.
#[must_use]
pub fn list_issues() -> Vec<(&'static str, String)> {
    let issues = ISSUES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    issues.iter().map(|(k, v)| (*k, v.clone())).collect()
}

/// Count of currently-reported issues. Used by the tray refresh to
/// decide between normal vs. warning icon.
#[must_use]
pub fn issue_count() -> usize {
    let issues = ISSUES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    issues.len()
}

// --- Feature-gated GUI plumbing -------------------------------------------
//
// The native icon + event loop are only compiled when the `tray` feature is
// enabled. With the feature off the daemon updates the issue set for free but
// no UI is drawn and no main-thread run loop is needed.
//
// Platform split:
//   macOS   — native objc2: NSApplication + NSStatusItem
//   Windows — stub (Win32 Shell_NotifyIcon planned for phase 2)
//   Linux   — stub (GTK4 / ksni planned for phase 2)

// ---------------------------------------------------------------------------
// Windows stub
// ---------------------------------------------------------------------------

#[cfg(all(feature = "tray", target_os = "windows"))]
mod gui {
    use std::thread::JoinHandle;

    /// Ask the user to approve an action.
    /// TODO: Windows notification/dialog. Until one exists, fail safe with
    /// `CouldNotShow` (leave the request pending) — never auto-approve.
    pub async fn ask_approval(
        _title: &str,
        _body: &str,
        _code: Option<&str>,
        _allow_always: bool,
    ) -> crate::notify::ApprovalOutcome {
        crate::notify::ApprovalOutcome::CouldNotShow
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
    /// TODO: GTK4 / freedesktop dialog. Until one exists, fail safe with
    /// `CouldNotShow` (leave the request pending) — never auto-approve.
    pub async fn ask_approval(
        _title: &str,
        _body: &str,
        _code: Option<&str>,
        _allow_always: bool,
    ) -> crate::notify::ApprovalOutcome {
        crate::notify::ApprovalOutcome::CouldNotShow
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
    use super::{issue_count, log_mode};
    use block2::RcBlock;
    use core::ffi::c_uchar;
    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, Bool};
    // AnyThread as _ brings the `alloc()` method into scope for AnyThread classes
    // (NSBitmapImageRep, NSImage).  MainThreadOnly brings `alloc(mtm)` for
    // MainThreadOnly classes (e.g. NSStatusItem).
    use objc2::{AnyThread as _, MainThreadMarker, MainThreadOnly, Message as _, msg_send};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSBitmapImageRep, NSColor,
        NSCompositingOperation, NSDeviceRGBColorSpace, NSImage, NSImageSymbolConfiguration,
        NSStatusBar,
    };
    use objc2_foundation::{NSObject, NSPoint, NSRect, NSSize, NSString, NSTimer};
    use std::cell::RefCell;
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    const TRAY_ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
    // Pixel dimensions of the rasterized RGBA buffer.
    const TRAY_ICON_PIXEL_SIZE: isize = 44;
    // Logical point size for NSImage — half the pixel size so macOS treats
    // the buffer as @2x Retina representation of a 22-point icon (the menu
    // bar's actual logical point size).
    const TRAY_ICON_LOGICAL_PTS: f64 = 22.0;

    // -----------------------------------------------------------------------
    // ObjC class: drives the approval popup queue
    //
    // Held on the heap so timer callbacks can borrow it across iterations
    // of the run loop.  Approvals are dispatched onto the main thread by
    // `ask_approval`; the popup itself runs inline in this class's method.
    // -----------------------------------------------------------------------

    objc2::define_class!(
        // SAFETY: NSObject has no subclassing requirements; this class
        // has no Drop impl that would conflict with the generated dealloc.
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        struct TimerCallbackTarget;

        impl TimerCallbackTarget {
            #[unsafe(method(refreshTick:))]
            fn refresh_tick(&self, _: Option<&AnyObject>) {
                let mtm = MainThreadMarker::new()
                    .expect("refreshTick: must run on main thread");
                refresh_snapshot(mtm);
            }
        }
    );

    // -----------------------------------------------------------------------
    // Cross-thread work queue — background threads push `FnOnce` closures
    // here; the 250ms `NSTimer` drains them on the main thread.
    // `wake_main_run_loop()` interrupts the run-loop wait so the drain
    // happens within one quantum instead of at the next 250ms boundary.
    //
    // Why closures instead of (data, sender) tuples: ask_approval's
    // result channel is `tokio::sync::oneshot`. When a test runtime
    // tears down, the sender goes out of scope, the closure is dropped,
    // and `rx.await` resolves to Err → CouldNotShow. With a blocking
    // `mpsc::Receiver::recv()` + spawn_blocking, the runtime would hang
    // on shutdown waiting for the blocking task — observed as
    // `testEndToEndApprovalReturnsApproved` hanging in tokio's
    // BlockingPool::shutdown.
    // -----------------------------------------------------------------------

    static PENDING_MAIN_WORK: Mutex<Vec<Box<dyn FnOnce() + Send>>> = Mutex::new(Vec::new());

    fn push_main_work(f: impl FnOnce() + Send + 'static) {
        PENDING_MAIN_WORK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Box::new(f));
    }

    fn drain_main_work() {
        let work: Vec<_> = PENDING_MAIN_WORK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
            .collect();
        for f in work {
            f();
        }
    }

    /// Push a `CFRunLoopWakeUp` on the main run loop so the next timer
    /// tick fires immediately rather than waiting up to 250ms.
    fn wake_main_run_loop() {
        unsafe extern "C" {
            fn CFRunLoopGetMain() -> *mut std::ffi::c_void;
            fn CFRunLoopWakeUp(rl: *mut std::ffi::c_void);
        }
        unsafe { CFRunLoopWakeUp(CFRunLoopGetMain()) };
    }

    // -----------------------------------------------------------------------
    // Snapshot — what the tray refresh cares about reading
    // -----------------------------------------------------------------------

    #[derive(PartialEq, Eq, Clone, Copy)]
    struct Snapshot {
        has_issues: bool,
        log_mode: bool,
    }

    impl Snapshot {
        fn read() -> Self {
            Self {
                has_issues: issue_count() > 0,
                log_mode: log_mode(),
            }
        }
    }

    // -----------------------------------------------------------------------
    // Persistent UI state — thread_local because NSStatusItem is
    // MainThreadOnly and cannot be stored in a Mutex (not Send/Sync). The
    // timer callback and all AppKit calls are on the main thread, so
    // RefCell gives safe interior mutability here.
    // -----------------------------------------------------------------------

    struct TrayUi {
        status_item: Retained<objc2_app_kit::NSStatusItem>,
        normal_image: Retained<NSImage>,
        warning_image: Retained<NSImage>,
        logmode_image: Retained<NSImage>,
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
    // Public API
    // -----------------------------------------------------------------------

    /// Dispatch an `NSAlert` approval dialog to the main thread and await
    /// the user's response. The work queue delivers the call within 250ms
    /// (next timer tick); `wake_main_run_loop` reduces that to the next
    /// run-loop iteration. Returns `CouldNotShow` if the channel is dropped
    /// (sender panicked / main run loop ended), so the caller can route to
    /// another channel instead of treating the silence as a denial.
    pub async fn ask_approval(
        title: &str,
        body: &str,
        code: Option<&str>,
        allow_always: bool,
    ) -> crate::notify::ApprovalOutcome {
        let (tx, rx) = tokio::sync::oneshot::channel::<crate::notify::ApprovalOutcome>();
        let title = title.to_string();
        let body = body.to_string();
        let code = code.map(str::to_string);
        push_main_work(move || {
            let result = crate::notify_macos::show_approval_alert(
                &title,
                &body,
                code.as_deref(),
                allow_always,
            );
            let _ = tx.send(result);
        });
        wake_main_run_loop();
        // Channel drop → CouldNotShow rather than a silent Yes. Tests
        // that shut down the tokio runtime without a main loop will
        // drop the sender; `rx.await` resolves to Err and we return a
        // safe sentinel — no hang.
        rx.await
            .unwrap_or(crate::notify::ApprovalOutcome::CouldNotShow)
    }

    /// Run the macOS event loop. Owns the main thread until `NSApp run`
    /// returns (it doesn't, except via `NSApp terminate:`); the tokio
    /// thread is joined when launchd sends SIGTERM and the tray code
    /// exits via `process::exit`.
    pub fn run_event_loop(_tokio_handle: JoinHandle<()>) -> ! {
        let mtm = MainThreadMarker::new()
            .expect("run_event_loop must be called from the main thread on macOS");
        // Bring the app to an accessory state so the daemon can host an
        // NSStatusItem without claiming a Dock icon.
        let app = NSApplication::sharedApplication(mtm);
        // Accessory: host an NSStatusItem without claiming a Dock icon. Use the
        // safe typed binding rather than a raw `msg_send!` — `setActivationPolicy:`
        // returns BOOL, and the old `let _: () = msg_send![…]` mistyped that as void,
        // which objc2's debug-build return-type verification rejects (a startup panic
        // when run directly). The safe binding's `-> bool` return is compiler-checked.
        let _ = app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
        TRAY_UI.with(|cell| {
            *cell.borrow_mut() = Some(build_tray_ui(mtm));
        });

        // Periodic refresh: drain the approval queue and paint any tray
        // changes. 250ms balances responsiveness vs CPU.
        let target: Retained<TimerCallbackTarget> =
            unsafe { msg_send![TimerCallbackTarget::alloc(mtm), init] };
        let interval = 0.25_f64;
        unsafe {
            let _ = NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
                interval,
                &target,
                objc2::sel!(refreshTick:),
                None,
                true,
            );
        }

        app.run();
        std::process::exit(0);
    }

    // -----------------------------------------------------------------------
    // Build the tray icon
    // -----------------------------------------------------------------------

    fn build_tray_ui(mtm: MainThreadMarker) -> TrayUi {
        // NSStatusItem with NO menu. The tray is a passive indicator —
        // clicking it does nothing. All actions live in the `kyris` CLI.
        let status_bar = NSStatusBar::systemStatusBar();
        // NSVariableStatusItemLength = -1.0
        let status_item = status_bar.statusItemWithLength(-1.0);

        let normal_image =
            build_normal_image().expect("kyris icon RGBA failed to materialize as NSImage");
        // Primary path: theme-aware overlay composite. Falls back to
        // the static amber recolor if the SF Symbol isn't available
        // (pre-macOS-11 — vanishingly rare on the current target).
        let warning_image = build_warning_image(&normal_image)
            .or_else(build_warning_image_fallback)
            .expect("warning icon failed to materialize as NSImage");
        let logmode_image = build_logmode_image(&normal_image);

        // Initial state: assume healthy. The first refresh tick will
        // correct if the issue set is already populated.
        apply_icon(&status_item, mtm, &normal_image);

        TrayUi {
            status_item,
            normal_image,
            warning_image,
            logmode_image,
            last_snapshot: Snapshot::read(),
            needs_initial_paint: true,
        }
    }

    // -----------------------------------------------------------------------
    // Snapshot refresh — called from the 250ms NSTimer
    // -----------------------------------------------------------------------

    fn refresh_snapshot(mtm: MainThreadMarker) {
        // Drain any FnOnce closures queued by background threads
        // (approval popups, etc.) on the main thread first so prompts
        // surface promptly.
        drain_main_work();

        TRAY_UI.with(|cell| {
            let mut opt = cell.borrow_mut();
            let Some(ui) = opt.as_mut() else { return };
            let now = Snapshot::read();
            if now == ui.last_snapshot && !ui.needs_initial_paint {
                return;
            }
            ui.needs_initial_paint = false;

            // Precedence: log mode (durable state) > issues (actionable) >
            // normal. Log mode wins outright: when the user has run
            // `kyris disable`, the daemon is observe-only and not
            // mediating anything, so there is nothing actionable to
            // alarm about — overlaying a warning would contradict the
            // "disabled" signal the user explicitly asked for. Issues
            // still win over normal when enforcing.
            let image = if now.log_mode {
                &ui.logmode_image
            } else if now.has_issues {
                &ui.warning_image
            } else {
                &ui.normal_image
            };
            apply_icon(&ui.status_item, mtm, image);

            ui.last_snapshot = now;
        });
    }

    // -----------------------------------------------------------------------
    // Icon helpers
    // -----------------------------------------------------------------------

    /// Set the status item's image. Splitting this from the build path
    /// keeps the refresh tick cheap — no `NSImage` allocation per tick.
    fn apply_icon(
        status_item: &objc2_app_kit::NSStatusItem,
        mtm: MainThreadMarker,
        image: &NSImage,
    ) {
        if let Some(btn) = status_item.button(mtm) {
            unsafe {
                let _: () = msg_send![&*btn, setImage: image];
            }
        }
    }

    /// Normal (healthy) icon: existing kyris RGBA, marked as a template
    /// so macOS auto-tints to match menu-bar appearance.
    fn build_normal_image() -> Option<Retained<NSImage>> {
        let image = build_ns_image(TRAY_ICON_RGBA, TRAY_ICON_PIXEL_SIZE, TRAY_ICON_LOGICAL_PTS)?;
        unsafe {
            let _: () = msg_send![&*image, setTemplate: true];
        }
        Some(image)
    }

    /// Warning icon: a true overlay composite drawn at render time so
    /// it stays theme-aware.
    ///
    /// Three layers, drawn into a 22×22 `NSImage` via
    /// `imageWithSize:flipped:drawingHandler:` (which re-runs the block
    /// every time the image is composited to a context — so
    /// `NSColor.labelColor` always reflects the *current* menu-bar
    /// appearance):
    ///
    ///   1. Fill the rect with `labelColor` (white on dark mode, black
    ///      on light mode — the right "tint" for menu-bar glyphs).
    ///   2. Draw the kyris template with `DestinationIn` compositing —
    ///      this keeps the labelColor only where the kyris A has
    ///      pixels, effectively tinting the glyph.
    ///   3. Draw the multicolor SF Symbol `exclamationmark.triangle.fill`
    ///      in the bottom-right corner with `SourceOver`. The symbol
    ///      renders in its canonical colors (yellow + black) regardless
    ///      of the menu-bar theme — exactly what a warning glyph should
    ///      do.
    ///
    /// Returns `None` if the SF Symbol API call fails (e.g. running on
    /// pre-macOS-11 where the symbol name doesn't resolve). The caller
    /// falls back to the amber recolor in that case.
    fn build_warning_image(normal_template: &NSImage) -> Option<Retained<NSImage>> {
        let symbol = build_warning_symbol()?;
        let base = normal_template.retain();
        let size = NSSize {
            width: TRAY_ICON_LOGICAL_PTS,
            height: TRAY_ICON_LOGICAL_PTS,
        };

        // The drawing handler must be `'static + Fn` — captured values
        // (base + symbol) are `Retained<NSImage>` clones, ref-counted so
        // the originals stay alive as long as the block does. Block is
        // re-invoked on every draw — labelColor is sampled fresh each
        // time, so the composite tracks dark/light mode automatically.
        let block = RcBlock::new(move |rect: NSRect| -> Bool {
            unsafe {
                // 1. Fill rect with labelColor (theme-aware).
                let label_color = NSColor::labelColor();
                label_color.set();
                NSRectFill(rect);

                // 2. Mask: keep the fill only where the kyris glyph has
                //    pixels. Destination-in compositing intersects the
                //    existing content with the new image's alpha.
                base.drawInRect_fromRect_operation_fraction(
                    rect,
                    NSRect::ZERO,
                    NSCompositingOperation::DestinationIn,
                    1.0,
                );

                // 3. Overlay: multicolor warning glyph in the
                //    bottom-right corner at ~55% size.
                let badge_size = rect.size.width * 0.6;
                let badge_rect = NSRect {
                    origin: NSPoint {
                        x: rect.size.width - badge_size,
                        y: 0.0,
                    },
                    size: NSSize {
                        width: badge_size,
                        height: badge_size,
                    },
                };
                symbol.drawInRect_fromRect_operation_fraction(
                    badge_rect,
                    NSRect::ZERO,
                    NSCompositingOperation::SourceOver,
                    1.0,
                );
            }
            Bool::YES
        });

        let composite = NSImage::imageWithSize_flipped_drawingHandler(size, false, &block);
        // NOT a template — the multicolor SF Symbol must render in its
        // own palette, not be auto-tinted to one color by macOS.
        unsafe {
            let _: () = msg_send![&*composite, setTemplate: false];
        }
        Some(composite)
    }

    /// Resolve the multicolor warning SF Symbol. Returns `None` on
    /// older macOS where the API or the symbol name doesn't exist —
    /// callers should fall back to the recolored RGBA.
    fn build_warning_symbol() -> Option<Retained<NSImage>> {
        let name = NSString::from_str("exclamationmark.triangle.fill");
        let accessibility = NSString::from_str("warning");
        let base = NSImage::imageWithSystemSymbolName_accessibilityDescription(
            &name,
            Some(&accessibility),
        )?;
        // configurationPreferringMulticolor is macOS 12+. If the call
        // returns a usable configuration, request multicolor rendering;
        // otherwise fall back to whatever the system gives us (still a
        // valid symbol image, just monochrome).
        let multicolor = NSImageSymbolConfiguration::configurationPreferringMulticolor();
        Some(
            base.imageWithSymbolConfiguration(&multicolor)
                .unwrap_or(base),
        )
    }

    /// Log-mode icon: kyris glyph (theme-tinted) with a long red
    /// horizontal bar drawn through the vertical center. Signals
    /// "agentpactd is auditing but not enforcing" — commands run
    /// unmediated until the user flips the user policy from
    /// `mode: log` to `mode: enforce`.
    ///
    /// Drawn at render time (`imageWithSize:flipped:drawingHandler:`)
    /// for the same theme-awareness reason as the warning composite:
    /// the labelColor mask tracks dark/light mode automatically. The
    /// red bar uses `systemRedColor`, which macOS desaturates slightly
    /// in dark mode on its own.
    fn build_logmode_image(normal_template: &NSImage) -> Retained<NSImage> {
        let base = normal_template.retain();
        let size = NSSize {
            width: TRAY_ICON_LOGICAL_PTS,
            height: TRAY_ICON_LOGICAL_PTS,
        };

        // Bar geometry: full-width, ~2.5pt thick, vertically centered.
        // 2.5pt at 22pt logical is the smallest stroke that remains
        // visible at @2x without being heavy. Centering uses the icon
        // mid-line (11pt) ± half thickness.
        let bar_thickness = 2.5_f64;
        let bar_y = (TRAY_ICON_LOGICAL_PTS - bar_thickness) / 2.0;
        let bar_rect = NSRect {
            origin: NSPoint { x: 0.0, y: bar_y },
            size: NSSize {
                width: TRAY_ICON_LOGICAL_PTS,
                height: bar_thickness,
            },
        };

        let block = RcBlock::new(move |rect: NSRect| -> Bool {
            unsafe {
                // 1. Theme-aware tint mask for the kyris glyph.
                let label_color = NSColor::labelColor();
                label_color.set();
                NSRectFill(rect);
                base.drawInRect_fromRect_operation_fraction(
                    rect,
                    NSRect::ZERO,
                    NSCompositingOperation::DestinationIn,
                    1.0,
                );

                // 2. Red horizontal bar drawn on top with SourceOver.
                //    systemRedColor adapts slightly in dark mode; no
                //    need for a custom dark-mode variant.
                let red = NSColor::systemRedColor();
                red.set();
                NSRectFill(bar_rect);
            }
            Bool::YES
        });

        let composite = NSImage::imageWithSize_flipped_drawingHandler(size, false, &block);
        // NOT a template — the red bar must render as red, not be
        // auto-tinted to a single menu-bar foreground color.
        unsafe {
            let _: () = msg_send![&*composite, setTemplate: false];
        }
        composite
    }

    /// Pre-macOS-11 fallback: the legacy amber recolor. Static (no
    /// theme awareness) but always available since it's pure pixel
    /// math on the existing kyris RGBA.
    fn build_warning_image_fallback() -> Option<Retained<NSImage>> {
        let rgba = degraded_icon_rgba();
        let image = build_ns_image(&rgba, TRAY_ICON_PIXEL_SIZE, TRAY_ICON_LOGICAL_PTS)?;
        unsafe {
            let _: () = msg_send![&*image, setTemplate: false];
        }
        Some(image)
    }

    // AppKit's NSRectFill is a C function (not a method) — declare its
    // C signature so the drawing handler can call it. Safe to use inside
    // a focused drawing context (drawingHandler block runs inside one).
    unsafe extern "C" {
        fn NSRectFill(rect: NSRect);
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
        // Pass `planes = NULL` so NSBitmapImageRep allocates and owns
        // the pixel buffer for its own lifetime, then copy the source
        // RGBA into it. The alternative — handing it a pointer into a
        // Rust-owned Vec — is a use-after-free: NSBitmapImageRep does
        // not copy the bytes (Apple: "the bitmap data must remain
        // valid for the lifetime of the NSBitmapImageRep object").
        let rep = unsafe {
            NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
                NSBitmapImageRep::alloc(),
                std::ptr::null_mut(),
                pixel_size, pixel_size,
                8, 4,
                true, false,
                NSDeviceRGBColorSpace,
                pixel_size * 4,
                32,
            )
        }?;
        unsafe {
            let dst: *mut c_uchar = rep.bitmapData();
            if dst.is_null() {
                return None;
            }
            std::ptr::copy_nonoverlapping(rgba.as_ptr(), dst, rgba.len());
        }
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
    // Tests
    // -----------------------------------------------------------------------

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn testSetActivationPolicyReturnsBool() {
            // Regression for the tray.rs:361 startup panic. `-[NSApplication
            // setActivationPolicy:]` returns BOOL; the old raw `let _: () =
            // msg_send![…]` mistyped the return as void, which objc2's debug-build
            // return-type verification rejects at runtime. run_event_loop now uses
            // the safe typed binding — this compile-time assertion pins its signature
            // to `-> bool`, so a regression to `()` (or an untyped msg_send) won't build.
            // Anonymous `_` pattern — using `_signature` would trip
            // clippy::no_effect_underscore_binding; this is a pure compile-time
            // type check, no value needed.
            let _: fn(
                &objc2_app_kit::NSApplication,
                objc2_app_kit::NSApplicationActivationPolicy,
            ) -> bool = objc2_app_kit::NSApplication::setActivationPolicy;
        }

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

    // Every test in this module mutates the process-global `ISSUES`
    // map. cargo's default test runner parallelizes within a binary,
    // so without serialization tests would race and produce flaky
    // failures (observed pre-fix: a test asserting `listed.len() == 1`
    // saw an unrelated test's key still in the map). The same pattern
    // used in `kyris_core::paths::tests::ENV_LOCK`.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset_issues() {
        let mut issues = ISSUES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        issues.clear();
    }

    /// Acquire the serializing lock + clear the issue set so every
    /// test starts from a known-empty state. Returns the guard so
    /// the lock is held for the lifetime of the test.
    fn isolated() -> std::sync::MutexGuard<'static, ()> {
        let guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        reset_issues();
        guard
    }

    #[test]
    fn testReportAndClearIssue() {
        let _g = isolated();
        assert_eq!(issue_count(), 0);
        report_issue("agentpactd", "socket unreachable");
        assert_eq!(issue_count(), 1);
        let listed = list_issues();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "agentpactd");
        assert_eq!(listed[0].1, "socket unreachable");
        clear_issue("agentpactd");
        assert_eq!(issue_count(), 0);
    }

    #[test]
    fn testIssueSetIsKeyedSoDuplicatesAreUpdates() {
        let _g = isolated();
        report_issue("sync", "first reason");
        report_issue("sync", "updated reason");
        let listed = list_issues();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1, "updated reason");
    }

    #[test]
    fn testListIssuesReturnsDeterministicOrder() {
        let _g = isolated();
        report_issue("zulu", "z");
        report_issue("alpha", "a");
        report_issue("mike", "m");
        let listed = list_issues();
        let keys: Vec<&'static str> = listed.iter().map(|(k, _)| *k).collect();
        assert_eq!(keys, vec!["alpha", "mike", "zulu"]);
    }

    #[test]
    fn testClearIssueIsIdempotent() {
        let _g = isolated();
        clear_issue("nonexistent");
        assert_eq!(issue_count(), 0);
    }
}
