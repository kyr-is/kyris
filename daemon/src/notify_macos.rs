// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Modern macOS notifications via `UNUserNotificationCenter`, called
//! in-process from `kyrisd`.
//!
//! Why in-process: macOS's notification daemon (`usernoted`) refuses
//! to register an authorization request from a process that
//! `LaunchServices` doesn't recognize as a foreground-eligible app. A
//! launchctl-loaded bundle (`Kyrisd.app`) qualifies, but a
//! subprocess spawned from it does NOT — child processes inherit
//! kernel-level credentials but not `LaunchServices` identity. We
//! tried a sibling Swift helper (`kyris-notify`); it failed at
//! `requestAuthorization` with `UNErrorDomain code=1` even when
//! invoked by the running daemon. So every UN center call lives
//! here, in `kyrisd`'s own process. See Apple Forums thread 679326.
//!
//! The module is `cfg(target_os = "macos")`-gated; callers in
//! `notify.rs` mirror the gating. Everything is safe to call from
//! any thread — UN center's APIs are documented as thread-safe.

#![cfg(target_os = "macos")]
#![allow(unsafe_code)]

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::Bool;
use objc2_foundation::{NSBundle, NSError, NSString, NSUUID};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
    UNUserNotificationCenter,
};

/// True when the running process is inside a real `.app` bundle.
/// UN center crashes hard (`NSInternalInconsistencyException`) when
/// called from an unbundled process; this check is the gate.
#[must_use]
fn has_bundle_identity() -> bool {
    NSBundle::mainBundle().bundleIdentifier().is_some()
}

/// Daemon-startup permission request. Idempotent at the macOS level
/// — calling `requestAuthorization` when already Authorized, Denied,
/// or Provisional is a silent no-op (no second dialog). Only on
/// `NotDetermined` does the system actually show the prompt.
///
/// We intentionally skip a pre-check via `getNotificationSettings`:
/// that call is async and blocking the main thread on its
/// completion handler inside tao's `Init` handler triggered
/// `Notifications are not allowed for this application` from
/// usernoted — likely because the main run loop couldn't dispatch
/// the GCD completion while we were holding it. Going straight to
/// `requestAuthorization` (which has its own non-blocking handler)
/// avoids the deadlock.
pub fn request_authorization_if_needed() {
    if !has_bundle_identity() {
        tracing::debug!("notifications: no bundle identity (unbundled run)");
        return;
    }

    let center = UNUserNotificationCenter::currentNotificationCenter();
    let options = UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound;

    let handler = RcBlock::new(|granted: Bool, err: *mut NSError| {
        if !err.is_null() {
            let description = unsafe { (*err).localizedDescription() };
            tracing::warn!(
                error = %description.to_string(),
                "notifications: authorization request errored"
            );
        } else if granted.as_bool() {
            tracing::info!("notifications: authorization granted");
        } else {
            tracing::warn!("notifications: authorization denied by user");
        }
    });

    center.requestAuthorizationWithOptions_completionHandler(options, &handler);
    tracing::info!("notifications: authorization request dispatched");
}

/// Show a modal Yes / No / Always approval dialog on the main thread.
/// Returns an [`crate::notify::ApprovalOutcome`] reflecting the user's
/// choice, or `CouldNotShow` if the panel never became visible to the
/// user (occluded, off-active-space, off-screen) within the visibility
/// poll window — callers should treat that as a signal to escalate to
/// another channel rather than a denial.
/// Must be called from the main thread (asserted via `MainThreadMarker`).
///
/// Renders a custom `NSPanel` rather than `NSAlert` because `NSAlert`
/// stacks 3 buttons vertically once the dialog is short — we always
/// want horizontal `[Always] [No] [Yes]` for muscle-memory consistency.
///
/// `code`, when `Some`, is rendered below the body in a scrollable
/// monospaced view with syntect colorization.
///
/// Captures the frontmost app before showing and reactivates it after the
/// modal dismisses. macOS doesn't auto-restore the previous frontmost app
/// when an `Accessory`-policy process (`kyrisd`) transiently activates to
/// display a modal — without this, focus stays stuck on `Kyrisd.app` after
/// the user clicks a button.
#[cfg(feature = "tray")]
pub fn show_approval_alert(
    title: &str,
    body: &str,
    code: Option<&str>,
) -> crate::notify::ApprovalOutcome {
    use crate::notify::ApprovalOutcome;


    // AppKit wire codes for stopModalWithCode:. Kept local — the public
    // API surfaces ApprovalOutcome, never these integers.
    const MODAL_CODE_YES: isize = 1;
    const MODAL_CODE_NO: isize = 2;
    const MODAL_CODE_ALWAYS: isize = 3;
    const MODAL_CODE_COULD_NOT_SHOW: isize = 99;
    use core::ffi::c_uchar;
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{AnyThread as _, MainThreadMarker, MainThreadOnly, msg_send, sel};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationOptions, NSBackingStoreType, NSBezelStyle,
        NSBitmapImageRep, NSBorderType, NSButton, NSDeviceRGBColorSpace, NSFont, NSImage,
        NSImageView, NSPanel, NSScreen, NSScrollView, NSTextField, NSTextView, NSView,
        NSWindowStyleMask, NSWorkspace,
    };
    use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

    const ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
    const ICON_PX: isize = 44;

    // Layout constants. NSView coords are bottom-left origin, so y values
    // count up from the window's bottom edge.
    const PADDING: f64 = 20.0;
    const ICON_SIZE: f64 = 44.0;
    const HEADER_GAP: f64 = 12.0;
    const TITLE_H: f64 = 20.0;
    const TITLE_BODY_GAP: f64 = 4.0;
    const BODY_H: f64 = 18.0;
    const HEADER_CODE_GAP: f64 = 16.0;
    const CODE_BUTTON_GAP: f64 = 16.0;
    const BUTTON_W: f64 = 100.0;
    const BUTTON_H: f64 = 32.0;
    const BUTTON_SPACING: f64 = 10.0;
    const MIN_W: f64 = 460.0;
    const MIN_TEXT_COL_W: f64 = 320.0;

    let mtm = MainThreadMarker::new().expect("must be called from main thread");
    let app = NSApplication::sharedApplication(mtm);

    // --- Code area dimensions ---
    let (screen_w, screen_h) = NSScreen::mainScreen(mtm).map_or((1280.0, 800.0), |s| {
        let f = s.visibleFrame();
        (f.size.width, f.size.height)
    });

    let (code_w, code_h) = if let Some(c) = code {
        const CHAR_WIDTH: f64 = 7.2; // 12pt monospaced advance, empirical
        const LINE_HEIGHT: f64 = 16.0;
        const H_PAD: f64 = 32.0; // scroll bar + bezel + breathing room
        const V_PAD: f64 = 12.0;
        const MIN_H: f64 = 56.0;
        const MIN_CODE_W: f64 = 380.0;

        let max_w = (screen_w * 0.70).max(MIN_CODE_W);
        let max_h = (screen_h * 0.65).max(MIN_H);

        #[allow(clippy::cast_precision_loss)] // line lengths stay modest
        let longest = c.lines().map(str::len).max().unwrap_or(0) as f64;
        let w = ((longest * CHAR_WIDTH) + H_PAD).clamp(MIN_CODE_W, max_w);

        #[allow(clippy::cast_precision_loss)] // line counts stay modest
        let lines = c.lines().count().max(1) as f64;
        let h = ((lines * LINE_HEIGHT) + V_PAD).clamp(MIN_H, max_h);
        (w, h)
    } else {
        (0.0, 0.0)
    };

    // --- Window dimensions ---
    // Width is whichever is wider: the code area + padding, or the
    // header (icon + text column) + padding. Clamped to MIN_W so a
    // bare "Allow X?" without a code block doesn't render a tiny panel.
    let header_min_w = PADDING + ICON_SIZE + HEADER_GAP + MIN_TEXT_COL_W + PADDING;
    let code_min_w = code_w + PADDING * 2.0;
    let content_w = code_min_w.max(header_min_w).max(MIN_W);

    let has_body = !body.is_empty();
    let text_block_h = if has_body {
        TITLE_H + TITLE_BODY_GAP + BODY_H
    } else {
        TITLE_H
    };
    let header_h = ICON_SIZE.max(text_block_h);
    let code_block_h = if code.is_some() {
        code_h + HEADER_CODE_GAP
    } else {
        0.0
    };
    let content_h = PADDING + header_h + code_block_h + CODE_BUTTON_GAP + BUTTON_H + PADDING;

    // --- Build panel ---
    let rect = NSRect {
        origin: NSPoint { x: 0.0, y: 0.0 },
        size: NSSize {
            width: content_w,
            height: content_h,
        },
    };
    let style_mask = NSWindowStyleMask::Titled;
    let panel: Retained<NSPanel> = unsafe {
        msg_send![
            NSPanel::alloc(mtm),
            initWithContentRect: rect,
            styleMask: style_mask,
            backing: NSBackingStoreType::Buffered,
            defer: false,
        ]
    };
    panel.setTitle(&NSString::from_str("Kyris"));
    unsafe { panel.setReleasedWhenClosed(false) };
    // Default for NSPanel is true, which can starve key equivalents
    // (Return/Escape) of keyboard events even after runModal makes the
    // window key. Forcing false guarantees the panel receives keystrokes.
    panel.setBecomesKeyOnlyIfNeeded(false);
    panel.center();
    let content_view: Retained<NSView> = panel.contentView().expect("contentView");

    // --- Icon ---
    let icon_y = content_h - PADDING - ICON_SIZE;
    let icon_rect = NSRect {
        origin: NSPoint {
            x: PADDING,
            y: icon_y,
        },
        size: NSSize {
            width: ICON_SIZE,
            height: ICON_SIZE,
        },
    };
    let mut rgba = ICON_RGBA.to_vec();
    let rep = unsafe {
        let mut planes = [
            rgba.as_mut_ptr().cast::<c_uchar>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ];
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(),
            planes.as_mut_ptr(),
            ICON_PX, ICON_PX,
            8, 4,
            true,
            false,
            NSDeviceRGBColorSpace,
            ICON_PX * 4,
            32,
        )
    };
    if let Some(rep) = rep {
        let image = NSImage::initWithSize(
            NSImage::alloc(),
            NSSize {
                width: ICON_SIZE,
                height: ICON_SIZE,
            },
        );
        image.addRepresentation(&rep);
        let image_view = NSImageView::new(mtm);
        image_view.setFrame(icon_rect);
        image_view.setImage(Some(&image));
        content_view.addSubview(&image_view);
    }

    // --- Title label ---
    let text_col_x = PADDING + ICON_SIZE + HEADER_GAP;
    let text_col_w = content_w - text_col_x - PADDING;
    let title_y = content_h - PADDING - TITLE_H;
    let title_rect = NSRect {
        origin: NSPoint {
            x: text_col_x,
            y: title_y,
        },
        size: NSSize {
            width: text_col_w,
            height: TITLE_H,
        },
    };
    let title_label = NSTextField::labelWithString(&NSString::from_str(title), mtm);
    title_label.setFrame(title_rect);
    title_label.setFont(Some(&NSFont::boldSystemFontOfSize(13.0)));
    content_view.addSubview(&title_label);

    // --- Body label (skipped when caller passes an empty string) ---
    if has_body {
        let body_y = title_y - TITLE_BODY_GAP - BODY_H;
        let body_rect = NSRect {
            origin: NSPoint {
                x: text_col_x,
                y: body_y,
            },
            size: NSSize {
                width: text_col_w,
                height: BODY_H,
            },
        };
        let body_label = NSTextField::labelWithString(&NSString::from_str(body), mtm);
        body_label.setFrame(body_rect);
        body_label.setFont(Some(&NSFont::systemFontOfSize(12.0)));
        content_view.addSubview(&body_label);
    }

    // --- Code area ---
    if let Some(code_text) = code {
        // Stretch the code block to fill the available width — when the
        // header sets the panel width (server name longer than the code
        // line), centering the narrow code looks like an alignment bug.
        let code_y = PADDING + BUTTON_H + CODE_BUTTON_GAP;
        let code_x = PADDING;
        let code_render_w = content_w - PADDING * 2.0;
        let code_rect = NSRect {
            origin: NSPoint {
                x: code_x,
                y: code_y,
            },
            size: NSSize {
                width: code_render_w,
                height: code_h,
            },
        };
        let _ = code_w; // sizing input only; rendered width is code_render_w

        let scroll = NSScrollView::initWithFrame(NSScrollView::alloc(mtm), code_rect);
        scroll.setHasVerticalScroller(true);
        scroll.setHasHorizontalScroller(false);
        scroll.setAutohidesScrollers(true);
        scroll.setBorderType(NSBorderType::BezelBorder);

        let text_view = NSTextView::initWithFrame(NSTextView::alloc(mtm), code_rect);
        text_view.setEditable(false);
        text_view.setSelectable(true);
        text_view.setDrawsBackground(true);
        // Rich text MUST be on for per-range attributed-string colors to
        // render — syntect's per-token coloring goes through addAttribute_
        // value_range on the text storage's attributed string, which is
        // ignored when the view is in plain-text mode.
        text_view.setRichText(true);

        let dark = crate::notify_macos_highlight::dark_mode_active(mtm);
        let attr = crate::notify_macos_highlight::build_attributed_string(code_text, dark, mtm);
        if let Some(storage) = unsafe { text_view.textStorage() } {
            storage.setAttributedString(&attr);
        } else {
            // Defensive fallback: NSTextView always vends a textStorage in
            // practice, but if it somehow doesn't we show plain monospace.
            let mono = NSFont::monospacedSystemFontOfSize_weight(12.0, 0.0);
            text_view.setFont(Some(&mono));
            let ns = NSString::from_str(code_text);
            text_view.setString(&ns);
        }
        scroll.setDocumentView(Some(&text_view));
        content_view.addSubview(&scroll);
    }

    // --- Buttons: [Always]   [No] [Yes]  (Yes is default, rightmost) ---
    let handler = ApprovalAction::new(mtm);
    let target: &AnyObject = &handler;

    let row_y = PADDING;
    let yes_x = content_w - PADDING - BUTTON_W;
    let no_x = yes_x - BUTTON_SPACING - BUTTON_W;
    let always_x = no_x - BUTTON_SPACING - BUTTON_W;

    let make_button = |label: &str, x: f64, tag: isize, key_eq: &str| -> Retained<NSButton> {
        let btn = unsafe {
            NSButton::buttonWithTitle_target_action(
                &NSString::from_str(label),
                Some(target),
                Some(sel!(decide:)),
                mtm,
            )
        };
        btn.setFrame(NSRect {
            origin: NSPoint { x, y: row_y },
            size: NSSize {
                width: BUTTON_W,
                height: BUTTON_H,
            },
        });
        btn.setBezelStyle(NSBezelStyle::Push);
        btn.setTag(tag);
        if !key_eq.is_empty() {
            btn.setKeyEquivalent(&NSString::from_str(key_eq));
        }
        btn
    };

    // Tag = MODAL_CODE_*; ApprovalAction calls stopModalWithCode:tag.
    let yes_btn = make_button("Yes", yes_x, MODAL_CODE_YES, "\r"); // Return: default
    let no_btn = make_button("No", no_x, MODAL_CODE_NO, "\u{1b}"); // Escape: cancel
    let always_btn = make_button("Always", always_x, MODAL_CODE_ALWAYS, "");
    content_view.addSubview(&yes_btn);
    content_view.addSubview(&no_btn);
    content_view.addSubview(&always_btn);

    // --- Activate, run modal, restore focus ---
    let prev_app = NSWorkspace::sharedWorkspace().frontmostApplication();
    #[allow(clippy::cast_possible_wrap)]
    let my_pid = std::process::id() as i32;

    // Bring kyrisd to the foreground so the panel actually surfaces.
    // Accessory-policy processes don't auto-activate when a window opens.
    #[allow(deprecated)] // activate() requires entitlements we don't ship
    app.activateIgnoringOtherApps(true);

    // Strong-display flags: bump z-order above normal windows, follow the
    // user across Spaces, order-front even if another app didn't relinquish
    // focus. Cheap-strong combo — does NOT change activation policy, so the
    // Dock icon doesn't flash into existence on every prompt (which would
    // be a worse user disruption than the prompt itself).
    const NS_POPUP_MENU_WINDOW_LEVEL: isize = 101;
    const NS_WINDOW_COLLECTION_BEHAVIOR_CAN_JOIN_ALL_SPACES: usize = 1;
    unsafe {
        let _: () = msg_send![&*panel, setLevel: NS_POPUP_MENU_WINDOW_LEVEL];
        let _: () = msg_send![
            &*panel,
            setCollectionBehavior: NS_WINDOW_COLLECTION_BEHAVIOR_CAN_JOIN_ALL_SPACES
        ];
        let _: () = msg_send![&*panel, orderFrontRegardless];
    }

    // Visibility poll: confirm the OS actually displayed the panel to the
    // user before we block on runModal. A panel can be "ordered front"
    // while the user is in a fullscreen app, on another Space, or with
    // the screen off — none of which gets the pixels in front of them.
    // If the panel hasn't passed all four checks (isVisible, isOnActiveSpace,
    // screen != nil, occlusionState contains the Visible bit) within
    // ~500ms, stop the modal with sentinel code 99 so the caller knows
    // the prompt was undeliverable and can fall back to another channel.
    const VISIBILITY_POLL_MAX_MS: u128 = 500;
    let panel_raw: usize = Retained::as_ptr(&panel) as usize;
    let app_raw: usize = Retained::as_ptr(&app) as usize;
    let start_time = std::time::Instant::now();

    let poll_block = block2::RcBlock::new(
        move |timer: std::ptr::NonNull<objc2_foundation::NSTimer>| {
            let panel_ptr = panel_raw as *mut AnyObject;
            let app_ptr = app_raw as *mut AnyObject;
            let visible_to_user = unsafe {
                let visible: bool = msg_send![panel_ptr, isVisible];
                let on_active_space: bool = msg_send![panel_ptr, isOnActiveSpace];
                let screen: *mut AnyObject = msg_send![panel_ptr, screen];
                let occlusion: u64 = msg_send![panel_ptr, occlusionState];
                // NSWindowOcclusionStateVisible = 1 << 1
                let occlusion_visible = (occlusion & 0x2) != 0;
                visible && on_active_space && !screen.is_null() && occlusion_visible
            };
            let elapsed_ms = start_time.elapsed().as_millis();
            if visible_to_user {
                unsafe {
                    let _: () = msg_send![timer.as_ref(), invalidate];
                }
                tracing::info!(
                    target: "kyrisd::approval",
                    elapsed_ms = elapsed_ms as u64,
                    "approval panel visible to user"
                );
            } else if elapsed_ms >= VISIBILITY_POLL_MAX_MS {
                unsafe {
                    let _: () = msg_send![timer.as_ref(), invalidate];
                    let _: () = msg_send![app_ptr, stopModalWithCode: MODAL_CODE_COULD_NOT_SHOW];
                }
                tracing::warn!(
                    target: "kyrisd::approval",
                    "approval panel never became visible — aborting modal"
                );
            }
        },
    );
    let poll_timer = unsafe {
        objc2_foundation::NSTimer::scheduledTimerWithTimeInterval_repeats_block(
            0.05,
            true,
            &poll_block,
        )
    };

    let response: isize = unsafe { msg_send![&*app, runModalForWindow: &*panel] };

    // CRITICAL: invalidate the poll timer before any of the local Retained<>
    // values go out of scope. The timer's block captures the panel pointer
    // as a raw usize; without explicit invalidate, a tick fired after this
    // function returns would dereference freed memory.
    unsafe {
        let _: () = msg_send![&*poll_timer, invalidate];
    }

    panel.orderOut(None);

    if let Some(app) = prev_app
        && app.processIdentifier() != my_pid
    {
        let _ = app.activateWithOptions(NSApplicationActivationOptions::ActivateAllWindows);
    }

    // `handler` and the button Retained<…> values stay in scope until end
    // of function — needed because NSButton holds a *weak* reference to its
    // target, and the buttons themselves are retained by content_view but
    // we don't want any drop-order surprises during a future refactor.
    let _ = (&handler, &yes_btn, &no_btn, &always_btn);

    match response {
        MODAL_CODE_YES => ApprovalOutcome::Yes,
        MODAL_CODE_NO => ApprovalOutcome::No,
        MODAL_CODE_ALWAYS => ApprovalOutcome::Always,
        MODAL_CODE_COULD_NOT_SHOW => ApprovalOutcome::CouldNotShow,
        other => {
            tracing::warn!(
                target: "kyrisd::approval",
                ?other,
                "unexpected modal response; defaulting to No"
            );
            ApprovalOutcome::No
        }
    }
}

// ApprovalAction: an objc target object whose `decide:` selector reads
// the sender NSButton's tag and calls `[NSApp stopModalWithCode:tag]`.
// This is what makes each button dismiss the modal with the right
// decision code. Defined at module scope (not inside the function)
// because `define_class!` registers a global Objective-C class.
#[cfg(feature = "tray")]
mod approval_action {
    use objc2::rc::Retained;
    use objc2::runtime::AnyObject;
    use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send};
    use objc2_app_kit::NSApplication;
    use objc2_foundation::NSObject;

    define_class!(
        #[unsafe(super(NSObject))]
        #[thread_kind = MainThreadOnly]
        #[name = "KyrisApprovalAction"]
        pub(super) struct ApprovalAction;

        impl ApprovalAction {
            #[unsafe(method(decide:))]
            fn decide(&self, sender: Option<&AnyObject>) {
                let mtm = MainThreadMarker::new()
                    .expect("decide: invoked off the main thread");
                let app = NSApplication::sharedApplication(mtm);
                let tag: isize = match sender {
                    Some(s) => unsafe { msg_send![s, tag] },
                    None => 0,
                };
                app.stopModalWithCode(tag);
            }
        }
    );

    impl ApprovalAction {
        pub(super) fn new(mtm: MainThreadMarker) -> Retained<Self> {
            unsafe { msg_send![Self::alloc(mtm), init] }
        }
    }
}

#[cfg(feature = "tray")]
use approval_action::ApprovalAction;

/// Fire-and-forget notification delivery. Returns immediately.
/// Delivery errors surface in the completion handler, which we log
/// at warn level. Callers should treat this as best-effort — the
/// `tracing::info!` line in `notify.rs::send_toast` is the
/// authoritative record that the toast fired.
pub fn post(title: &str, body: &str) {
    if !has_bundle_identity() {
        tracing::debug!("notifications: no bundle identity (unbundled run)");
        return;
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));

    let identifier: Retained<NSString> = NSUUID::new().UUIDString();
    let request =
        UNNotificationRequest::requestWithIdentifier_content_trigger(&identifier, &content, None);

    let handler = RcBlock::new(|err: *mut NSError| {
        if !err.is_null() {
            let description = unsafe { (*err).localizedDescription() };
            tracing::warn!(
                error = %description.to_string(),
                "UN notification delivery failed"
            );
        }
    });

    center.addNotificationRequest_withCompletionHandler(&request, Some(&handler));
}
