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
/// Returns one of the string literals `"yes"`, `"no"`, or `"always"`.
/// Must be called from the main thread (asserted via `MainThreadMarker`).
#[cfg(feature = "tray")]
pub fn show_approval_alert(title: &str, body: &str) -> &'static str {
    use core::ffi::c_uchar;
    use objc2::{AnyThread as _, MainThreadMarker};
    use objc2_app_kit::{
        NSAlert, NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSAlertThirdButtonReturn,
        NSApplication, NSBitmapImageRep, NSDeviceRGBColorSpace, NSImage,
    };
    use objc2_foundation::{NSSize, NSString};

    // Reuse the same 44×44 RGBA the tray icon already compiled in.
    const ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
    const PX: isize = 44;

    let mtm = MainThreadMarker::new().expect("must be called from main thread");
    NSApplication::sharedApplication(mtm);

    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(body));
    let yes_btn = alert.addButtonWithTitle(&NSString::from_str("Yes"));
    yes_btn.setKeyEquivalent(&NSString::from_str(""));
    alert.addButtonWithTitle(&NSString::from_str("No"));
    alert.addButtonWithTitle(&NSString::from_str("Always"));

    // Build NSImage from the pre-rasterized RGBA bytes (same data as tray icon).
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
            PX, PX,
            8, 4,
            true,
            false,
            NSDeviceRGBColorSpace,
            PX * 4,
            32,
        )
    };
    if let Some(rep) = rep {
        #[allow(clippy::cast_precision_loss)] // PX is 44; exact in f64
        let image = NSImage::initWithSize(
            NSImage::alloc(),
            NSSize {
                width: PX as f64,
                height: PX as f64,
            },
        );
        image.addRepresentation(&rep);
        unsafe { alert.setIcon(Some(&image)) };
    }

    let response = alert.runModal();
    if response == NSAlertFirstButtonReturn {
        "yes"
    } else if response == NSAlertSecondButtonReturn {
        "no"
    } else if response == NSAlertThirdButtonReturn {
        "always"
    } else {
        // NSAlertErrorReturn (-1) if the sheet couldn't be shown; deny safely.
        tracing::warn!(response = ?response, "unexpected NSAlert response; defaulting to deny");
        "no"
    }
}

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
