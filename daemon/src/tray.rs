// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! macOS/Linux/Windows menu-bar (tray) icon for `kyrisd`.
//!
//! On macOS, `tray-icon` requires the icon to be created on the main thread
//! and the `AppKit` run loop to be pumped continuously, otherwise the icon
//! never renders. The daemon's main thread therefore calls
//! [`run_event_loop`] (which itself constructs the tray) while Tokio runs
//! on a background thread; see `kyrisd::main`.
use std::sync::atomic::{AtomicU8, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

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
    fn tooltip(self) -> &'static str {
        match self {
            Self::Normal => "Kyris daemon: running",
            Self::Degraded => "Kyris daemon: degraded",
            Self::RelayDisconnected => "Kyris daemon: relay disconnected",
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

const TRAY_ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
const TRAY_ICON_SIZE: u32 = 44;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Run the platform UI event loop on the calling thread until `tokio_handle`
/// finishes. On macOS this constructs the tray icon and pumps the
/// `CFRunLoop`; on other platforms it currently only waits for shutdown.
/// Failures to build the tray icon are logged and the call falls back to
/// waiting on Tokio without a tray.
pub fn run_event_loop(tokio_handle: &JoinHandle<()>) {
    let tray = match build_tray() {
        Ok(tray) => Some(tray),
        Err(e) => {
            tracing::warn!(error = %e, "system tray unavailable");
            None
        }
    };

    let mut last_applied = current_state();
    if let Some(tray) = tray.as_ref() {
        apply_state(tray, last_applied);
    }

    while !tokio_handle.is_finished() {
        pump_platform_once();
        let now = current_state();
        if now != last_applied {
            if let Some(tray) = tray.as_ref() {
                apply_state(tray, now);
            }
            last_applied = now;
        }
    }
}

fn build_tray() -> Result<tray_icon::TrayIcon, String> {
    let icon = build_tray_icon(false).map_err(|e| e.to_string())?;
    // Template mode lets macOS auto-tint the icon for the menu bar's current
    // appearance (white on dark, black on light). The source SVG is a single
    // dark color on transparent, so the alpha channel carries the shape.
    tray_icon::TrayIconBuilder::new()
        .with_tooltip(TrayState::Normal.tooltip())
        .with_icon(icon)
        .with_icon_as_template(true)
        .build()
        .map_err(|e| e.to_string())
}

fn apply_state(tray: &tray_icon::TrayIcon, state: TrayState) {
    if let Err(err) = tray.set_tooltip(Some(state.tooltip())) {
        tracing::warn!(error = %err, "failed to update tray tooltip");
    }
    let degraded = !matches!(state, TrayState::Normal);
    // Template tinting strips color, so disable it for the degraded icon
    // (which encodes status with its amber tint) and re-enable for normal.
    // `set_icon` alone resets the template flag to false on every call —
    // `set_icon_with_as_template` is the atomic API that keeps both in sync.
    match build_tray_icon(degraded) {
        Ok(icon) => {
            if let Err(err) = tray.set_icon_with_as_template(Some(icon), !degraded) {
                tracing::warn!(error = %err, "failed to update tray icon");
            }
        }
        Err(err) => tracing::warn!(error = %err, "failed to rebuild tray icon"),
    }
}

fn pump_platform_once() {
    #[cfg(target_os = "macos")]
    {
        use core_foundation::base::TCFType;
        use core_foundation::string::CFString;

        let default_mode = CFString::new("kCFRunLoopDefaultMode");
        core_foundation::runloop::CFRunLoop::run_in_mode(
            default_mode.as_concrete_TypeRef(),
            POLL_INTERVAL,
            true,
        );
    }

    #[cfg(not(target_os = "macos"))]
    {
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn build_tray_icon(degraded: bool) -> Result<tray_icon::Icon, tray_icon::BadIcon> {
    let rgba = if degraded {
        degraded_icon_rgba()
    } else {
        TRAY_ICON_RGBA.to_vec()
    };
    tray_icon::Icon::from_rgba(rgba, TRAY_ICON_SIZE, TRAY_ICON_SIZE)
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
    fn testBuildTrayIconNormalSucceeds() {
        // The icon must be constructible from the embedded RGBA bytes;
        // mismatched dimensions / corrupted bytes would surface here.
        assert!(build_tray_icon(false).is_ok());
    }

    #[test]
    fn testBuildTrayIconDegradedSucceeds() {
        assert!(build_tray_icon(true).is_ok());
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
    fn testDegradedIconRgbaLengthMatches() {
        assert_eq!(degraded_icon_rgba().len(), TRAY_ICON_RGBA.len());
    }
}
