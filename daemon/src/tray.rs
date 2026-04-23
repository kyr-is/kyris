// SPDX-License-Identifier: Apache-2.0
use std::sync::atomic::{AtomicU8, Ordering};

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

pub fn spawn_tray() {
    std::thread::spawn(|| {
        if let Err(e) = run_tray_loop() {
            tracing::warn!(error = %e, "system tray unavailable");
        }
    });
}

const TRAY_ICON_RGBA: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/tray_icon_44.rgba"));
const TRAY_ICON_SIZE: u32 = 44;

fn run_tray_loop() -> Result<(), String> {
    use tray_icon::TrayIconBuilder;

    let icon = build_tray_icon(false).map_err(|e| e.to_string())?;
    let _tray = TrayIconBuilder::new()
        .with_tooltip("Kyris daemon")
        .with_icon(icon)
        .build()
        .map_err(|e| e.to_string())?;

    loop {
        std::thread::sleep(std::time::Duration::from_secs(2));
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
}
