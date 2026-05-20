// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Syntect-driven syntax highlighting for the approval popup's accessoryView.
//!
//! `two-face` bundles bat's curated `SyntaxSet`/`ThemeSet` so we don't have
//! to vendor `.sublime-syntax` files ourselves. We tokenize the verbatim
//! code with syntect, then walk the `(Style, &str)` pairs into a single
//! `NSMutableAttributedString` with per-range foreground colors and a
//! monospaced base font. The popup's `NSTextView` renders the result.
//!
//! Theme selection follows the running app's effective appearance
//! (`NSAppearance.bestMatchFromAppearancesWithNames`), so dark-mode users
//! get a dark theme and light-mode users get a light theme without
//! per-user config.
//!
//! Language detection is deliberately conservative: shell is the
//! overwhelming majority of agent commands, so we default to it; first-line
//! shebangs (`#!/usr/bin/env python` etc.) switch to the matching syntax;
//! anything we can't classify renders as plain text in monospace (no
//! coloring, no crash).

#![cfg(target_os = "macos")]
#![allow(unsafe_code)]

use std::sync::OnceLock;

use objc2::rc::Retained;
use objc2::runtime::NSObjectProtocol;
use objc2::{AnyThread as _, MainThreadMarker};
use objc2_app_kit::{NSColor, NSFont, NSFontAttributeName, NSForegroundColorAttributeName};
use objc2_foundation::{NSCopying, NSMutableAttributedString, NSRange, NSString};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Style, Theme, ThemeSet};
use syntect::parsing::{SyntaxReference, SyntaxSet};
use syntect::util::LinesWithEndings;

/// Bundled `SyntaxSet` — loaded once per process. Sourced from `two-face`'s
/// curated bat set so common languages (shell, python, ts, js, etc.) work
/// without per-developer setup. ~600 KB of compressed syntax data.
fn syntax_set() -> &'static SyntaxSet {
    static SET: OnceLock<SyntaxSet> = OnceLock::new();
    SET.get_or_init(two_face::syntax::extra_newlines)
}

/// Light + dark theme pair, picked once. `InspiredGitHub` mirrors the
/// macOS-default light reading surface; `Solarized (dark)` is the
/// dark-mode counterpart bat ships and the broadest-comfort dark option.
/// Falls back to syntect's `base16-ocean.{light,dark}` if the curated
/// names move in a future two-face release (defense-in-depth — without
/// it a panicked lookup would block the popup).
fn themes() -> &'static (Theme, Theme) {
    static THEMES: OnceLock<(Theme, Theme)> = OnceLock::new();
    THEMES.get_or_init(|| {
        let set: ThemeSet = two_face::theme::extra().into();
        // The `expect` calls are practically unreachable — two-face ships
        // a non-empty theme set. If a future version drops every theme
        // we'd rather panic loudly on first popup than render an empty
        // accessoryView with no diagnostic.
        let light = set
            .themes
            .get("InspiredGitHub")
            .or_else(|| set.themes.get("base16-ocean.light"))
            .or_else(|| set.themes.values().next())
            .cloned()
            .expect("two-face shipped no themes — cannot pick a light theme");
        let dark = set
            .themes
            .get("Solarized (dark)")
            .or_else(|| set.themes.get("base16-ocean.dark"))
            .or_else(|| set.themes.values().next())
            .cloned()
            .expect("two-face shipped no themes — cannot pick a dark theme");
        (light, dark)
    })
}

/// Pick a syntect syntax based on the first line of the code. Shebangs
/// (`#!/usr/bin/env python`) get the matching language; everything else
/// falls back to the shared Unix shell syntax (which covers bash, zsh,
/// and `sh` well enough for an approval prompt's purposes).
fn detect_syntax<'a>(code: &str, set: &'a SyntaxSet) -> &'a SyntaxReference {
    if let Some(first) = code.lines().next()
        && let Some(syntax) = set.find_syntax_by_first_line(first)
    {
        return syntax;
    }
    set.find_syntax_by_token("bash")
        .or_else(|| set.find_syntax_by_token("sh"))
        .unwrap_or_else(|| set.find_syntax_plain_text())
}

/// Build a highlighted `NSMutableAttributedString` from the verbatim code
/// payload. The caller wires the result into the popup's `NSTextView` via
/// `textStorage().setAttributedString`.
///
/// `dark_mode` selects the theme; the caller passes `true` when
/// `NSApp.effectiveAppearance.bestMatchFromAppearancesWithNames`
/// resolves to a dark appearance.
pub fn build_attributed_string(
    code: &str,
    dark_mode: bool,
    _mtm: MainThreadMarker,
) -> Retained<NSMutableAttributedString> {
    let set = syntax_set();
    let (light, dark) = themes();
    let theme = if dark_mode { dark } else { light };
    let syntax = detect_syntax(code, set);

    let attr = NSMutableAttributedString::new();

    // Use the system monospaced font once for the whole document — applied
    // as a default range at the end so every character gets it without
    // having to re-set per syntect segment.
    let mono: Retained<NSFont> = NSFont::monospacedSystemFontOfSize_weight(12.0, 0.0);

    let mut highlighter = HighlightLines::new(syntax, theme);

    // Track our cumulative UTF-16 length — `NSAttributedString` ranges are
    // in UTF-16 code units, not bytes. Append the original line text into
    // the attributed string, then back-fill foreground color per segment.
    let mut cursor_utf16: usize = 0;

    for line in LinesWithEndings::from(code) {
        // `highlight_line` returns the line broken into `(Style, &str)` runs.
        let Ok(ranges) = highlighter.highlight_line(line, set) else {
            // Best-effort: append the raw line uncolored if syntect chokes.
            let ns = NSString::from_str(line);
            attr.appendAttributedString(&NSMutableAttributedString::initWithString(
                NSMutableAttributedString::alloc(),
                &ns,
            ));
            cursor_utf16 += utf16_len(line);
            continue;
        };
        for (style, segment) in ranges {
            let segment_utf16 = utf16_len(segment);
            // Append the raw text first
            let ns = NSString::from_str(segment);
            attr.appendAttributedString(&NSMutableAttributedString::initWithString(
                NSMutableAttributedString::alloc(),
                &ns,
            ));
            // Then color the range we just added
            let color = ns_color_from_style(style);
            let range = NSRange {
                location: cursor_utf16,
                length: segment_utf16,
            };
            unsafe {
                attr.addAttribute_value_range(
                    NSForegroundColorAttributeName,
                    color.as_ref(),
                    range,
                );
            }
            cursor_utf16 += segment_utf16;
        }
    }

    // Apply the monospaced font across the entire document in one shot.
    let full = NSRange {
        location: 0,
        length: cursor_utf16,
    };
    unsafe {
        attr.addAttribute_value_range(NSFontAttributeName, mono.as_ref(), full);
    }

    attr
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

fn ns_color_from_style(style: Style) -> Retained<NSColor> {
    let fg = style.foreground;
    NSColor::colorWithSRGBRed_green_blue_alpha(
        f64::from(fg.r) / 255.0,
        f64::from(fg.g) / 255.0,
        f64::from(fg.b) / 255.0,
        f64::from(fg.a) / 255.0,
    )
}

/// Resolve whether the running app should render the popup in dark mode.
/// Reads `NSApp.effectiveAppearance` and matches against the dark
/// aqua name; defaults to false (light) when the lookup fails for any
/// reason (no app instance, unrecognized appearance name).
pub fn dark_mode_active(mtm: MainThreadMarker) -> bool {
    use objc2_app_kit::{NSAppearanceNameDarkAqua, NSApplication};
    let app = NSApplication::sharedApplication(mtm);
    let appearance = app.effectiveAppearance();
    let dark_name: &NSString = unsafe { NSAppearanceNameDarkAqua };
    let names = vec![dark_name.copy()];
    let ns_names = objc2_foundation::NSArray::from_retained_slice(&names);
    let best = appearance.bestMatchFromAppearancesWithNames(&ns_names);
    // Compare via NSString::isEqual rather than `==` — both sides are
    // `&NSString`, but the trait resolution for `PartialEq` on
    // `Retained<NSString>` is ambiguous in this position.
    if let Some(n) = best {
        n.isEqual(Some(dark_name.as_ref()))
    } else {
        false
    }
}
