// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Rebuild when the git commit changes. Three paths cover all cases:
    // HEAD — branch switches; refs/heads/ — new commits on current branch;
    // packed-refs — refs compacted by `git gc` or remote fetch operations.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
    println!("cargo:rerun-if-changed=.git/packed-refs");
    emit_build_metadata();
    // Tray icon is opt-in via `--features tray`; only generate the
    // rasterized RGBA when we'll actually link the tray module in.
    if std::env::var_os("CARGO_FEATURE_TRAY").is_some() {
        rasterize_svg("assets/icon.svg", "tray_icon_44.rgba", 44, 44);
    }
}

fn emit_build_metadata() {
    let date = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%d"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=KYRIS_BUILD_DATE={date}");

    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=KYRIS_COMMIT={commit}");
}

fn rasterize_svg(svg_path: &str, out_name: &str, width: u32, height: u32) {
    println!("cargo:rerun-if-changed={svg_path}");

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
    let out_path = Path::new(&out_dir).join(out_name);

    let svg_data =
        fs::read_to_string(svg_path).unwrap_or_else(|e| panic!("Failed to read {svg_path}: {e}"));

    let tree = resvg::usvg::Tree::from_str(&svg_data, &resvg::usvg::Options::default())
        .unwrap_or_else(|e| panic!("Failed to parse SVG: {e}"));

    let svg_size = tree.size();
    let sx = width as f32 / svg_size.width();
    let sy = height as f32 / svg_size.height();

    let mut pixmap = resvg::tiny_skia::Pixmap::new(width, height).expect("failed to create pixmap");

    resvg::render(
        &tree,
        resvg::tiny_skia::Transform::from_scale(sx, sy),
        &mut pixmap.as_mut(),
    );

    let rgba = pixmap.data();
    let expected_bytes = (width * height * 4) as usize;
    assert_eq!(rgba.len(), expected_bytes, "unexpected RGBA buffer size");

    fs::write(&out_path, rgba).expect("write RGBA bytes");
}
