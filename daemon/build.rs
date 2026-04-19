// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    rasterize_svg("assets/icon.svg", "tray_icon_44.rgba", 44, 44);
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
