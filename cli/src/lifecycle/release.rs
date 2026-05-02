// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
use std::path::PathBuf;

#[derive(serde::Deserialize)]
pub struct GitHubRelease {
    pub tag_name: String,
    pub assets: Vec<GitHubAsset>,
}

#[derive(serde::Deserialize)]
pub struct GitHubAsset {
    pub name: String,
    pub browser_download_url: String,
}

pub fn release_target() -> Result<&'static str, String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64" | "arm64") => Ok("darwin-aarch64"),
        ("macos", "x86_64") => Ok("darwin-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        (os, arch) => Err(format!("Unsupported target: {os}/{arch}")),
    }
}

pub fn user_agent() -> String {
    format!("kyris/{}", env!("CARGO_PKG_VERSION"))
}

pub fn github_releases_base_url() -> String {
    "https://api.github.com".to_string()
}

pub fn brew_formula_installed(formula: &str) -> bool {
    std::process::Command::new("brew")
        .args(["list", formula])
        .output()
        .is_ok_and(|output| output.status.success())
}

pub async fn fetch_latest_release(owner: &str, repo: &str) -> Result<GitHubRelease, String> {
    let url = format!(
        "{}/repos/{owner}/{repo}/releases/latest",
        github_releases_base_url()
    );
    reqwest::Client::new()
        .get(url)
        .header("accept", "application/vnd.github+json")
        .header("user-agent", user_agent())
        .send()
        .await
        .map_err(|e| format!("Failed to query GitHub Releases for {owner}/{repo}: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GitHub Releases request failed for {owner}/{repo}: {e}"))?
        .json::<GitHubRelease>()
        .await
        .map_err(|e| format!("Failed to parse GitHub release for {owner}/{repo}: {e}"))
}

pub async fn download_asset(asset: &GitHubAsset) -> Result<Vec<u8>, String> {
    let bytes = reqwest::Client::new()
        .get(&asset.browser_download_url)
        .header("user-agent", user_agent())
        .send()
        .await
        .map_err(|e| format!("Failed to download {}: {e}", asset.name))?
        .error_for_status()
        .map_err(|e| format!("Download failed for {}: {e}", asset.name))?
        .bytes()
        .await
        .map_err(|e| format!("Failed to read {}: {e}", asset.name))?;
    Ok(bytes.to_vec())
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    digest.as_ref().iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

pub async fn download_and_verify(
    release: &GitHubRelease,
    asset: &GitHubAsset,
) -> Result<Vec<u8>, String> {
    let tarball_bytes = download_asset(asset).await?;

    let checksums_asset = release.assets.iter().find(|a| a.name == "SHA256SUMS");

    let Some(checksums_asset) = checksums_asset else {
        return Err(format!(
            "Release is missing SHA256SUMS file — cannot verify {}",
            asset.name
        ));
    };

    let checksums_bytes = download_asset(checksums_asset).await?;
    let checksums_text = String::from_utf8(checksums_bytes)
        .map_err(|e| format!("SHA256SUMS is not valid UTF-8: {e}"))?;

    let expected_hash = parse_checksums(&checksums_text, &asset.name)
        .ok_or_else(|| format!("SHA256SUMS does not contain an entry for {}", asset.name))?;

    let actual_hash = sha256_hex(&tarball_bytes);
    if actual_hash != expected_hash {
        return Err(format!(
            "Checksum mismatch for {}: expected {expected_hash}, got {actual_hash}",
            asset.name
        ));
    }

    Ok(tarball_bytes)
}

pub fn extract_tarball(bytes: &[u8], label: &str) -> Result<PathBuf, String> {
    let temp_dir = std::env::temp_dir().join(format!(
        "kyris-release-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    ));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("Cannot create {}: {e}", temp_dir.display()))?;

    let archive_path = temp_dir.join(label);
    std::fs::write(&archive_path, bytes)
        .map_err(|e| format!("Cannot write {}: {e}", archive_path.display()))?;

    let status = std::process::Command::new("tar")
        .args([
            "-xzf",
            &archive_path.to_string_lossy(),
            "-C",
            &temp_dir.to_string_lossy(),
        ])
        .status()
        .map_err(|e| format!("Failed to run tar for {label}: {e}"))?;
    if !status.success() {
        return Err(format!("tar failed while extracting {label}"));
    }

    Ok(temp_dir)
}

fn parse_checksums(text: &str, filename: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Format: "<hash>  <filename>" or "<hash> <filename>"
        if let Some((hash, name)) = line.split_once(char::is_whitespace) {
            let name = name.trim();
            if name == filename || name.trim_start_matches("./") == filename {
                return Some(hash.to_lowercase());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testSha256Hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn testParseChecksumsFindsEntry() {
        let text = "abc123  kyris-darwin-aarch64.tar.gz\ndef456  kyris-linux-x86_64.tar.gz\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testParseChecksumsMissingEntry() {
        let text = "abc123  kyris-darwin-aarch64.tar.gz\n";
        assert_eq!(parse_checksums(text, "kyris-linux-x86_64.tar.gz"), None);
    }

    #[test]
    fn testParseChecksumsSkipsComments() {
        let text = "# SHA256 checksums\nabc123  kyris-darwin-aarch64.tar.gz\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testParseChecksumsSkipsEmptyLines() {
        let text = "\n\nabc123  kyris-darwin-aarch64.tar.gz\n\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testParseChecksumsSingleSpace() {
        let text = "abc123 kyris-darwin-aarch64.tar.gz\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testParseChecksumsNormalizesCase() {
        let text = "ABC123  kyris-darwin-aarch64.tar.gz\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testParseChecksumsHandlesDotSlashPrefix() {
        let text = "abc123  ./kyris-darwin-aarch64.tar.gz\n";
        assert_eq!(
            parse_checksums(text, "kyris-darwin-aarch64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn testReleaseTargetReturnsValue() {
        let result = release_target();
        assert!(result.is_ok());
        let target = result.unwrap();
        assert!(
            target.starts_with("darwin-") || target.starts_with("linux-"),
            "unexpected target: {target}"
        );
    }
}
