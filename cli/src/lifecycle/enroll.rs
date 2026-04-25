// SPDX-License-Identifier: Apache-2.0
use clap::Args;
use kyris_core::sync::EnrollmentResponse;
use serde::{Deserialize, Serialize};
use std::io::IsTerminal;

use crate::service::{ServiceKind, restart_service, service_state};
use crate::state::{credentials_path, load_or_init_config, save_config, write_managed_file};

#[derive(Args)]
pub struct EnrollArgs {
    #[arg(long)]
    pub force: bool,
    #[arg(long)]
    pub relay_url: Option<String>,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct EnrollmentRequest {
    hostname: String,
    os: String,
    arch: String,
    kyris_version: String,
    agentpact_version: String,
}

pub fn run(args: EnrollArgs) {
    if let Err(error) = enroll(args) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn enroll(args: EnrollArgs) -> Result<(), String> {
    let mut config = load_or_init_config()?;
    let relay_url = resolve_relay_url(&args, &config)?;
    let existing_credentials = load_credentials()?;
    if config.sync.relay_url != relay_url {
        config.sync.relay_url.clone_from(&relay_url);
    }

    let github_client_id = std::env::var("GITHUB_CLIENT_ID")
        .map_err(|_| "GITHUB_CLIENT_ID is not set.".to_string())?;

    if args.force {
        println!("Re-enrolling via GitHub device flow...");
    } else {
        println!("Starting enrollment via GitHub device flow...");
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for enrollment: {e}"))?;

    let device_code = runtime.block_on(request_device_code(&github_client_id))?;
    println!(
        "Open {} and enter code {}",
        device_code.verification_uri, device_code.user_code
    );
    maybe_open_verification_uri(&device_code.verification_uri);

    let github_access_token = poll_access_token(&runtime, &github_client_id, &device_code)?;
    let enrollment = runtime.block_on(enroll_with_relay(
        &relay_url,
        &github_access_token,
        machine_metadata(),
    ))?;
    verify_force_rotation(existing_credentials.as_ref(), &enrollment, args.force)?;

    write_credentials(&enrollment)?;
    update_sync_config(&mut config)?;
    save_config(&config)?;

    println!("Enrollment complete.");
    println!("Credentials written to {}", credentials_path()?.display());
    let state = service_state(ServiceKind::Kyrisd);
    if state.managed_by_homebrew || state.launchd_loaded {
        restart_service(ServiceKind::Kyrisd)?;
        wait_for_kyrisd_health(&config.server.listen)?;
        println!("Restarted kyrisd to activate sync.");
        println!(
            "kyrisd is healthy at http://{}/healthz",
            config.server.listen
        );
    } else {
        println!("Restart kyrisd to activate sync.");
        if wait_for_kyrisd_health(&config.server.listen).is_ok() {
            println!(
                "kyrisd is already healthy at http://{}/healthz",
                config.server.listen
            );
        }
    }
    println!("Machine enrolled as {}", enrollment.machine_id);
    Ok(())
}

async fn request_device_code(client_id: &str) -> Result<DeviceCodeResponse, String> {
    let client = reqwest::Client::new();
    client
        .post(github_device_code_url())
        .header("accept", "application/json")
        .header("user-agent", user_agent())
        .form(&[("client_id", client_id), ("scope", "read:user user:email")])
        .send()
        .await
        .map_err(|e| format!("Failed to request GitHub device code: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GitHub device code request failed: {e}"))?
        .json::<DeviceCodeResponse>()
        .await
        .map_err(|e| format!("Failed to parse GitHub device code response: {e}"))
}

fn poll_access_token(
    runtime: &tokio::runtime::Runtime,
    client_id: &str,
    device_code: &DeviceCodeResponse,
) -> Result<String, String> {
    let started_at = std::time::Instant::now();
    let mut interval = device_code.interval.max(1);

    loop {
        if started_at.elapsed().as_secs() >= device_code.expires_in {
            return Err("GitHub device code expired before authorization completed.".to_string());
        }

        let response =
            runtime.block_on(request_access_token(client_id, &device_code.device_code))?;
        if let Some(access_token) = response.access_token {
            return Ok(access_token);
        }

        match response.error.as_deref() {
            Some("authorization_pending") => {}
            Some("slow_down") => {
                interval += 5;
            }
            Some("access_denied") => {
                return Err("GitHub authorization was denied.".to_string());
            }
            Some("expired_token") => {
                return Err("GitHub device code expired.".to_string());
            }
            Some(error) => {
                return Err(format!("GitHub device flow failed: {error}"));
            }
            None => {
                return Err("GitHub device flow returned an empty token response.".to_string());
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

async fn request_access_token(
    client_id: &str,
    device_code: &str,
) -> Result<AccessTokenResponse, String> {
    let client = reqwest::Client::new();
    client
        .post(github_access_token_url())
        .header("accept", "application/json")
        .header("user-agent", user_agent())
        .form(&[
            ("client_id", client_id),
            ("device_code", device_code),
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
        ])
        .send()
        .await
        .map_err(|e| format!("Failed to poll GitHub access token: {e}"))?
        .error_for_status()
        .map_err(|e| format!("GitHub access token request failed: {e}"))?
        .json::<AccessTokenResponse>()
        .await
        .map_err(|e| format!("Failed to parse GitHub access token response: {e}"))
}

async fn enroll_with_relay(
    relay_url: &str,
    github_access_token: &str,
    request: EnrollmentRequest,
) -> Result<EnrollmentResponse, String> {
    let client = reqwest::Client::new();
    client
        .post(format!("{relay_url}/api/v1/enroll"))
        .header("authorization", format!("Bearer {github_access_token}"))
        .header("user-agent", user_agent())
        .json(&request)
        .send()
        .await
        .map_err(|e| format!("Failed to enroll with kyris-relay: {e}"))?
        .error_for_status()
        .map_err(|e| format!("kyris-relay enrollment failed: {e}"))?
        .json::<EnrollmentResponse>()
        .await
        .map_err(|e| format!("Failed to parse kyris-relay enrollment response: {e}"))
}

fn machine_metadata() -> EnrollmentRequest {
    EnrollmentRequest {
        hostname: hostname(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        kyris_version: env!("CARGO_PKG_VERSION").to_string(),
        agentpact_version: component_version("agentpactd"),
    }
}

fn hostname() -> String {
    if let Ok(value) = std::env::var("HOSTNAME")
        && !value.trim().is_empty()
    {
        return value;
    }

    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn component_version(name: &str) -> String {
    std::process::Command::new(name)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "not-found".to_string())
}

fn write_credentials(credentials: &EnrollmentResponse) -> Result<(), String> {
    let path = credentials_path()?;
    let contents = serde_json::to_string_pretty(credentials)
        .map_err(|e| format!("Cannot serialize enrollment credentials: {e}"))?;
    let _ = write_managed_file(&path, &contents, "credentials", Some(0o600))?;
    Ok(())
}

fn load_credentials() -> Result<Option<EnrollmentResponse>, String> {
    let path = credentials_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read {}: {e}", path.display()))?;
    let credentials = serde_json::from_str(&contents)
        .map_err(|e| format!("Cannot parse {}: {e}", path.display()))?;
    Ok(Some(credentials))
}

fn update_sync_config(config: &mut kyris_core::config::KyrisdConfig) -> Result<(), String> {
    config.sync.enabled = true;

    if !std::io::stdin().is_terminal() {
        return Ok(());
    }

    let default_scope = config.sync.scope.join(",");
    let prompt = if default_scope.is_empty() {
        "Sync directories (comma-separated, blank to keep current)"
    } else {
        "Sync directories (comma-separated, blank to keep existing)"
    };

    let input: String = dialoguer::Input::new()
        .with_prompt(prompt)
        .allow_empty(true)
        .with_initial_text(default_scope.clone())
        .interact_text()
        .map_err(|e| format!("Failed to read sync scope: {e}"))?;

    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Ok(());
    }

    config.sync.scope = trimmed
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect();
    Ok(())
}

fn user_agent() -> String {
    format!("kyris/{}", env!("CARGO_PKG_VERSION"))
}

fn github_device_code_url() -> String {
    std::env::var("KYRIS_TEST_GITHUB_DEVICE_CODE_URL")
        .unwrap_or_else(|_| "https://github.com/login/device/code".to_string())
}

fn github_access_token_url() -> String {
    std::env::var("KYRIS_TEST_GITHUB_ACCESS_TOKEN_URL")
        .unwrap_or_else(|_| "https://github.com/login/oauth/access_token".to_string())
}

fn maybe_open_verification_uri(verification_uri: &str) {
    if env_flag("KYRIS_TEST_DISABLE_BROWSER_OPEN") {
        return;
    }
    let _ = open::that(verification_uri);
}

fn resolve_relay_url(
    args: &EnrollArgs,
    config: &kyris_core::config::KyrisdConfig,
) -> Result<String, String> {
    let relay_url = args
        .relay_url
        .clone()
        .or_else(|| std::env::var("KYRIS_RELAY_URL").ok())
        .unwrap_or_else(|| config.sync.relay_url.clone())
        .trim()
        .trim_end_matches('/')
        .to_string();

    if relay_url.is_empty() {
        return Err(
            "Cannot enroll without a relay URL. Set `[sync].relay_url`, pass `--relay-url`, or set `KYRIS_RELAY_URL`."
                .to_string(),
        );
    }
    Ok(relay_url)
}

fn verify_force_rotation(
    existing: Option<&EnrollmentResponse>,
    enrollment: &EnrollmentResponse,
    force: bool,
) -> Result<(), String> {
    if !force {
        return Ok(());
    }
    let Some(existing) = existing else {
        return Ok(());
    };
    if enrollment.machine_id != existing.machine_id {
        return Err(format!(
            "Force enrollment changed machine_id from {} to {}. Expected rotation on the existing machine record.",
            existing.machine_id, enrollment.machine_id
        ));
    }
    if enrollment.machine_token == existing.machine_token {
        return Err(
            "Force enrollment did not rotate the machine token. Expected a new machine_token."
                .to_string(),
        );
    }
    Ok(())
}

fn wait_for_kyrisd_health(listen: &str) -> Result<(), String> {
    let url = format!("http://{listen}/healthz");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Cannot build runtime for enrollment verification: {e}"))?;

    runtime.block_on(async {
        for _ in 0..20 {
            match reqwest::get(&url).await {
                Ok(response) if response.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(std::time::Duration::from_millis(250)).await,
            }
        }
        Err(format!(
            "kyrisd is not healthy after enrollment restart at {url}"
        ))
    })
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        let normalized = value.trim().to_ascii_lowercase();
        matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_relay_url_prefers_flag() {
        let args = EnrollArgs {
            force: false,
            relay_url: Some("https://flag.example/".to_string()),
        };
        let config: kyris_core::config::KyrisdConfig = serde_saphyr::from_str(
            r#"
sync:
  relay_url: "https://config.example"
"#,
        )
        .expect("config");

        assert_eq!(
            resolve_relay_url(&args, &config).expect("relay url"),
            "https://flag.example"
        );
    }

    #[test]
    fn test_verify_force_rotation_requires_same_machine_id() {
        let existing = EnrollmentResponse {
            machine_token: "old-token".to_string(),
            machine_id: "machine-1".to_string(),
        };
        let enrollment = EnrollmentResponse {
            machine_token: "new-token".to_string(),
            machine_id: "machine-2".to_string(),
        };

        let error =
            verify_force_rotation(Some(&existing), &enrollment, true).expect_err("should fail");
        assert!(error.contains("machine_id"));
    }

    #[test]
    fn test_verify_force_rotation_requires_new_token() {
        let existing = EnrollmentResponse {
            machine_token: "same-token".to_string(),
            machine_id: "machine-1".to_string(),
        };
        let enrollment = EnrollmentResponse {
            machine_token: "same-token".to_string(),
            machine_id: "machine-1".to_string(),
        };

        let error =
            verify_force_rotation(Some(&existing), &enrollment, true).expect_err("should fail");
        assert!(error.contains("did not rotate"));
    }
}
