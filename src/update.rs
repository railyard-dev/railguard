use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, Duration};

const REMOTE_URL: &str = "https://github.com/railroaddev/railroad.git";
const GITHUB_REPO: &str = "railroaddev/railroad";
const CHECK_INTERVAL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 1 week
const BUILD_HASH: &str = env!("RAILROAD_GIT_HASH");
const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Info about the latest release from GitHub.
pub struct ReleaseInfo {
    pub tag: String,
    pub version: String,
    pub body: String,
}

/// Check for updates. Two checks:
/// 1. Security tag — every session, <100ms. For emergency patches.
/// 2. Main branch — once per week. For normal updates.
/// Returns a message if an update exists.
pub fn check_for_update(cwd: &Path) -> Option<String> {
    // Always check for emergency security patches
    if let Some(msg) = check_security_tag() {
        return Some(msg);
    }

    // Weekly check for normal updates
    check_main_branch(cwd)
}

/// Fetch the latest release info from GitHub.
pub fn fetch_latest_release() -> Result<ReleaseInfo, String> {
    let url = format!("https://api.github.com/repos/{}/releases/latest", GITHUB_REPO);

    let output = Command::new("curl")
        .args(["-fsSL", "-H", "Accept: application/vnd.github+json", &url])
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        return Err("Could not fetch release info from GitHub".to_string());
    }

    let body = String::from_utf8(output.stdout)
        .map_err(|_| "Invalid UTF-8 in response".to_string())?;

    let json: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("Failed to parse release JSON: {}", e))?;

    let tag = json["tag_name"]
        .as_str()
        .ok_or("No tag_name in release")?
        .to_string();

    let version = tag.strip_prefix('v').unwrap_or(&tag).to_string();

    let release_body = json["body"]
        .as_str()
        .unwrap_or("")
        .to_string();

    Ok(ReleaseInfo {
        tag,
        version,
        body: release_body,
    })
}

/// Compare two semver strings. Returns true if `remote` is newer than `local`.
pub fn is_newer(local: &str, remote: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.')
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };
    let l = parse(local);
    let r = parse(remote);
    r > l
}

/// Get the current installed version string.
pub fn current_version() -> &'static str {
    CURRENT_VERSION
}

/// Detect the platform target triple (e.g., "aarch64-apple-darwin").
fn detect_target() -> Option<String> {
    let os_output = Command::new("uname").arg("-s").output().ok()?;
    let arch_output = Command::new("uname").arg("-m").output().ok()?;

    let os = String::from_utf8(os_output.stdout).ok()?.trim().to_lowercase();
    let arch = String::from_utf8(arch_output.stdout).ok()?.trim().to_string();

    let os_label = match os.as_str() {
        "darwin" => "apple-darwin",
        "linux" => "unknown-linux-gnu",
        _ => return None,
    };

    let arch_label = match arch.as_str() {
        "x86_64" | "amd64" => "x86_64",
        "arm64" | "aarch64" => "aarch64",
        _ => return None,
    };

    Some(format!("{}-{}", arch_label, os_label))
}

/// Find the install directory for the railroad binary.
fn install_dir() -> String {
    // Use the directory of the currently running binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            return dir.display().to_string();
        }
    }
    // Fallback
    let home = dirs::home_dir().unwrap_or_default();
    let cargo_bin = home.join(".cargo/bin");
    if cargo_bin.exists() {
        return cargo_bin.display().to_string();
    }
    "/usr/local/bin".to_string()
}

/// Download and install a prebuilt binary from a GitHub release.
/// Returns Ok(true) if successful, Ok(false) if binary not available for platform.
fn download_binary(tag: &str, target: &str, dest_dir: &str) -> Result<bool, String> {
    let tarball = format!("railroad-{}-{}.tar.gz", tag, target);
    let url = format!(
        "https://github.com/{}/releases/download/{}/{}",
        GITHUB_REPO, tag, tarball
    );

    // Download to a temp directory
    let tmp_output = Command::new("mktemp")
        .arg("-d")
        .output()
        .map_err(|e| format!("mktemp failed: {}", e))?;
    let tmpdir = String::from_utf8(tmp_output.stdout)
        .map_err(|_| "Invalid tmpdir".to_string())?
        .trim()
        .to_string();

    let tarball_path = format!("{}/{}", tmpdir, tarball);

    let curl = Command::new("curl")
        .args(["-fsSL", "-o", &tarball_path, &url])
        .output()
        .map_err(|e| format!("curl failed: {}", e))?;

    if !curl.status.success() {
        let _ = Command::new("rm").args(["-rf", &tmpdir]).output();
        return Ok(false);
    }

    // Extract
    let tar = Command::new("tar")
        .args(["-xzf", &tarball_path, "-C", &tmpdir])
        .output()
        .map_err(|e| format!("tar failed: {}", e))?;

    if !tar.status.success() {
        let _ = Command::new("rm").args(["-rf", &tmpdir]).output();
        return Err("Failed to extract archive".to_string());
    }

    // Move binaries
    let binary_src = format!("{}/railroad", tmpdir);
    let binary_dest = format!("{}/railroad", dest_dir);

    if !Path::new(&binary_src).exists() {
        let _ = Command::new("rm").args(["-rf", &tmpdir]).output();
        return Err("Archive did not contain expected binary".to_string());
    }

    let mv = Command::new("mv")
        .args([&binary_src, &binary_dest])
        .output()
        .map_err(|e| format!("mv failed: {}", e))?;

    if !mv.status.success() {
        let _ = Command::new("rm").args(["-rf", &tmpdir]).output();
        return Err(format!("Failed to move binary to {}", dest_dir));
    }

    let _ = Command::new("chmod").args(["+x", &binary_dest]).output();

    // Also move railroad-shell if present
    let shell_src = format!("{}/railroad-shell", tmpdir);
    if Path::new(&shell_src).exists() {
        let shell_dest = format!("{}/railroad-shell", dest_dir);
        let _ = Command::new("mv").args([&shell_src, &shell_dest]).output();
        let _ = Command::new("chmod").args(["+x", &shell_dest]).output();
    }

    let _ = Command::new("rm").args(["-rf", &tmpdir]).output();
    Ok(true)
}

/// Build from source using cargo install.
fn build_from_source() -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["install", "--git", REMOTE_URL])
        .status()
        .map_err(|e| format!("Failed to run cargo: {}", e))?;

    if !status.success() {
        return Err("cargo install failed".to_string());
    }
    Ok(())
}

/// Run the full update: check version, download, install, re-register hooks.
/// If `check_only` is true, just report whether an update is available.
pub fn run_update(check_only: bool) -> i32 {
    use colored::Colorize;

    println!("{}", "railroad update".bold());
    println!();

    // 1. Fetch latest release
    print!("  Checking for updates... ");
    let release = match fetch_latest_release() {
        Ok(r) => r,
        Err(e) => {
            println!("{}", "failed".red());
            eprintln!("  {} {}", "✗".red().bold(), e);
            return 1;
        }
    };

    let current = current_version();

    // 2. Compare versions
    if !is_newer(current, &release.version) {
        println!("{}", "up to date".green());
        println!();
        println!("  Current version: {}", current.cyan());
        println!("  Latest release:  {}", release.version.cyan());
        println!();
        println!("  {} Already on the latest version.", "✓".green().bold());
        return 0;
    }

    println!("{}", "update available".yellow());
    println!();
    println!("  Current version: {}", current.cyan());
    println!("  Latest release:  {} ({})", release.version.green().bold(), release.tag);

    // 3. Show changelog if available
    if !release.body.is_empty() {
        println!();
        println!("  {}", "What's new:".bold());
        for line in release.body.lines().take(20) {
            println!("    {}", line);
        }
    }

    if check_only {
        println!();
        println!("  Run {} to install this update.", "railroad update".cyan());
        return 0;
    }

    println!();

    // 4. Download and install
    let dest = install_dir();

    // Try prebuilt binary first
    if let Some(target) = detect_target() {
        print!("  Downloading prebuilt binary for {}... ", target);
        match download_binary(&release.tag, &target, &dest) {
            Ok(true) => {
                println!("{}", "done".green());
                println!("  {} Installed to {}", "✓".green().bold(), dest);
            }
            Ok(false) => {
                println!("{}", "not available".yellow());
                print!("  Building from source... ");
                match build_from_source() {
                    Ok(()) => println!("{}", "done".green()),
                    Err(e) => {
                        println!("{}", "failed".red());
                        eprintln!("  {} {}", "✗".red().bold(), e);
                        return 1;
                    }
                }
            }
            Err(e) => {
                println!("{}", "failed".red());
                eprintln!("  {} {}", "✗".red().bold(), e);
                print!("  Building from source... ");
                match build_from_source() {
                    Ok(()) => println!("{}", "done".green()),
                    Err(e2) => {
                        println!("{}", "failed".red());
                        eprintln!("  {} {}", "✗".red().bold(), e2);
                        return 1;
                    }
                }
            }
        }
    } else {
        // Can't detect platform, go straight to cargo
        print!("  Building from source... ");
        match build_from_source() {
            Ok(()) => println!("{}", "done".green()),
            Err(e) => {
                println!("{}", "failed".red());
                eprintln!("  {} {}", "✗".red().bold(), e);
                return 1;
            }
        }
    }

    // 5. Re-register hooks
    println!();
    print!("  Re-registering hooks... ");
    match crate::install::hooks::install_hooks() {
        Ok(_) => {
            println!("{}", "done".green());
            println!("  {} Hooks updated", "✓".green().bold());
        }
        Err(e) => {
            println!("{}", "warning".yellow());
            eprintln!("  {} Hook registration failed: {}", "!".yellow().bold(), e);
            eprintln!("  Run {} to register manually.", "railroad install".cyan());
        }
    }

    println!();
    println!(
        "  {} Updated to {} successfully.",
        "✓".green().bold(),
        release.version.green().bold()
    );
    0
}

/// Check if a `security` tag exists on the remote that doesn't match our build.
/// Runs every session — single ref lookup is <100ms.
fn check_security_tag() -> Option<String> {
    if BUILD_HASH == "unknown" {
        return None;
    }

    let output = Command::new("git")
        .args(["ls-remote", REMOTE_URL, "refs/tags/security"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    let security_hash = stdout.split_whitespace().next()?;

    // No security tag on remote — no emergency
    if security_hash.is_empty() {
        return None;
    }

    // If our build matches the security tag, we're already patched
    if security_hash.starts_with(BUILD_HASH) || BUILD_HASH.starts_with(security_hash) {
        return None;
    }

    Some(
        "⚠ A security patch for Railroad is available. \
         Run `railroad update` to update immediately."
            .to_string(),
    )
}

/// Check if main branch has moved ahead of our build. Rate-limited to once per week.
fn check_main_branch(cwd: &Path) -> Option<String> {
    let marker = cwd.join(".railroad/last-update-check");

    // Rate limit: skip if checked recently
    if let Ok(meta) = fs::metadata(&marker) {
        if let Ok(modified) = meta.modified() {
            if let Ok(elapsed) = SystemTime::now().duration_since(modified) {
                if elapsed < CHECK_INTERVAL {
                    return None;
                }
            }
        }
    }

    // Touch the marker file regardless of outcome
    let _ = fs::create_dir_all(cwd.join(".railroad"));
    let _ = fs::write(&marker, "");

    if BUILD_HASH == "unknown" {
        return None;
    }

    let output = Command::new("git")
        .args(["ls-remote", REMOTE_URL, "refs/heads/main"])
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let remote_hash = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .next()?
        .to_string();

    if remote_hash.starts_with(BUILD_HASH) || BUILD_HASH.starts_with(&remote_hash) {
        return None;
    }

    Some(
        "A new version of Railroad is available. \
         Run `railroad update` to update."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_newer() {
        assert!(is_newer("0.3.3", "0.3.4"));
        assert!(is_newer("0.3.3", "0.4.0"));
        assert!(is_newer("0.3.3", "1.0.0"));
        assert!(!is_newer("0.3.3", "0.3.3"));
        assert!(!is_newer("0.3.3", "0.3.2"));
        assert!(!is_newer("1.0.0", "0.9.9"));
    }

    #[test]
    fn test_current_version() {
        let v = current_version();
        assert!(!v.is_empty());
        assert!(v.contains('.'));
    }
}
