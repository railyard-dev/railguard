/// railyard-shell: A POSIX shell shim that wraps every command in an OS sandbox.
///
/// Claude Code calls this as its shell (via CLAUDE_CODE_SHELL env var).
/// Every `Bash` tool call runs: railyard-shell -c "command"
/// Which becomes: sandbox-exec -f profile.sb -- /bin/sh -c "command"
///
/// The user never changes their workflow. They type `claude` as normal.
/// Every shell command is kernel-sandboxed transparently.

use std::env;
use std::path::Path;
use std::process::{Command, ExitCode};

#[cfg(not(unix))]
use std::process::Stdio;

use railyard::policy::loader::load_policy_or_defaults;
use railyard::sandbox::detect::{detect_sandbox, SandboxCapability};
use railyard::sandbox::macos;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();

    // Safety: this binary is ONLY a shell wrapper for sandbox execution.
    // If someone accidentally invokes it with CLI subcommands, bail early
    // and point them to the correct binary.
    if args.len() > 1 && !args[1].starts_with('-') {
        eprintln!("railyard-shell is the sandbox shell wrapper, not the CLI.");
        eprintln!("Use `railyard {}` instead.", args[1]);
        return ExitCode::from(1);
    }

    // Recursion guard: if we're already inside a sandbox, just exec bare shell
    if env::var("RAILYARD_SANDBOXED").is_ok() {
        return exec_bare(&args);
    }

    // Parse shell-compatible args: railyard-shell -c "command string"
    let command_str = match parse_shell_args(&args) {
        Some(cmd) => cmd,
        None => {
            // No -c flag — interactive mode or script execution. Fall through to real shell.
            return exec_bare(&args);
        }
    };

    // Load policy from cwd
    let cwd = env::current_dir().unwrap_or_else(|_| Path::new("/").to_path_buf());
    let policy = load_policy_or_defaults(&cwd);

    // If fence is disabled, skip sandbox
    if !policy.fence.enabled {
        return exec_bare_command(&command_str);
    }

    // Detect sandbox capability
    let capability = detect_sandbox();

    match capability {
        SandboxCapability::MacOsSandboxExec => {
            exec_macos_sandbox(&policy.fence, &cwd.display().to_string(), &command_str)
        }
        SandboxCapability::LinuxLandlock { .. } => {
            exec_linux_sandbox(&policy.fence, &cwd.display().to_string(), &command_str)
        }
        SandboxCapability::None => {
            // No sandbox available — fall through to bare shell
            exec_bare_command(&command_str)
        }
    }
}

/// Parse -c "command" from shell args.
fn parse_shell_args(args: &[String]) -> Option<String> {
    // Look for -c flag
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" && i + 1 < args.len() {
            return Some(args[i + 1].clone());
        }
        i += 1;
    }
    None
}

/// Execute command inside macOS sandbox-exec.
fn exec_macos_sandbox(
    fence: &railyard::types::FenceConfig,
    cwd: &str,
    command: &str,
) -> ExitCode {
    let profile = macos::generate_profile(fence, cwd);

    // Write profile to a temp file inside .railyard/
    let profile_dir = Path::new(cwd).join(".railyard");
    let _ = std::fs::create_dir_all(&profile_dir);
    let profile_path = profile_dir.join("shell-sandbox.sb");
    if std::fs::write(&profile_path, &profile).is_err() {
        // Can't write profile — fall back to bare shell
        return exec_bare_command(command);
    }

    // Use exec() to replace our process — zero overhead, transparent stdio
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new("sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg(command)
            .env("RAILYARD_SANDBOXED", "1")
            .exec();
        eprintln!("railyard-shell: exec failed: {}", err);
        ExitCode::from(127)
    }

    #[cfg(not(unix))]
    {
        let status = Command::new("sandbox-exec")
            .arg("-f")
            .arg(&profile_path)
            .arg("--")
            .arg("/bin/sh")
            .arg("-c")
            .arg(command)
            .env("RAILYARD_SANDBOXED", "1")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        match status {
            Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
            Err(_) => ExitCode::from(127),
        }
    }
}

/// Execute command inside Linux bubblewrap sandbox.
fn exec_linux_sandbox(
    fence: &railyard::types::FenceConfig,
    cwd: &str,
    command: &str,
) -> ExitCode {
    // Check if bwrap is available
    let bwrap_check = Command::new("which").arg("bwrap").output();
    if bwrap_check.map(|o| o.status.success()).unwrap_or(false) {
        let home = dirs::home_dir()
            .map(|h| h.display().to_string())
            .unwrap_or_default();

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let mut cmd = Command::new("bwrap");
            // System paths (read-only)
            cmd.args(["--ro-bind", "/usr", "/usr"]);
            cmd.args(["--ro-bind", "/bin", "/bin"]);
            cmd.args(["--ro-bind", "/sbin", "/sbin"]);
            if Path::new("/lib").exists() {
                cmd.args(["--ro-bind", "/lib", "/lib"]);
            }
            if Path::new("/lib64").exists() {
                cmd.args(["--ro-bind", "/lib64", "/lib64"]);
            }
            cmd.args(["--ro-bind", "/etc", "/etc"]);
            cmd.args(["--dev", "/dev"]);
            cmd.args(["--proc", "/proc"]);
            cmd.args(["--tmpfs", "/tmp"]);
            // Project dir (read-write)
            cmd.args(["--bind", cwd, cwd]);
            // Shadow sensitive dirs with empty tmpfs
            let ssh_dir = format!("{}/.ssh", home);
            let aws_dir = format!("{}/.aws", home);
            let gnupg_dir = format!("{}/.gnupg", home);
            cmd.args(["--tmpfs", &ssh_dir]);
            cmd.args(["--tmpfs", &aws_dir]);
            cmd.args(["--tmpfs", &gnupg_dir]);
            // Additional denied paths from config
            for denied in &fence.denied_paths {
                let expanded = if denied.starts_with("~/") {
                    format!("{}{}", home, &denied[1..])
                } else {
                    denied.clone()
                };
                if !expanded.contains("/.ssh") && !expanded.contains("/.aws") && !expanded.contains("/.gnupg") {
                    cmd.args(["--tmpfs", &expanded]);
                }
            }
            cmd.arg("--")
                .arg("/bin/sh")
                .arg("-c")
                .arg(command);
            cmd.env("RAILYARD_SANDBOXED", "1");

            let err = cmd.exec();
            eprintln!("railyard-shell: exec bwrap failed: {}", err);
            return ExitCode::from(127);
        }
    }

    // bwrap not available — fall through
    exec_bare_command(command)
}

/// Execute command with bare /bin/sh (no sandbox).
fn exec_bare_command(command: &str) -> ExitCode {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .exec();
        eprintln!("railyard-shell: exec failed: {}", err);
        ExitCode::from(127)
    }

    #[cfg(not(unix))]
    {
        let status = Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        match status {
            Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
            Err(_) => ExitCode::from(127),
        }
    }
}

/// Pass through all args to /bin/sh (interactive mode or no -c flag).
fn exec_bare(args: &[String]) -> ExitCode {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new("/bin/sh");
        for arg in &args[1..] {
            cmd.arg(arg);
        }
        let err = cmd.exec();
        eprintln!("railyard-shell: exec failed: {}", err);
        ExitCode::from(127)
    }

    #[cfg(not(unix))]
    {
        let mut cmd = Command::new("/bin/sh");
        for arg in &args[1..] {
            cmd.arg(arg);
        }
        let status = cmd
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();
        match status {
            Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
            Err(_) => ExitCode::from(127),
        }
    }
}
