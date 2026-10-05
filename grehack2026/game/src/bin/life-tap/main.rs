// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! `life-tap`: watch the game of life's gRPC traffic, and keep every
//! message as a `.pb` file prototools opens directly (spec 0375 S6).
//!
//! A wrapper around Wireshark's command-line tools. dumpcap captures the
//! loopback traffic on the port; the tap keeps it as a pcapng and feeds it
//! to tshark, which decodes gRPC as it arrives — the equivalent of
//! `dumpcap -w - | tee capture.pcapng | tshark -r - …`, which the tap
//! prints when it starts, to be copied and adapted.

mod tracker;

use clap::Parser;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{chown, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tracker::Tracker;

const CAPTURE_HELP: &str = "\
Capturing needs privilege, for dumpcap alone (spec 0393):
  on a Linux machine          sudo -v, then life-tap as yourself: it runs
                              dumpcap with sudo -n, and tshark as you
  in the workshop container   podman exec -it workshop life-tap
                              docker exec -it -u 0 workshop life-tap
  on NixOS, without sudo      programs.wireshark.enable = true, and your
                              user in the wireshark group";

#[derive(Parser)]
#[command(
    about = "Watch the game of life's gRPC traffic, and keep every message as a .pb file",
    long_about = "Captures the gRPC traffic of life-server and life-client on the \
        loopback interface, prints one line per message, and writes each message to \
        DIR/NNNNNN-request.pb or DIR/NNNNNN-response.pb (a request and its response \
        share NNNNNN), the whole capture to DIR/capture.pcapng, and what it prints \
        to DIR/tap.log.",
    after_help = CAPTURE_HELP
)]
struct Args {
    /// The server's port.
    #[arg(long, default_value_t = 50051)]
    port: u16,

    /// Where to write [default: /work/capture, or ./capture where there is
    /// no /work].
    #[arg(long)]
    out: Option<PathBuf>,

    /// .proto files for tshark: the printed lines then name each message's
    /// type and fields.
    #[arg(long)]
    proto_path: Option<PathBuf>,

    /// Stop the tap writing to the output directory (one started detached).
    #[arg(long)]
    stop: bool,

    /// Leave out the startup block of dumpcap and tshark commands to adapt
    /// (spec 0393 S4). The per-message lines and the summary still print.
    #[arg(short, long)]
    quiet: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let out = match &args.out {
        Some(dir) => absolute(dir),
        None if Path::new("/work").is_dir() => PathBuf::from("/work/capture"),
        None => absolute(Path::new("capture")),
    };
    let result = if args.stop {
        stop(&out)
    } else {
        tap(&args, &out)
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("life-tap: {e}");
            ExitCode::FAILURE
        }
    }
}

fn absolute(path: &Path) -> PathBuf {
    std::env::current_dir()
        .map(|cwd| cwd.join(path))
        .unwrap_or_else(|_| path.to_path_buf())
}

fn pid_file(out: &Path) -> PathBuf {
    out.join("tap.pid")
}

fn alive(pid: i32) -> bool {
    // SAFETY: signal 0 only checks that the process exists.
    unsafe { libc::kill(pid, 0) == 0 }
}

fn signal(pid: u32, sig: i32) {
    // SAFETY: plain kill(2) on a process we started or were told about.
    unsafe {
        libc::kill(pid as i32, sig);
    }
}

// ── --stop ───────────────────────────────────────────────────────────────────

/// Stop the tap writing to `out`, and return once it has finished — its
/// files complete. A tap behind on a burst of traffic writes its backlog
/// first.
fn stop(out: &Path) -> Result<ExitCode, String> {
    let pid_file = pid_file(out);
    let pid: i32 = fs::read_to_string(&pid_file)
        .map_err(|_| format!("no tap is writing to {} (no tap.pid there)", out.display()))?
        .trim()
        .parse()
        .map_err(|e| format!("{}: {e}", pid_file.display()))?;
    // SAFETY: kill(2) with a pid read from the tap's own pid file.
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return Err(format!(
            "tap {pid} is not running (stale {}?)",
            pid_file.display()
        ));
    }
    let started = Instant::now();
    let mut told = false;
    while pid_file.exists() {
        if !alive(pid) {
            return Err(format!(
                "tap {pid} died without removing {}",
                pid_file.display()
            ));
        }
        if !told && started.elapsed() > Duration::from_secs(2) {
            println!("life-tap: waiting for tap {pid} to write its last messages");
            told = true;
        }
        if started.elapsed() > Duration::from_secs(120) {
            return Err(format!("tap {pid} did not stop within 120 s"));
        }
        thread::sleep(Duration::from_millis(100));
    }
    Ok(ExitCode::SUCCESS)
}

// ── Who the files are for, and how to capture ────────────────────────────────

/// The user the tap works for, who gets every file it writes: the one who
/// ran sudo, or the owner of the workshop's /work; otherwise the tap's own.
fn owner() -> (u32, u32) {
    let env = |name| std::env::var(name).ok().and_then(|v| v.parse::<u32>().ok());
    if let Some(uid) = env("SUDO_UID") {
        return (uid, env("SUDO_GID").unwrap_or(uid));
    }
    if let Ok(meta) = fs::metadata("/work") {
        return (meta.uid(), meta.gid());
    }
    // SAFETY: getuid and getgid cannot fail.
    unsafe { (libc::getuid(), libc::getgid()) }
}

/// How the tap runs dumpcap (spec 0393 S1). tshark always runs as the
/// tap's own user.
#[derive(Debug, PartialEq)]
enum Dumpcap {
    /// Run as is: NixOS's capability wrapper, or plain dumpcap when the tap
    /// is root already (the workshop container).
    Direct(String),
    /// `sudo -n <path>`: the tap runs as the user, and dumpcap alone gets
    /// root. `-n` never prompts, since a tap in the background cannot read
    /// a password.
    Sudo(String),
}

impl Dumpcap {
    fn command(&self) -> Command {
        match self {
            Dumpcap::Direct(path) => Command::new(path),
            Dumpcap::Sudo(path) => {
                let mut command = Command::new("sudo");
                command.arg("-n").arg(path);
                command
            }
        }
    }

    /// The command line as the startup block prints it.
    fn shown(&self, args: &[String]) -> String {
        match self {
            Dumpcap::Direct(path) => words(path, args),
            Dumpcap::Sudo(path) => format!("sudo {}", words(path, args)),
        }
    }
}

const WRAPPER: &str = "/run/wrappers/bin/dumpcap";

/// Spec 0393 S1's order: the NixOS wrapper (`wrapper_usable`), then plain
/// dumpcap when the tap is `root`, then `sudo -n` on dumpcap's path.
fn choose_dumpcap(
    wrapper_usable: bool,
    root: bool,
    on_path: Option<String>,
) -> Result<Dumpcap, String> {
    if wrapper_usable {
        return Ok(Dumpcap::Direct(WRAPPER.to_string()));
    }
    if root {
        return Ok(Dumpcap::Direct("dumpcap".to_string()));
    }
    on_path.map(Dumpcap::Sudo).ok_or_else(|| {
        "dumpcap is not on PATH: run the tap from the grehack2026 demo shell \
         (cd grehack2026 && nix-shell, spec 0394)"
            .to_string()
    })
}

/// The dumpcap to run (spec 0393 S1). In the `sudo` case, the credentials
/// are checked here, without running anything (`sudo -n -v`), so that a
/// tap with none fails before it creates a file or starts tshark.
fn dumpcap() -> Result<Dumpcap, String> {
    let usable = Command::new(WRAPPER)
        .arg("-v")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    // SAFETY: geteuid cannot fail.
    let root = unsafe { libc::geteuid() } == 0;
    let chosen = choose_dumpcap(usable, root, find_on_path("dumpcap"))?;
    if matches!(chosen, Dumpcap::Sudo(_)) {
        let cached = Command::new("sudo")
            .args(["-n", "-v"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !cached {
            return Err(format!(
                "capturing needs root: run `sudo -v` first, then start the tap again\n\n\
                 {CAPTURE_HELP}"
            ));
        }
    }
    Ok(chosen)
}

/// `name`'s full path, from PATH: `sudo` resets PATH, so the demo shell's
/// dumpcap is passed to it by path.
fn find_on_path(name: &str) -> Option<String> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|p| p.is_file())
            .map(|p| p.to_string_lossy().into_owned())
    })
}

/// Give a file or directory the tap created to the user it works for. A
/// failure is not the tap's business (a macOS bind mount may refuse it).
fn give(path: &Path, (uid, gid): (u32, u32)) {
    let _ = chown(path, Some(uid), Some(gid));
}

/// The number the next call takes: after the highest already in `out`, so
/// a second run adds to the first rather than overwriting it.
fn next_call(out: &Path) -> u64 {
    fs::read_dir(out)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let (num, rest) = name.split_once('-')?;
            (num.len() == 6 && rest.ends_with(".pb"))
                .then(|| num.parse::<u64>().ok())
                .flatten()
        })
        .max()
        .map_or(1, |n| n + 1)
}

// ── Output ───────────────────────────────────────────────────────────────────

/// What the tap prints goes to the terminal and to `tap.log`.
struct Log {
    file: File,
}

impl Log {
    fn say(&mut self, line: &str) {
        println!("{line}");
        let _ = writeln!(self.file, "{line}");
    }
}

/// An argument as a shell word: bare when safe, single-quoted otherwise.
fn word(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_./:=,+@%-".contains(c));
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

fn words(program: &str, args: &[String]) -> String {
    std::iter::once(word(program))
        .chain(args.iter().map(|a| word(a)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Local time of day, `HH:MM:SS.mmm`.
fn clock(epoch: f64) -> String {
    let secs = epoch.trunc() as libc::time_t;
    // SAFETY: localtime_r writes into the tm we own.
    let tm = unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&secs, &mut tm);
        tm
    };
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        (epoch.fract() * 1000.0) as u32
    )
}

// ── The tap ──────────────────────────────────────────────────────────────────

fn tap(args: &Args, out: &Path) -> Result<ExitCode, String> {
    let owner = owner();
    let dumpcap = dumpcap()?;

    let pid_file = pid_file(out);
    if let Some(pid) = fs::read_to_string(&pid_file)
        .ok()
        .and_then(|p| p.trim().parse::<i32>().ok())
    {
        if alive(pid) {
            return Err(format!(
                "a tap is already writing to {} (pid {pid}); life-tap --stop stops it",
                out.display()
            ));
        }
    }
    if !out.is_dir() {
        fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
        give(out, owner);
    }

    let pcap_path = out.join("capture.pcapng");
    let log_path = out.join("tap.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("opening {}: {e}", log_path.display()))?;
    give(&log_path, owner);
    let log = Arc::new(Mutex::new(Log { file: log_file }));
    let say = |line: &str| log.lock().unwrap().say(line);

    // -B: a 64 MiB kernel buffer, so a burst of large messages on the
    // loopback is not dropped before dumpcap reads it.
    let dumpcap_args: Vec<String> = [
        "-q",
        "-i",
        "lo",
        "-f",
        &format!("tcp port {}", args.port),
        "-B",
        "64",
        "-w",
        "-",
    ]
    .map(String::from)
    .to_vec();
    // `-r -`, reading the stream as a file, rather than `-i -`, a live
    // capture from stdin: that starts a dumpcap of tshark's own, spooling to
    // a temporary file, and an end of input arriving while it settles in
    // (the first seconds, in a container) lost everything not yet
    // processed. `-r -` prints each message as it arrives all the same, and
    // drains to the end. Cleartext HTTP/2 on a port other than 80 is not
    // recognized on its own, hence `-d`.
    let mut tshark_args: Vec<String> = [
        "-l",
        "-n",
        "-r",
        "-",
        "-d",
        &format!("tcp.port=={},http2", args.port),
        "-Y",
        tracker::FILTER,
        "-T",
        "fields",
        "-E",
        &format!("separator={}", tracker::SEPARATOR),
    ]
    .map(String::from)
    .to_vec();
    let mut fields: Vec<&str> = tracker::FIELDS.to_vec();
    if let Some(dir) = &args.proto_path {
        let dir = absolute(dir);
        tshark_args.push("-o".into());
        // The second field is "load all": tshark must read every file up
        // front to learn the service, which maps the method path to its
        // messages; on demand, through imports, it never does.
        tshark_args.push(format!(
            "uat:protobuf_search_paths:\"{}\",\"TRUE\"",
            dir.display()
        ));
        fields.extend(tracker::PROTO_FIELDS);
    }
    for f in fields {
        tshark_args.push("-e".into());
        tshark_args.push(f.into());
    }

    say(&format!(
        "life-tap: capturing gRPC on port {} into {}",
        args.port,
        out.display()
    ));
    if !args.quiet {
        for line in startup_block(&dumpcap, &dumpcap_args, &pcap_path, &tshark_args) {
            say(&line);
        }
    }

    let pcap = File::create(&pcap_path).map_err(|e| format!("{}: {e}", pcap_path.display()))?;
    give(&pcap_path, owner);

    // Both in a process group of their own: a Ctrl-C in the terminal
    // reaches the tap alone, which stops dumpcap and lets tshark drain.
    let mut tshark = Command::new("tshark")
        .args(&tshark_args)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| starting("tshark", &e))?;
    let mut capture = dumpcap
        .command()
        .args(&dumpcap_args)
        .process_group(0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| starting("dumpcap", &e))?;
    fs::write(&pid_file, format!("{}\n", std::process::id()))
        .map_err(|e| format!("{}: {e}", pid_file.display()))?;

    let tee = {
        let mut from = capture.stdout.take().expect("piped");
        let mut to = tshark.stdin.take().expect("piped");
        let mut pcap = pcap;
        thread::spawn(move || -> io::Result<()> {
            let mut buf = vec![0u8; 1 << 16];
            loop {
                let n = from.read(&mut buf)?;
                if n == 0 {
                    return Ok(()); // dropping `to` closes tshark's input
                }
                pcap.write_all(&buf[..n])?;
                to.write_all(&buf[..n])?;
            }
        })
    };
    // tshark's complaints, shown only if it fails: as root it always warns
    // that running as root "could be dangerous".
    let tshark_err = {
        let mut err = tshark.stderr.take().expect("piped");
        thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            text
        })
    };
    let dumpcap_err = {
        let mut err = capture.stderr.take().expect("piped");
        thread::spawn(move || {
            let mut text = String::new();
            let _ = err.read_to_string(&mut text);
            text
        })
    };
    let reader = {
        let lines = BufReader::new(tshark.stdout.take().expect("piped"));
        let log = Arc::clone(&log);
        let out = out.to_path_buf();
        let mut tracker = Tracker::new(args.port, next_call(&out));
        thread::spawn(move || read(lines, &mut tracker, &out, owner, &log))
    };

    let outcome = run(&mut capture);
    let tee_result = tee.join().expect("the tee does not panic");
    let tshark_status = tshark.wait();
    let summary = reader.join().expect("the reader does not panic");
    let _ = fs::remove_file(&pid_file);

    if let Err(e) = tee_result {
        say(&format!(
            "life-tap: passing the capture on to tshark failed: {e}"
        ));
    }
    if !tshark_status.as_ref().is_ok_and(|s| s.success()) {
        say(&format!(
            "life-tap: tshark failed ({}):",
            tshark_status.map_or_else(|e| e.to_string(), |s| s.to_string())
        ));
        say(tshark_err.join().unwrap_or_default().trim_end());
    }
    match outcome {
        Run::Stopped | Run::Ended => {
            say("");
            say(&summary);
            Ok(ExitCode::SUCCESS)
        }
        Run::Failed => {
            let err = dumpcap_err.join().unwrap_or_default();
            say("life-tap: dumpcap could not capture:");
            say(err.trim_end());
            let lower = err.to_lowercase();
            if lower.contains("permission") || lower.contains("not permitted") {
                say("life-tap: in a container without NET_RAW (rootless Podman's default), start");
                say("          it with --cap-add NET_RAW; elsewhere, run sudo -v before the tap");
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

/// The block of commands to adapt that the tap prints on startup, unless
/// `-q` (spec 0393 S4). Run as root (the container), they are for a root
/// terminal; through `sudo`, for any terminal.
fn startup_block(
    dumpcap: &Dumpcap,
    dumpcap_args: &[String],
    pcap_path: &Path,
    tshark_args: &[String],
) -> Vec<String> {
    let whose = match dumpcap {
        Dumpcap::Sudo(_) => "a terminal",
        Dumpcap::Direct(_) => "a root terminal",
    };
    vec![
        format!("life-tap: the commands, to adapt in {whose} of your own:"),
        format!("  {} \\", dumpcap.shown(dumpcap_args)),
        format!("    | tee {} \\", word(&pcap_path.to_string_lossy())),
        format!("    | {}", words("tshark", tshark_args)),
        String::new(),
    ]
}

/// Why a Wireshark tool did not start, and, when it is not installed, how
/// to get it.
fn starting(program: &str, e: &io::Error) -> String {
    if e.kind() == io::ErrorKind::NotFound {
        format!(
            "{program} is not on PATH: run the tap from the grehack2026 demo shell \
             (cd grehack2026 && nix-shell, spec 0394), or use the Nix-built life-tap \
             (nix-build -A grehack2026.life), which carries it"
        )
    } else {
        format!("starting {program}: {e}")
    }
}

/// How long the tap keeps capturing after being asked to stop.
const STOP_GRACE: Duration = Duration::from_secs(1);

enum Run {
    /// Ctrl-C or SIGTERM.
    Stopped,
    /// dumpcap ended by itself after it had started capturing.
    Ended,
    /// dumpcap failed at the start.
    Failed,
}

/// Wait for Ctrl-C or SIGTERM, then stop dumpcap; or for dumpcap to end.
fn run(capture: &mut Child) -> Run {
    let pid = capture.id();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a tokio runtime");
    runtime.block_on(async {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("installing the SIGTERM handler");
        let started = Instant::now();
        let mut poll = tokio::time::interval(Duration::from_millis(100));
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
                _ = poll.tick() => {
                    if let Ok(Some(status)) = capture.try_wait() {
                        let early = started.elapsed() < Duration::from_secs(2);
                        return if early && !status.success() {
                            Run::Failed
                        } else {
                            Run::Ended
                        };
                    }
                }
            }
        }
        // Capture on for a moment first: dumpcap drops the packets it
        // received just before a SIGTERM (a burst of calls ending under
        // 0.3 s before the stop went unsaved, on this VM; 1 s leaves room
        // for a slower container). Then dumpcap closes its output properly,
        // and the tee and tshark see the end of it and finish.
        tokio::time::sleep(STOP_GRACE).await;
        signal(pid, libc::SIGTERM);
        let _ = capture.wait();
        Run::Stopped
    })
}

/// Read tshark's lines until it ends; return the closing summary.
fn read(
    lines: impl BufRead,
    tracker: &mut Tracker,
    out: &Path,
    owner: (u32, u32),
    log: &Mutex<Log>,
) -> String {
    let say = |line: &str| log.lock().unwrap().say(line);
    for line in lines.lines() {
        let Ok(line) = line else { break };
        let fed = match tracker.feed(&line) {
            Ok(fed) => fed,
            Err(e) => {
                say(&format!("life-tap: skipping a line tshark printed: {e}"));
                continue;
            }
        };
        if fed.first_missed {
            say("life-tap: missing messages: their connection predates the tap, so tshark");
            say("          cannot tell they are gRPC; life-client renews its connection every");
            say("          2 s (--renew-every), and the tap sees the next one whole");
        }
        for m in fed.messages {
            let file = m.file_name();
            let path = out.join(&file);
            if let Err(e) = fs::write(&path, &m.bytes) {
                say(&format!("life-tap: writing {}: {e}", path.display()));
                continue;
            }
            give(&path, owner);
            say(&format!(
                "{} {} {:<28} {:>7} bytes  {file}{}",
                clock(m.time),
                m.dir.arrow(),
                m.path.as_deref().unwrap_or("?"),
                m.bytes.len(),
                m.detail.map_or(String::new(), |d| format!("  {d}"))
            ));
        }
    }
    format!(
        "life-tap: stopped: {} requests and {} responses saved, {} messages missed",
        tracker.requests,
        tracker.responses,
        tracker.missed()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec 0393 test plan 1 (S1): the wrapper first, then root, then
    /// `sudo -n` on dumpcap's path.
    #[test]
    fn dumpcap_is_chosen_wrapper_then_root_then_sudo() {
        let path = Some("/nix/store/x/bin/dumpcap".to_string());
        assert_eq!(
            choose_dumpcap(true, false, path.clone()),
            Ok(Dumpcap::Direct(WRAPPER.to_string()))
        );
        assert_eq!(
            choose_dumpcap(true, true, path.clone()),
            Ok(Dumpcap::Direct(WRAPPER.to_string()))
        );
        assert_eq!(
            choose_dumpcap(false, true, path.clone()),
            Ok(Dumpcap::Direct("dumpcap".to_string()))
        );
        assert_eq!(
            choose_dumpcap(false, false, path.clone()),
            Ok(Dumpcap::Sudo("/nix/store/x/bin/dumpcap".to_string()))
        );
        assert!(choose_dumpcap(false, false, None).is_err());
    }

    /// Spec 0393 S1: through sudo, dumpcap is run as `sudo -n <path>`, and
    /// shown as `sudo <path> …`.
    #[test]
    fn a_sudo_dumpcap_runs_and_shows_through_sudo() {
        let dumpcap = Dumpcap::Sudo("/bin/dumpcap".to_string());
        let command = dumpcap.command();
        assert_eq!(command.get_program(), "sudo");
        let args: Vec<_> = command.get_args().collect();
        assert_eq!(args, ["-n", "/bin/dumpcap"]);
        assert_eq!(dumpcap.shown(&["-q".to_string()]), "sudo /bin/dumpcap -q");
    }

    /// Spec 0393 test plan 2 (S4): the startup block is the heading and
    /// the pipeline; `-q` prints none of it (the caller skips it). Through
    /// sudo, the heading no longer asks for a root terminal.
    #[test]
    fn the_startup_block_names_the_pipeline_and_who_runs_it() {
        let args = ["-q".to_string()];
        let tshark = ["-l".to_string()];
        let pcap = Path::new("/tmp/c/capture.pcapng");
        let sudo = startup_block(&Dumpcap::Sudo("/bin/dumpcap".into()), &args, pcap, &tshark);
        assert_eq!(
            sudo[0],
            "life-tap: the commands, to adapt in a terminal of your own:"
        );
        assert!(sudo[1].starts_with("  sudo /bin/dumpcap -q"), "{}", sudo[1]);
        assert!(sudo[3].contains("tshark -l"), "{}", sudo[3]);
        let root = startup_block(&Dumpcap::Direct("dumpcap".into()), &args, pcap, &tshark);
        assert_eq!(
            root[0],
            "life-tap: the commands, to adapt in a root terminal of your own:"
        );
    }

    #[test]
    fn quiet_is_an_option() {
        let args = Args::try_parse_from(["life-tap", "-q"]).unwrap();
        assert!(args.quiet);
        assert!(!Args::try_parse_from(["life-tap"]).unwrap().quiet);
    }

    #[test]
    fn words_are_quoted_only_when_needed() {
        assert_eq!(word("tcp.port==50051,http2"), "tcp.port==50051,http2");
        assert_eq!(word("tcp port 50051"), "'tcp port 50051'");
        assert_eq!(word("it's"), r"'it'\''s'");
        assert_eq!(word("separator=|"), "'separator=|'");
    }

    #[test]
    fn numbering_continues_after_existing_files() {
        let dir = std::env::temp_dir().join(format!("life-tap-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(next_call(&dir), 1);
        for name in [
            "000007-request.pb",
            "000012-response.pb",
            "capture.pcapng",
            "12-x.pb",
        ] {
            fs::write(dir.join(name), b"").unwrap();
        }
        assert_eq!(next_call(&dir), 13);
        fs::remove_dir_all(&dir).unwrap();
    }
}
