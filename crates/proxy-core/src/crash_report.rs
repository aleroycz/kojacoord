//! Crash reporting.
//!
//! When the proxy dies unexpectedly — a panic on any thread, or a fatal
//! error out of the accept loop — we write a single self-contained report
//! to `logs/crash-report-<timestamp>.txt` describing *everything* about the
//! failure: what happened, where, the recent activity that led up to it, a
//! full stack trace, runtime/version/server details, and the process memory
//! map (loaded modules). It is the first thing to attach to a bug report.
//!
//! Three moving parts:
//!   - a **breadcrumb ring** ([`record`]) — the "last actions" trail. It is
//!     fed automatically from `tracing` events by the breadcrumb layer the
//!     binary installs, so anything already logged shows up here for free.
//!   - **metadata** ([`set_metadata`]) — a curated, *secret-free* snapshot
//!     of version/server/runtime info, set once at startup.
//!   - the **panic hook** ([`install_panic_hook`]) and [`report_fatal_error`]
//!     — the two entry points that actually build and write a report.
//!
//! Sensitive-data policy: the report deliberately never includes auth
//! tokens, database URLs, RSA keys, or raw config. Free-text (breadcrumbs,
//! panic messages) is run through [`redact`], which strips IPv4 addresses so
//! a connection log line can't leak a player's IP into a shared report.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

/// How many recent actions to keep. Sized to comfortably cover the run-up to
/// a crash without bloating the report.
const MAX_BREADCRUMBS: usize = 150;

/// Cap on memory-map lines so a process with thousands of mappings can't
/// produce a multi-megabyte report.
const MAX_MEMMAP_LINES: usize = 400;

fn breadcrumbs() -> &'static Mutex<VecDeque<String>> {
    static BREADCRUMBS: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();
    BREADCRUMBS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_BREADCRUMBS)))
}

/// Append one action to the breadcrumb trail. Cheap and lock-guarded; safe to
/// call from anywhere, including inside the panic hook. The text is redacted
/// before storage so secrets/IPs never enter the ring.
pub fn record(action: impl AsRef<str>) {
    let line = format!(
        "[{}] {}",
        chrono::Local::now().format("%H:%M:%S%.3f"),
        redact(action.as_ref())
    );
    if let Ok(mut ring) = breadcrumbs().lock() {
        if ring.len() == MAX_BREADCRUMBS {
            ring.pop_front();
        }
        ring.push_back(line);
    }
}

/// Curated, secret-free snapshot of the running proxy. Set once at startup
/// via [`set_metadata`]; read by the crash builder.
#[derive(Clone)]
pub struct CrashMetadata {
    pub version: String,
    pub server_id: String,
    pub bind: String,
    pub online_mode: bool,
    pub max_players: usize,
    pub plugins_loaded: usize,
    /// Monotonic start instant, for uptime.
    pub started_at: Instant,
}

fn metadata_slot() -> &'static OnceLock<CrashMetadata> {
    static META: OnceLock<CrashMetadata> = OnceLock::new();
    &META
}

/// Record the startup metadata. Idempotent — only the first call wins.
pub fn set_metadata(meta: CrashMetadata) {
    let _ = metadata_slot().set(meta);
}

/// Install the global panic hook. Call once, as early in `main` as possible
/// (before any worker threads spawn) so panics anywhere are captured. The
/// previous hook is preserved and still runs, so the usual panic message is
/// still printed to stderr.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Extract without naming the hook-info type (keeps us compatible
        // across the PanicInfo→PanicHookInfo rename).
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_string());
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown location>".to_string());
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();

        // Never let report generation itself abort the process.
        let written = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_report(
                "Unexpected panic",
                &format!("thread '{thread}' panicked at {location}"),
                &redact(&message),
                Some(std::backtrace::Backtrace::force_capture()),
            )
        }));
        match written {
            Ok(Ok(path)) => {
                eprintln!(
                    "\n// Kojacoord crashed. A crash report was saved to:\n//   {}\n",
                    path.display()
                );
            },
            _ => eprintln!("\n// Kojacoord crashed, and the crash report could not be written.\n"),
        }

        previous(info);
    }));
}

/// Write a crash report for a fatal (non-panic) error — e.g. the accept loop
/// returning `Err`. Returns the path written, if any.
pub fn report_fatal_error(
    context: &str,
    error: &dyn std::fmt::Display,
) -> Option<std::path::PathBuf> {
    write_report(
        "Fatal error",
        context,
        &redact(&error.to_string()),
        Some(std::backtrace::Backtrace::force_capture()),
    )
    .ok()
}

/// Build the full report text and write it to `logs/crash-report-<ts>.txt`.
fn write_report(
    kind: &str,
    description: &str,
    cause: &str,
    backtrace: Option<std::backtrace::Backtrace>,
) -> std::io::Result<std::path::PathBuf> {
    let now = chrono::Local::now();
    let report = build_report(kind, description, cause, backtrace, now);

    std::fs::create_dir_all("logs")?;
    let path = std::path::PathBuf::from(format!(
        "logs/crash-report-{}.txt",
        now.format("%Y-%m-%d_%H-%M-%S")
    ));
    std::fs::write(&path, report)?;
    Ok(path)
}

fn build_report(
    kind: &str,
    description: &str,
    cause: &str,
    backtrace: Option<std::backtrace::Backtrace>,
    now: chrono::DateTime<chrono::Local>,
) -> String {
    let mut out = String::with_capacity(8 * 1024);

    out.push_str("---- Kojacoord Crash Report ----\n\n");
    out.push_str("// ");
    out.push_str(witty_line(now.timestamp_subsec_nanos()));
    out.push_str("\n\n");

    out.push_str(&format!("Time: {}\n", now.format("%Y-%m-%d %H:%M:%S %:z")));
    out.push_str(&format!("Description: {kind} — {description}\n\n"));

    out.push_str("Caused by:\n");
    out.push_str(&indent(cause));
    out.push_str("\n\n");

    out.push_str(
        "A detailed walkthrough of the error, its surrounding state, and all known\n\
         details is as follows:\n",
    );
    out.push_str(&"-".repeat(78));
    out.push('\n');

    // -- Last actions --
    out.push_str("\n-- Last Actions (oldest first) --\n");
    out.push_str("Details:\n");
    let trail = breadcrumbs()
        .lock()
        .map(|r| r.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    if trail.is_empty() {
        out.push_str("\t(no actions recorded)\n");
    } else {
        for line in trail {
            out.push('\t');
            out.push_str(&line);
            out.push('\n');
        }
    }

    // -- Stacktrace --
    out.push_str("\n-- Stacktrace --\n");
    match backtrace {
        Some(bt) => {
            // `Backtrace` is only resolved when RUST_BACKTRACE is enabled or
            // force-captured; say so explicitly if it's empty.
            let text = format!("{bt}");
            if text.trim().is_empty() || text.contains("disabled backtrace") {
                out.push_str(
                    "\t(backtrace unavailable — run with RUST_BACKTRACE=1 for symbol detail)\n",
                );
            } else {
                out.push_str(&indent(&text));
                out.push('\n');
            }
        },
        None => out.push_str("\t(not captured)\n"),
    }

    // -- System details --
    out.push_str("\n-- System Details --\n");
    out.push_str("Details:\n");
    for (k, v) in system_details() {
        out.push_str(&format!("\t{k}: {v}\n"));
    }

    // -- Memory map / loaded modules --
    out.push_str("\n-- Memory Map / Loaded Modules --\n");
    out.push_str("Details:\n");
    out.push_str(&memory_map());
    out.push('\n');

    out.push_str(&format!(
        "\n#@!@# Kojacoord crashed. Everything above is yours to share — secrets and\n\
         IP addresses have been stripped. ({})\n",
        now.format("%Y-%m-%d %H:%M:%S")
    ));

    out
}

/// Curated, secret-free runtime + version + server facts.
fn system_details() -> Vec<(String, String)> {
    let mut d = Vec::new();
    if let Some(meta) = metadata_slot().get() {
        d.push(("Kojacoord Version".into(), meta.version.clone()));
        d.push(("Server ID".into(), meta.server_id.clone()));
        d.push(("Bind Address".into(), meta.bind.clone()));
        d.push(("Online Mode".into(), meta.online_mode.to_string()));
        d.push(("Max Players".into(), meta.max_players.to_string()));
        d.push(("Plugins Loaded".into(), meta.plugins_loaded.to_string()));
        d.push((
            "Uptime".into(),
            humanize_duration(meta.started_at.elapsed()),
        ));
    } else {
        d.push((
            "Kojacoord Version".into(),
            "(metadata not yet initialised — crashed during startup)".into(),
        ));
    }

    d.push(("Operating System".into(), os_description()));
    d.push((
        "CPU Cores".into(),
        std::thread::available_parallelism()
            .map(|n| n.get().to_string())
            .unwrap_or_else(|_| "unknown".into()),
    ));
    d.push(("Process ID".into(), std::process::id().to_string()));
    let (used, total, peak) = memory_usage();
    d.push((
        "Memory".into(),
        format!("{used} in use / {total} total (peak {peak})"),
    ));
    d
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Strip data we never want in a shareable report. Currently IPv4 addresses
/// (the most common PII to leak via connection logs); the port is kept since
/// it isn't sensitive. Extend here if new sensitive shapes appear.
pub fn redact(text: &str) -> String {
    redact_ipv4(text)
}

fn redact_ipv4(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        // Only treat this position as a candidate IP start if the preceding
        // byte isn't a digit or dot — otherwise a 5+-part version string like
        // `1.2.3.4.5` would have its inner `2.3.4.5` matched as an address.
        let left_boundary_ok = i == 0 || !matches!(bytes[i - 1], b'0'..=b'9' | b'.');
        if left_boundary_ok {
            if let Some(len) = match_ipv4(&bytes[i..]) {
                out.push_str("[redacted-ip]");
                i += len;
                continue;
            }
        }
        {
            // Push one UTF-8 char to stay valid.
            let ch_len = utf8_len(bytes[i]);
            out.push_str(&text[i..i + ch_len]);
            i += ch_len;
        }
    }
    out
}

/// If `s` starts with a dotted-quad IPv4 literal, return its byte length.
fn match_ipv4(s: &[u8]) -> Option<usize> {
    let mut pos = 0;
    for octet in 0..4 {
        if octet > 0 {
            if s.get(pos) != Some(&b'.') {
                return None;
            }
            pos += 1;
        }
        let start = pos;
        while pos < s.len() && s[pos].is_ascii_digit() && pos - start < 3 {
            pos += 1;
        }
        if pos == start {
            return None; // no digits
        }
    }
    // Reject if the next char would make it part of a longer number (e.g. a
    // version like 1.2.3.4.5) — require a non-digit, non-dot boundary.
    if matches!(s.get(pos), Some(b) if b.is_ascii_digit() || *b == b'.') {
        return None;
    }
    Some(pos)
}

fn utf8_len(first: u8) -> usize {
    match first {
        b if b < 0x80 => 1,
        b if b >> 5 == 0b110 => 2,
        b if b >> 4 == 0b1110 => 3,
        _ => 4,
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn indent(text: &str) -> String {
    text.lines()
        .map(|l| format!("\t{l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn humanize_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn witty_line(seed: u32) -> &'static str {
    const LINES: &[&str] = &[
        "Don't worry, it's not your fault. Probably.",
        "This is a job for a crash report!",
        "Oops. We tripped over a packet.",
        "Everything was fine until it wasn't.",
        "I bet this didn't happen in testing.",
        "Hold my keepalive.",
    ];
    LINES[(seed as usize) % LINES.len()]
}

fn os_description() -> String {
    let base = format!("{} ({})", std::env::consts::OS, std::env::consts::ARCH);
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            for line in content.lines() {
                if let Some(name) = line.strip_prefix("PRETTY_NAME=") {
                    return format!("{} — {base}", name.trim_matches('"'));
                }
            }
        }
    }
    base
}

// ---------------------------------------------------------------------------
// Platform: memory usage + memory map
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn memory_usage() -> (String, String, String) {
    fn field(content: &str, key: &str) -> Option<u64> {
        content.lines().find_map(|l| {
            l.strip_prefix(key).and_then(|rest| {
                rest.trim()
                    .trim_end_matches(" kB")
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
        })
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let used = field(&status, "VmRSS:")
        .map(kib)
        .unwrap_or_else(|| "?".into());
    let peak = field(&status, "VmHWM:")
        .map(kib)
        .unwrap_or_else(|| "?".into());
    let total = field(&meminfo, "MemTotal:")
        .map(kib)
        .unwrap_or_else(|| "?".into());
    (used, total, peak)
}

#[cfg(target_os = "linux")]
fn kib(kib: u64) -> String {
    human_bytes(kib * 1024)
}

#[cfg(target_os = "linux")]
fn memory_map() -> String {
    match std::fs::read_to_string("/proc/self/maps") {
        Ok(maps) => {
            let mut out = String::new();
            for line in maps.lines().take(MAX_MEMMAP_LINES) {
                out.push('\t');
                out.push_str(line);
                out.push('\n');
            }
            if maps.lines().count() > MAX_MEMMAP_LINES {
                out.push_str(&format!(
                    "\t… ({} more mappings omitted)\n",
                    maps.lines().count() - MAX_MEMMAP_LINES
                ));
            }
            out
        },
        Err(e) => format!("\t(unavailable: {e})\n"),
    }
}

#[cfg(windows)]
fn memory_usage() -> (String, String, String) {
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::GetCurrentProcess;

    let (mut used, mut peak, mut total) = ("?".to_string(), "?".to_string(), "?".to_string());

    // SAFETY: both calls receive correctly-sized, locally-owned out-params
    // whose `cb`/`dwLength` we set first, exactly as the API requires.
    unsafe {
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        if K32GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut pmc,
            std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        )
        .as_bool()
        {
            used = human_bytes(pmc.WorkingSetSize as u64);
            peak = human_bytes(pmc.PeakWorkingSetSize as u64);
        }

        let mut mem = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut mem).is_ok() {
            total = human_bytes(mem.ullTotalPhys);
        }
    }
    (used, total, peak)
}

#[cfg(windows)]
fn memory_map() -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
        TH32CS_SNAPMODULE32,
    };

    // SAFETY: ToolHelp snapshot of our own modules; every out-param is a
    // stack local with `dwSize` set before first use, and the snapshot handle
    // is closed on every exit path.
    unsafe {
        let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, 0) {
            Ok(h) => h,
            Err(e) => return format!("\t(module enumeration unavailable: {e})\n"),
        };

        let mut entry = MODULEENTRY32W {
            dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
            ..Default::default()
        };

        let mut out = String::new();
        let mut count = 0usize;
        if Module32FirstW(snapshot, &mut entry).is_ok() {
            loop {
                if count < MAX_MEMMAP_LINES {
                    let name = wide_to_string(&entry.szModule);
                    out.push_str(&format!(
                        "\t{:016p}  {:>10}  {}\n",
                        entry.modBaseAddr,
                        human_bytes(entry.modBaseSize as u64),
                        name
                    ));
                }
                count += 1;
                if Module32NextW(snapshot, &mut entry).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snapshot);
        if count > MAX_MEMMAP_LINES {
            out.push_str(&format!(
                "\t… ({} more modules omitted)\n",
                count - MAX_MEMMAP_LINES
            ));
        }
        if out.is_empty() {
            out.push_str("\t(no modules enumerated)\n");
        }
        out
    }
}

#[cfg(windows)]
fn wide_to_string(wide: &[u16]) -> String {
    let end = wide.iter().position(|&c| c == 0).unwrap_or(wide.len());
    String::from_utf16_lossy(&wide[..end])
}

// --- macOS -----------------------------------------------------------------
// No `/proc` on macOS. The "memory map" is the set of loaded Mach-O images
// (the dyld image list — the analogue of Windows' module list); memory
// figures come from `sysctl hw.memsize` (total) and `task_info` (resident /
// peak). All three use stable libSystem symbols, so no extra dependency.

#[cfg(target_os = "macos")]
fn memory_usage() -> (String, String, String) {
    extern "C" {
        fn sysctlbyname(
            name: *const std::os::raw::c_char,
            oldp: *mut std::os::raw::c_void,
            oldlenp: *mut usize,
            newp: *mut std::os::raw::c_void,
            newlen: usize,
        ) -> std::os::raw::c_int;
        static mach_task_self_: u32;
        fn task_info(
            task: u32,
            flavor: u32,
            info: *mut u32,
            count: *mut u32,
        ) -> std::os::raw::c_int;
    }

    // Total physical memory.
    let total = {
        let mut value: u64 = 0;
        let mut size = std::mem::size_of::<u64>();
        // SAFETY: out-param and its length match a u64; name is NUL-terminated.
        let rc = unsafe {
            sysctlbyname(
                b"hw.memsize\0".as_ptr() as *const std::os::raw::c_char,
                &mut value as *mut _ as *mut _,
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc == 0 {
            human_bytes(value)
        } else {
            "?".into()
        }
    };

    // Resident + peak via MACH_TASK_BASIC_INFO. We read the result as raw
    // bytes (resident_size at offset 8, resident_size_max at 16) to stay
    // independent of the exact struct layout.
    const MACH_TASK_BASIC_INFO: u32 = 20;
    const COUNT: u32 = 12; // sizeof(mach_task_basic_info) / sizeof(natural_t)
    let mut buf = [0u8; 64];
    let mut count = COUNT;
    // SAFETY: `buf` is large enough for the flavor; `count` is set first.
    let kr = unsafe {
        task_info(
            mach_task_self_,
            MACH_TASK_BASIC_INFO,
            buf.as_mut_ptr() as *mut u32,
            &mut count,
        )
    };
    let (used, peak) = if kr == 0 {
        let resident = u64::from_ne_bytes(buf[8..16].try_into().unwrap());
        let resident_max = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
        (human_bytes(resident), human_bytes(resident_max))
    } else {
        ("?".into(), "?".into())
    };

    (used, total, peak)
}

#[cfg(target_os = "macos")]
fn memory_map() -> String {
    extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_name(image_index: u32) -> *const std::os::raw::c_char;
        fn _dyld_get_image_header(image_index: u32) -> *const std::os::raw::c_void;
    }

    // SAFETY: the dyld image APIs are read-only queries over the current
    // process's already-loaded images; indices stay within the live count.
    let count = unsafe { _dyld_image_count() };
    let mut out = String::new();
    for i in 0..count.min(MAX_MEMMAP_LINES as u32) {
        let header = unsafe { _dyld_get_image_header(i) };
        let name_ptr = unsafe { _dyld_get_image_name(i) };
        let name = if name_ptr.is_null() {
            "<unknown>".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(name_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        out.push_str(&format!("\t{header:016p}  {name}\n"));
    }
    if count as usize > MAX_MEMMAP_LINES {
        out.push_str(&format!(
            "\t… ({} more images omitted)\n",
            count as usize - MAX_MEMMAP_LINES
        ));
    }
    if out.is_empty() {
        out.push_str("\t(no images enumerated)\n");
    }
    out
}

// --- other platforms -------------------------------------------------------

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn memory_usage() -> (String, String, String) {
    ("?".into(), "?".into(), "?".into())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn memory_map() -> String {
    "\t(memory map not supported on this platform)\n".into()
}

/// Human-readable byte size (binary units).
fn human_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_ipv4_keeps_port() {
        assert_eq!(
            redact("New connection from 192.168.1.42:51234"),
            "New connection from [redacted-ip]:51234"
        );
    }

    #[test]
    fn does_not_redact_versions() {
        // A 4-part version is not an IP boundary (trailing dot/digit guard).
        assert_eq!(redact("proto 1.2.3.4.5 ok"), "proto 1.2.3.4.5 ok");
        // But a clean dotted quad is redacted.
        assert_eq!(redact("ip=10.0.0.1 done"), "ip=[redacted-ip] done");
    }

    #[test]
    fn redaction_preserves_unicode() {
        assert_eq!(redact("héllo ✦ 8.8.8.8"), "héllo ✦ [redacted-ip]");
    }

    #[test]
    fn breadcrumbs_round_trip_and_cap() {
        for i in 0..(MAX_BREADCRUMBS + 10) {
            record(format!("action {i}"));
        }
        let len = breadcrumbs().lock().unwrap().len();
        assert_eq!(len, MAX_BREADCRUMBS, "ring must cap");
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1024 * 1024 * 3), "3.0 MiB");
    }

    #[test]
    fn report_fatal_error_writes_a_file() {
        let err = std::io::Error::other("synthetic backend failure");
        let path = report_fatal_error("smoke test", &err).expect("should write a report");
        assert!(path.exists(), "crash report file must exist");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("Fatal error"));
        assert!(contents.contains("synthetic backend failure"));
        assert!(contents.contains("System Details"));
        let _ = std::fs::remove_file(&path); // keep the test dir tidy
    }

    #[test]
    fn report_contains_core_sections() {
        record("did a thing");
        let now = chrono::Local::now();
        let r = build_report(
            "Unexpected panic",
            "thread 'main' panicked at src/x.rs:1:1",
            "boom",
            None,
            now,
        );
        assert!(r.contains("Kojacoord Crash Report"));
        assert!(r.contains("Caused by:"));
        assert!(r.contains("Last Actions"));
        assert!(r.contains("System Details"));
        assert!(r.contains("Memory Map"));
    }
}
