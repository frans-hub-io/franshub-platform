//! The standard Prometheus process metrics (`process_resident_memory_bytes`,
//! `process_virtual_memory_bytes`, `process_cpu_seconds_total`, `process_open_fds`,
//! `process_start_time_seconds`), read from `/proc` at scrape time. Elsewhere than on Linux
//! nothing is read and nothing is rendered.

use std::fmt::Write as _;

/// `USER_HZ`: the unit of the CPU times in `/proc/<pid>/stat`, 100 on every Linux architecture
/// Rust supports (the kernel converts to it whatever its internal `HZ` is).
const TICKS_PER_SECOND: f64 = 100.0;

/// One reading of the process metrics.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ProcessStats {
    /// `process_resident_memory_bytes` (`VmRSS`).
    pub resident_memory_bytes: u64,
    /// `process_virtual_memory_bytes` (`vsize`).
    pub virtual_memory_bytes: u64,
    /// `process_cpu_seconds_total`: user and system time.
    pub cpu_seconds: f64,
    /// `process_open_fds`.
    pub open_fds: u64,
    /// `process_start_time_seconds`: since the Unix epoch.
    pub start_time_seconds: f64,
}

impl ProcessStats {
    /// Reads the current process; `None` where `/proc` is not available.
    pub fn read() -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        let system = std::fs::read_to_string("/proc/stat").ok()?;
        let open_fds = std::fs::read_dir("/proc/self/fd").ok()?.count() as u64;
        parse(&stat, &status, &system, open_fds)
    }

    /// The Prometheus text format of these values, with `HELP` and `TYPE` lines.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(768);
        let mut metric = |name: &str, kind: &str, help: &str, value: String| {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}"
            );
        };
        metric(
            "process_resident_memory_bytes",
            "gauge",
            "Resident memory size in bytes.",
            self.resident_memory_bytes.to_string(),
        );
        metric(
            "process_virtual_memory_bytes",
            "gauge",
            "Virtual memory size in bytes.",
            self.virtual_memory_bytes.to_string(),
        );
        metric(
            "process_cpu_seconds_total",
            "counter",
            "Total user and system CPU time spent in seconds.",
            format!("{}", self.cpu_seconds),
        );
        metric(
            "process_open_fds",
            "gauge",
            "Number of open file descriptors.",
            self.open_fds.to_string(),
        );
        metric(
            "process_start_time_seconds",
            "gauge",
            "Start time of the process since unix epoch in seconds.",
            format!("{}", self.start_time_seconds),
        );
        out
    }
}

/// The process metrics in the Prometheus text format, or an empty string where they cannot be
/// read.
pub fn render() -> String {
    ProcessStats::read().map(|s| s.render()).unwrap_or_default()
}

/// Parses `/proc/self/stat`, `/proc/self/status` and `/proc/stat`.
fn parse(stat: &str, status: &str, system: &str, open_fds: u64) -> Option<ProcessStats> {
    // The command name (field 2) is in parentheses and may contain spaces and parentheses, so
    // the fields are counted from the last `)`: the first one after it is field 3 (`state`).
    let fields: Vec<&str> = stat
        .get(stat.rfind(')')? + 1..)?
        .split_whitespace()
        .collect();
    let field = |n: usize| -> Option<u64> { fields.get(n - 3)?.parse().ok() };
    let utime = field(14)?;
    let stime = field(15)?;
    let start_ticks = field(22)?;
    let virtual_memory_bytes = field(23)?;
    let resident_kib: u64 = status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let boot_time: u64 = system
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())?;
    Some(ProcessStats {
        resident_memory_bytes: resident_kib * 1024,
        virtual_memory_bytes,
        cpu_seconds: (utime + stime) as f64 / TICKS_PER_SECOND,
        open_fds,
        start_time_seconds: boot_time as f64 + start_ticks as f64 / TICKS_PER_SECOND,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str = "4242 (my (odd) name) S 1 4242 4242 0 -1 4194560 2100 0 0 0 250 50 0 0 20 0 \
                        12 0 123456 987654321 2048 18446744073709551615 1 1 0 0 0 0 0 4096 17991 0 0 0 \
                        17 3 0 0 0 0 0";
    const STATUS: &str = "Name:\tmy (odd) name\nVmSize:\t  964506 kB\nVmRSS:\t    8192 kB\n";
    const SYSTEM: &str = "cpu  1 2 3 4\nbtime 1795000000\nprocesses 99\n";

    #[test]
    fn parses_proc_files() {
        let s = parse(STAT, STATUS, SYSTEM, 7).unwrap();
        assert_eq!(
            s,
            ProcessStats {
                resident_memory_bytes: 8192 * 1024,
                virtual_memory_bytes: 987_654_321,
                cpu_seconds: 3.0,
                open_fds: 7,
                start_time_seconds: 1_795_000_000.0 + 1234.56,
            }
        );
        assert!(parse("garbage", STATUS, SYSTEM, 1).is_none());
        assert!(parse(STAT, STATUS, "cpu 1 2\n", 1).is_none());
    }

    #[test]
    fn renders_the_text_format() {
        let text = parse(STAT, STATUS, SYSTEM, 7).unwrap().render();
        assert!(
            text.contains(
                "# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 3\n"
            )
        );
        assert!(text.contains("process_resident_memory_bytes 8388608\n"));
        assert!(text.contains("process_open_fds 7\n"));
        assert!(text.ends_with('\n'));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_this_process() {
        let s = ProcessStats::read().expect("/proc is readable on Linux");
        assert!(s.resident_memory_bytes > 0);
        assert!(s.virtual_memory_bytes >= s.resident_memory_bytes);
        assert!(s.open_fds >= 3);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        assert!(s.start_time_seconds <= now + 1.0 && s.start_time_seconds > now - 86_400.0 * 30.0);
        let burn = std::time::Instant::now();
        let mut x = 0u64;
        while burn.elapsed() < std::time::Duration::from_millis(100) {
            x = std::hint::black_box(x.wrapping_add(1));
        }
        assert!(ProcessStats::read().unwrap().cpu_seconds > s.cpu_seconds);
    }
}
