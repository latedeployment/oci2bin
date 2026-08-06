#!/usr/bin/env python3
"""Benchmark oci2bin artifact startup modes with no Python dependencies."""

import argparse
import datetime
import json
import math
import os
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import inspect_image


MODE_ARGS = {
    "extract": [],
    "lazy": ["--lazy"],
    "vm": ["--vm", "--net", "none"],
}


def percentile(values, quantile):
    """Return a linearly interpolated percentile for a non-empty sequence."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def summarize(samples):
    """Summarize successful timing samples and all exit outcomes."""
    successful = [sample for sample in samples if sample["returncode"] == 0]
    elapsed = [sample["elapsed_ms"] for sample in successful]
    rss = [sample["peak_rss_kib"] for sample in successful
           if sample["peak_rss_kib"] is not None]
    summary = {
        "runs": len(samples),
        "successful_runs": len(successful),
        "success_rate": (len(successful) / len(samples)
                         if samples else 0.0),
    }
    if elapsed:
        summary["latency_ms"] = {
            "min": min(elapsed),
            "median": statistics.median(elapsed),
            "mean": statistics.fmean(elapsed),
            "p95": percentile(elapsed, 0.95),
            "max": max(elapsed),
            "stdev": (statistics.stdev(elapsed)
                      if len(elapsed) > 1 else 0.0),
        }
    if rss:
        summary["peak_rss_kib"] = {
            "median": statistics.median(rss),
            "max": max(rss),
        }
    failures = []
    for sample in samples:
        if sample["returncode"] != 0:
            failures.append({
                "returncode": sample["returncode"],
                "error": sample.get("error", ""),
            })
    if failures:
        summary["failures"] = failures
    return summary


def parse_modes(value):
    modes = []
    for mode in value.split(","):
        mode = mode.strip()
        if not mode:
            continue
        if mode == "all":
            modes.extend(MODE_ARGS)
            continue
        if mode not in MODE_ARGS:
            raise argparse.ArgumentTypeError(
                f"unknown mode {mode!r}; use extract,lazy,vm, or all")
        modes.append(mode)
    if not modes:
        raise argparse.ArgumentTypeError("at least one mode is required")
    # Preserve order while dropping duplicates.
    return list(dict.fromkeys(modes))


def mode_preflight(mode, meta):
    if mode == "lazy":
        if meta.get("rootfs_format", "tar") != "squashfs":
            return ("artifact has no SquashFS rootfs; rebuild with "
                    "--rootfs-format squashfs")
        missing = [name for name in ("squashfuse", "fuse-overlayfs")
                   if shutil.which(name) is None]
        if missing:
            return "missing runtime helper(s): " + ", ".join(missing)
        if not os.access("/dev/fuse", os.R_OK | os.W_OK):
            return "/dev/fuse is absent or inaccessible"
        if os.geteuid() != 0:
            try:
                fuse_config = Path("/etc/fuse.conf").read_text(
                    encoding="utf-8", errors="replace")
            except OSError:
                fuse_config = ""
            enabled = any(
                line.split("#", 1)[0].strip() == "user_allow_other"
                for line in fuse_config.splitlines())
            if not enabled:
                return ("user_allow_other is not enabled in "
                        "/etc/fuse.conf")
    if mode == "vm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "/dev/kvm is absent or inaccessible"
    return None


def _read_peak_rss(path):
    try:
        value = Path(path).read_text(encoding="ascii").strip()
        return int(value) if value else None
    except (OSError, ValueError):
        return None


def measure_once(command, timeout):
    """Run one launch and return wall time, peak RSS, status, and an error."""
    time_binary = "/usr/bin/time"
    time_path = None
    argv = list(command)
    if os.access(time_binary, os.X_OK):
        fd, time_path = tempfile.mkstemp(prefix="oci2bin-benchmark-time.")
        os.close(fd)
        argv = [time_binary, "-f", "%M", "-o", time_path, "--"] + argv

    started = time.perf_counter_ns()
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    timed_out = False
    try:
        _, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(proc.pid, signal.SIGKILL)
        _, stderr = proc.communicate()
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

    peak_rss = _read_peak_rss(time_path) if time_path else None
    if time_path:
        try:
            os.unlink(time_path)
        except OSError:
            pass

    error = stderr.decode(errors="replace").strip()
    if len(error) > 1000:
        error = error[-1000:]
    return {
        "elapsed_ms": elapsed_ms,
        "peak_rss_kib": peak_rss,
        "returncode": 124 if timed_out else proc.returncode,
        "timed_out": timed_out,
        "error": error,
    }


def benchmark_mode(binary, mode, command, runs, warmups, timeout):
    argv = [binary] + MODE_ARGS[mode] + ["--"] + command
    first = measure_once(argv, timeout)
    for _ in range(warmups):
        measure_once(argv, timeout)
    samples = [measure_once(argv, timeout) for _ in range(runs)]
    successful = sum(sample["returncode"] == 0 for sample in samples)
    status = ("ok" if successful == runs
              else "partial" if successful
              else "failed")
    return {
        "mode": mode,
        "command": argv,
        "status": status,
        "first_run": first,
        "summary": summarize(samples),
        "samples": samples,
    }


def host_metadata():
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text(
                encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith(("model name", "hardware")):
                cpu = line.split(":", 1)[-1].strip()
                break
    except OSError:
        pass
    return {
        "system": platform.system(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu": cpu,
        "python": platform.python_version(),
    }


def human_size(size):
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MiB"
    if size >= 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size} B"


def render_human(report):
    lines = [
        f"Artifact: {report['artifact']['path']} "
        f"({human_size(report['artifact']['size_bytes'])})",
        f"Runs: {report['settings']['runs']} measured, "
        f"{report['settings']['warmups']} warmup; "
        f"command: {' '.join(report['settings']['command'])}",
        "",
        ("MODE       STATUS      FIRST       MEDIAN         P95"
         "     RSS MAX    SUCCESS"),
        ("---------- -------- ---------- ------------ -----------"
         " ----------- ----------"),
    ]
    for result in report["results"]:
        if result["status"] == "skipped":
            lines.append(
                f"{result['mode']:<10} skipped    -          -"
                f"            -           -           -")
            lines.append(f"  reason: {result['reason']}")
            continue
        first = result["first_run"]["elapsed_ms"]
        latency = result["summary"].get("latency_ms", {})
        rss = result["summary"].get("peak_rss_kib", {}).get("max")
        rss_text = f"{rss / 1024:.1f} MiB" if rss is not None else "-"
        successes = result["summary"]["successful_runs"]
        runs = result["summary"]["runs"]
        lines.append(
            f"{result['mode']:<10} {result['status']:<8} "
            f"{first:>8.2f}ms "
            f"{latency.get('median', 0):>10.2f}ms "
            f"{latency.get('p95', 0):>9.2f}ms "
            f"{rss_text:>11} {successes:>4}/{runs:<4}")
        if result["status"] in ("partial", "failed"):
            failures = result["summary"].get("failures") or []
            if failures:
                lines.append(
                    f"  last error: {failures[-1]['error'] or '(none)'}")
    lines.extend([
        "",
        "FIRST is the first observed launch; kernel and filesystem caches are",
        "not forcibly dropped. JSON output includes every raw sample.",
    ])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="oci2bin benchmark",
        usage="oci2bin benchmark [OPTIONS] BINARY [-- CMD...]",
        description="measure artifact startup latency, peak RSS, and "
                    "launch reliability",
        epilog="CMD runs inside the artifact and defaults to /bin/true.")
    parser.add_argument("binary", help="oci2bin executable to benchmark")
    parser.add_argument(
        "--modes", type=parse_modes, default=parse_modes("extract,lazy"),
        metavar="LIST",
        help="comma-separated extract,lazy,vm modes, or all "
             "(default: extract,lazy)")
    parser.add_argument("--runs", type=int, default=10,
                        help="measured launches per mode (default: 10)")
    parser.add_argument("--warmups", type=int, default=1,
                        help="unmeasured warmup launches per mode (default: 1)")
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="seconds allowed per launch (default: 30)")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    parser.add_argument("-o", "--output",
                        help="write the selected output format to FILE")
    raw_args = list(sys.argv[1:] if argv is None else argv)
    command = []
    if "--" in raw_args:
        separator = raw_args.index("--")
        command = raw_args[separator + 1:]
        raw_args = raw_args[:separator]
    args = parser.parse_args(raw_args)

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.warmups < 0:
        parser.error("--warmups cannot be negative")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")

    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        parser.error(f"artifact not found: {binary}")
    if not os.access(binary, os.X_OK):
        parser.error(f"artifact is not executable: {binary}")

    if not command:
        command = ["/bin/true"]

    meta = inspect_image.read_meta_block(binary) or {}
    report = {
        "schema_version": 1,
        "recorded_at": datetime.datetime.now(
            datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "host": host_metadata(),
        "artifact": {
            "path": binary,
            "size_bytes": os.path.getsize(binary),
            "image": meta.get("image", "unknown"),
            "rootfs_format": meta.get("rootfs_format", "tar"),
            "payload_encoding": meta.get("payload_encoding", "unknown"),
        },
        "settings": {
            "runs": args.runs,
            "warmups": args.warmups,
            "timeout_seconds": args.timeout,
            "command": command,
        },
        "results": [],
    }

    for mode in args.modes:
        reason = mode_preflight(mode, meta)
        if reason:
            report["results"].append({
                "mode": mode,
                "status": "skipped",
                "reason": reason,
            })
            continue
        report["results"].append(
            benchmark_mode(binary, mode, command, args.runs, args.warmups,
                           args.timeout))

    rendered = (json.dumps(report, indent=2, sort_keys=True)
                if args.json else render_human(report))
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    failed = any(result["status"] in ("partial", "failed")
                 for result in report["results"])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
