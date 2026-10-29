from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

from dnsassess.config import load_rate

ROOT = Path(__file__).resolve().parent
CAPTURE_LOG = "/tmp/dnsassess-tcpdump.log"
CAPTURE_PID = "/tmp/dnsassess-tcpdump.pid"
LAB_CLIENT_IP = "172.28.0.2"
DESTINATION_RE = re.compile(r">\s+((?:\d{1,3}\.){3}\d{1,3})\.53:")
DNS_QUESTION_RE = re.compile(r"\b\d+\+\s+(?:\[[^\]]+\]\s+)*(?:A|SOA)\?")


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result


def peak_rate(timestamps: list[float], window_seconds: float = 1.0) -> int:
    """Return the largest packet count in any sliding one-second window."""
    ordered = sorted(timestamps)
    left = peak = 0
    for right, timestamp in enumerate(ordered):
        while timestamp - ordered[left] >= window_seconds:
            left += 1
        peak = max(peak, right - left + 1)
    return peak


def parse_capture(output: str) -> dict[str, list[float]]:
    events: dict[str, list[float]] = defaultdict(list)
    for line in output.splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            continue
        try:
            timestamp = float(fields[0])
        except ValueError:
            continue
        match = DESTINATION_RE.search(fields[1])
        if match and DNS_QUESTION_RE.search(fields[1]):
            events[match.group(1)].append(timestamp)
    return dict(events)


def _start_capture(container: str) -> None:
    command = (
        f"rm -f {CAPTURE_LOG} {CAPTURE_PID}; "
        "tcpdump -l -nn -tt -i eth1 "
        f"'src host {LAB_CLIENT_IP} and dst net 172.28.0.0/24 and "
        "(udp dst port 53 or tcp dst port 53)' "
        f"> {CAPTURE_LOG} 2>&1 & echo $! > {CAPTURE_PID}"
    )
    docker("exec", container, "sh", "-c", command)
    for _ in range(50):
        result = docker(
            "exec",
            container,
            "sh",
            "-c",
            f"kill -0 \"$(cat {CAPTURE_PID})\" 2>/dev/null && "
            f"grep -q 'listening on' {CAPTURE_LOG}",
            check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.1)
    log = docker("exec", container, "cat", CAPTURE_LOG, check=False).stdout
    raise RuntimeError(f"tcpdump did not start in {container}: {log.strip()}")


def _stop_capture(container: str) -> str:
    docker(
        "exec",
        container,
        "sh",
        "-c",
        f"kill -INT \"$(cat {CAPTURE_PID})\" 2>/dev/null || true; sleep 1",
        check=False,
    )
    return docker("exec", container, "cat", CAPTURE_LOG, check=False).stdout


def verify_rate(container: str, seed: str) -> int:
    rate = load_rate(ROOT / "config" / "rate.yaml")
    output_dir = "/app/out/rate-verification"
    _start_capture(container)
    scan = docker(
        "exec",
        container,
        "python3",
        "-m",
        "dnsassess.cli",
        "scan",
        "--scope",
        "/app/config/scope.yaml",
        "--rate",
        "/app/config/rate.yaml",
        "--out",
        output_dir,
        "--seed",
        seed,
        "--auth-log",
        "/var/log/authzone/queries.jsonl",
        check=False,
    )
    capture = _stop_capture(container)
    if scan.stdout:
        print(scan.stdout, end="")
    if scan.returncode:
        print(scan.stderr, file=sys.stderr, end="")
        return scan.returncode

    events = parse_capture(capture)
    if not events:
        print("rate verification failed: tcpdump captured no DNS queries", file=sys.stderr)
        print(capture, file=sys.stderr)
        return 1

    global_peak = peak_rate(
        [timestamp for timestamps in events.values() for timestamp in timestamps]
    )
    target_peaks = {ip: peak_rate(timestamps) for ip, timestamps in events.items()}
    print(f"Observed peak global rate: {global_peak} qps (cap {rate.global_qps:g})")
    for ip in sorted(target_peaks):
        print(
            f"Observed peak for {ip}: {target_peaks[ip]} qps "
            f"(cap {rate.per_target_qps:g})"
        )

    violations = []
    if global_peak > rate.global_qps:
        violations.append(
            f"global peak {global_peak} exceeds {rate.global_qps:g} qps"
        )
    violations.extend(
        f"{ip} peak {peak} exceeds {rate.per_target_qps:g} qps"
        for ip, peak in target_peaks.items()
        if peak > rate.per_target_qps
    )
    violations.extend(
        f"{ip} total {len(timestamps)} exceeds "
        f"{rate.max_queries_per_target} queries"
        for ip, timestamps in events.items()
        if len(timestamps) > rate.max_queries_per_target
    )
    if violations:
        print("rate verification failed: " + "; ".join(violations), file=sys.stderr)
        return 1
    print(f"Rate verification passed: captured {sum(map(len, events.values()))} DNS queries.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture and verify lab DNS query rates.")
    parser.add_argument("--container", default="lab-client")
    parser.add_argument("--seed", default="phase4-rate-check")
    args = parser.parse_args()
    try:
        return verify_rate(args.container, args.seed)
    except (OSError, RuntimeError) as exc:
        print(f"rate verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
