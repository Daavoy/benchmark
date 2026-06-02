#!/usr/bin/env python3
"""
Local HiveMQ 16 MB sensitivity check — fully Docker-free.

Runs HiveMQ CE, the publisher (main.py), and the subscriber (subscriber.py)
all as native host processes with no Docker and no resource limits.

Purpose: verify whether HiveMQ's 4.05 % message loss and elevated latency at
16 MB are a broker-inherent behaviour or an artefact of Docker container
overhead / resource limits.

Prerequisites:
  - Java 17+   : java -version          (already confirmed present)
  - tshark     : tshark --version        (for PCAP capture on loopback)
  - Python 3.x : python3 --version

All Python dependencies are installed automatically into a local venv on the
first run.

Usage (from this directory):
    python run_local_hivemq.py                   # 10 executions (default)
    python run_local_hivemq.py --numexecs 3      # quick smoke test
    python run_local_hivemq.py --no-capture      # skip PCAP (faster)
"""

import argparse
import csv
import os
import signal
import socket
import subprocess
import sys
import time
import urllib.request
import venv
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE          = Path(__file__).parent.resolve()
VUWSN_DIR     = HERE.parent / "virtualuwsn"          # subscriber.py, main.py live here
BENCHMARK_DIR = HERE.parent / "mqtt_benchmark"
PAYLOAD_DIR   = BENCHMARK_DIR / "publisher" / "data" / "synthetic" / "16mb"
RESULTS_DIR   = HERE / "results"
CAPTURES_DIR  = RESULTS_DIR / "captures"
LOG_BASE      = HERE / "logs"
VENV_DIR      = HERE / "venv"
HIVEMQ_DIR    = HERE / "hivemq-ce"
CONFIG_XML    = HERE / "hive-config.xml"

HIVEMQ_VERSION = "2024.5"
HIVEMQ_ZIP_URL = (
    f"https://github.com/hivemq/hivemq-community-edition/releases/download/"
    f"{HIVEMQ_VERSION}/hivemq-ce-{HIVEMQ_VERSION}.zip"
)
HIVEMQ_ZIP = HERE / f"hivemq-ce-{HIVEMQ_VERSION}.zip"
HIVEMQ_BIN = HIVEMQ_DIR / f"hivemq-ce-{HIVEMQ_VERSION}" / "bin" / "run.sh"

# .env from the main benchmark project (used to read passwords only).
ENV_FILE = BENCHMARK_DIR / ".env"

# Environment for native Python processes.
# VUWSN_DIR itself must be in PYTHONPATH so that `from gateway import Gateway`
# and `from vuwsn import *` resolve regardless of the working directory.
# mqtt_connector sub-package also needs to be on the path (mirrors the Dockerfile).
VUWSN_ENV = {
    **os.environ,
    "PYTHONPATH": os.pathsep.join([
        str(VUWSN_DIR),
        str(VUWSN_DIR / "mqtt_connector"),
        os.environ.get("PYTHONPATH", ""),
    ]),
    "PYTHONUNBUFFERED": "1",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_env(path: Path) -> dict:
    env = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        env[k.strip()] = v.strip()
    return env


def venv_python() -> Path:
    return VENV_DIR / "bin" / "python"


def setup_venv():
    """Create venv and install dependencies if not already done."""
    marker = VENV_DIR / ".deps_installed"
    if marker.exists():
        print(f"  venv already set up: {VENV_DIR}")
        return
    print(f"  Creating venv at {VENV_DIR} ...")
    venv.create(str(VENV_DIR), with_pip=True)
    req = VUWSN_DIR / "requirements.txt"
    print(f"  Installing dependencies from {req.name} ...")
    subprocess.run(
        [str(venv_python()), "-m", "pip", "install", "-r", str(req), "-q"],
        check=True,
    )
    marker.touch()
    print("  Dependencies installed.")


def wait_for_port(host: str, port: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(1)
    return False


def download_hivemq():
    if HIVEMQ_BIN.exists():
        print(f"  HiveMQ already present: {HIVEMQ_BIN.parent.parent.name}")
        return
    if not HIVEMQ_ZIP.exists():
        print(f"  Downloading HiveMQ CE {HIVEMQ_VERSION} ...")
        try:
            urllib.request.urlretrieve(HIVEMQ_ZIP_URL, HIVEMQ_ZIP)
        except Exception as e:
            print(f"\n[ERROR] Download failed: {e}")
            print(f"  Download manually from:\n    {HIVEMQ_ZIP_URL}")
            print(f"  and place the zip at:\n    {HIVEMQ_ZIP}")
            sys.exit(1)
    print(f"  Extracting {HIVEMQ_ZIP.name} ...")
    HIVEMQ_DIR.mkdir(exist_ok=True)
    with zipfile.ZipFile(HIVEMQ_ZIP) as zf:
        zf.extractall(HIVEMQ_DIR)
    HIVEMQ_BIN.chmod(0o755)
    print(f"  Extracted: {HIVEMQ_BIN.parent.parent.name}")


def start_hivemq() -> subprocess.Popen:
    import shutil
    conf_dir = HIVEMQ_BIN.parent.parent / "conf"
    conf_dir.mkdir(exist_ok=True)
    shutil.copy2(CONFIG_XML, conf_dir / "config.xml")
    log_file = RESULTS_DIR / "hivemq.log"
    print(f"  Starting HiveMQ CE  (log → {log_file.name})")
    return subprocess.Popen(
        [str(HIVEMQ_BIN)],
        cwd=str(HIVEMQ_BIN.parent.parent),
        stdout=open(log_file, "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )


def stop_hivemq(proc: subprocess.Popen):
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=15)
        print("  HiveMQ stopped.")
    except Exception as e:
        print(f"  [warn] HiveMQ stop: {e}")
        proc.kill()


def start_capture(pcap_path: Path) -> subprocess.Popen | None:
    tshark = subprocess.run(["which", "tshark"], capture_output=True, text=True).stdout.strip()
    if not tshark:
        print("  [warn] tshark not found — skipping PCAP capture.")
        return None
    pcap_path.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        [tshark, "-i", "lo", "-f", "tcp port 1883", "-s", "200",
         "-w", str(pcap_path), "-q"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    print(f"  tshark capturing on lo → {pcap_path.name}")
    return proc


def stop_capture(proc: subprocess.Popen | None):
    if proc is None:
        return
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    print("  Capture stopped.")


def start_subscriber(log_dir: Path, password: str) -> subprocess.Popen:
    log_dir.mkdir(parents=True, exist_ok=True)
    cfg = HERE / "configs" / "subscriber_local.yml"
    log_file = log_dir / "subscriber.log"
    env = {
        **VUWSN_ENV,
        "BROKER_PASSWORD": password,
        "BROKER_USERNAME": "subscriber1",
        "QOS": "0",
    }
    out_log = open(log_dir / "stdout.log", "w")
    return subprocess.Popen(
        [str(venv_python()), str(VUWSN_DIR / "subscriber.py"),
         "--configfile", str(cfg),
         "--logfile", str(log_file)],
        cwd=str(VUWSN_DIR),
        env=env,
        stdout=out_log,
        stderr=subprocess.STDOUT,
    )


def stop_subscriber(proc: subprocess.Popen):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_publisher(cfg_path: Path, log_dir: Path, password: str) -> subprocess.Popen:
    """Start a single publisher process and return immediately (non-blocking).

    cwd is set to log_dir so that gateway.py's relative log path
    ('logs/{gateway_name}.{ts}.log') resolves inside log_dir/logs/.
    stdout/stderr are captured to log_dir/stdout.log so startup errors
    (connection refused, import failure) are not silently discarded.
    """
    (log_dir / "logs").mkdir(parents=True, exist_ok=True)
    env = {
        **VUWSN_ENV,
        "BROKER_PASSWORD": password,
        "QOS": "0",
    }
    out_log = open(log_dir / "stdout.log", "w")
    return subprocess.Popen(
        [str(venv_python()), str(VUWSN_DIR / "main.py"), "--configfile", str(cfg_path)],
        cwd=str(log_dir),   # gateway writes logs/ relative to here
        env=env,
        stdout=out_log,
        stderr=subprocess.STDOUT,
    )


# ── Log parsing ────────────────────────────────────────────────────────────────

def _percentile(data: list, p: float) -> float:
    if not data:
        return float("nan")
    s = sorted(data)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (k - lo) * (s[hi] - s[lo])


def parse_subscriber_log_window(
    log_path: Path,
    t_start: float,
    t_end: float,
    n_expected: int = 2000,
) -> dict:
    """Parse subscriber log lines that fall within a time window.

    The subscriber logs one data line per received message with the format:
        {ts}[INFO],{sha256},{send_ms},{recv_ms},{topic},{bytes},{topic_len},{idx}

    t_start / t_end are Unix timestamps (time.time()). The window is
    [t_start - 5 s, t_end + 30 s] to tolerate clock drift and in-flight lag.
    Latencies are computed as recv_ms - send_ms; negative values are excluded
    (sub-millisecond clock jitter artefact).
    """
    import re
    blank = {"n_recv": "?", "mean_latency_ms": "?",
             "p95_latency_ms": "?", "loss_pct": "?"}
    if not log_path.exists():
        return blank

    # Data lines: timestamp[INFO],<64-hex-chars>,send_ms,recv_ms,...
    data_pat = re.compile(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{4})\[INFO\],"
        r"[0-9a-f]{64},"
        r"([\d.]+),([\d.]+),"
    )

    window_lo = t_start - 5.0
    window_hi = t_end + 30.0
    latencies = []

    for line in log_path.read_text(errors="replace").splitlines():
        m = data_pat.match(line)
        if not m:
            continue
        try:
            from datetime import datetime as _dt
            ts = _dt.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S%z").timestamp()
        except ValueError:
            continue
        if ts < window_lo or ts > window_hi:
            continue
        lat = float(m.group(3)) - float(m.group(2))   # recv_ms - send_ms
        if lat >= 0:
            latencies.append(lat)

    if not latencies:
        return blank

    n_recv = len(latencies)
    mean_ms = sum(latencies) / n_recv
    p95_ms  = _percentile(latencies, 95)
    loss    = max(0.0, (n_expected - n_recv) / n_expected * 100)
    return {
        "n_recv":           n_recv,
        "mean_latency_ms":  round(mean_ms, 2),
        "p95_latency_ms":   round(p95_ms, 2),
        "loss_pct":         round(loss, 4),
    }


# ── CSV fields ─────────────────────────────────────────────────────────────────

CSV_FIELDS = [
    "experiment_id", "broker", "payload_size", "qos", "execution",
    "timestamp", "elapsed_s", "pcap_file",
    "loss_pct", "n_recv", "mean_latency_ms", "p95_latency_ms", "notes",
]


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--numexecs",     type=int, default=10)
    parser.add_argument("--no-capture",   action="store_true")
    parser.add_argument("--sleep-between", type=int, default=60)
    args = parser.parse_args()

    print("=" * 60)
    print("  Local HiveMQ 16 MB sensitivity check (fully Docker-free)")
    print(f"  Executions    : {args.numexecs}")
    print(f"  Sleep between : {args.sleep_between}s")
    print(f"  PCAP capture  : {'disabled' if args.no_capture else 'loopback (lo)'}")
    print("=" * 60)

    if not PAYLOAD_DIR.exists() or not any(PAYLOAD_DIR.iterdir()):
        print(f"\n[ERROR] 16 MB payloads not found at {PAYLOAD_DIR}")
        sys.exit(1)

    dotenv    = load_env(ENV_FILE)
    password1 = dotenv.get("PASSWORD1", "")
    password2 = dotenv.get("PASSWORD2", "")

    RESULTS_DIR.mkdir(exist_ok=True)
    experiment_id = datetime.now(timezone.utc).strftime("local_hivemq_16mb_%Y%m%dT%H%M%S")
    pcap_path     = CAPTURES_DIR / f"{experiment_id}.pcap"
    csv_path      = RESULTS_DIR / f"{experiment_id}.csv"

    # ── 1. Python venv ────────────────────────────────────────────────────────
    print("\n[1/6] Setting up Python venv ...")
    setup_venv()

    # ── 2. HiveMQ CE ─────────────────────────────────────────────────────────
    print("\n[2/6] Preparing HiveMQ CE ...")
    download_hivemq()
    hivemq_proc = start_hivemq()
    print("  Waiting for port 1883 (up to 60 s) ...")
    if not wait_for_port("127.0.0.1", 1883, timeout=60):
        print("[ERROR] HiveMQ did not open port 1883 in 60 s. Check hivemq.log.")
        stop_hivemq(hivemq_proc)
        sys.exit(1)
    print("  HiveMQ ready.")
    time.sleep(5)

    # ── 3. PCAP capture ───────────────────────────────────────────────────────
    print("\n[3/6] Starting PCAP capture ...")
    capture_proc = None if args.no_capture else start_capture(pcap_path)

    # ── 4. Subscriber ─────────────────────────────────────────────────────────
    print("\n[4/6] Starting subscriber ...")
    sub_log_dir = LOG_BASE / "subscriber"
    subscriber_proc = start_subscriber(sub_log_dir, password2)
    time.sleep(5)
    print("  Subscriber started.")

    # ── 5. Execution loop ─────────────────────────────────────────────────────
    print(f"\n[5/6] Running {args.numexecs} executions ...")
    rows = []
    cfg1 = HERE / "configs" / "publisher1_local.yml"
    cfg2 = HERE / "configs" / "publisher2_local.yml"

    DRAIN_SECS = 15   # seconds to wait after publishers finish for in-flight msgs

    for i in range(args.numexecs):
        print(f"\n  [{i+1}/{args.numexecs}] Publishing ...")
        t_start = time.time()

        p1 = run_publisher(cfg1, LOG_BASE / "provider1", password1)
        p2 = run_publisher(cfg2, LOG_BASE / "provider2", password1)
        p1.wait()
        p2.wait()
        t_end = time.time()
        elapsed = round(t_end - t_start, 2)
        print(f"    done in {elapsed}s — draining {DRAIN_SECS}s for in-flight msgs ...")
        time.sleep(DRAIN_SECS)

        sub_log_file = sub_log_dir / "subscriber.log"
        metrics = parse_subscriber_log_window(sub_log_file, t_start, t_end, n_expected=4000)
        print(f"    loss={metrics['loss_pct']}%  "
              f"mean={metrics['mean_latency_ms']}ms  "
              f"p95={metrics['p95_latency_ms']}ms")

        rows.append({
            "experiment_id":   experiment_id,
            "broker":          "hivemq_local",
            "payload_size":    "16mb",
            "qos":             0,
            "execution":       i,
            "timestamp":       datetime.now(timezone.utc).isoformat(),
            "elapsed_s":       elapsed,
            "pcap_file":       str(pcap_path) if not args.no_capture else "",
            "loss_pct":        metrics["loss_pct"],
            "n_recv":          metrics["n_recv"],
            "mean_latency_ms": metrics["mean_latency_ms"],
            "p95_latency_ms":  metrics["p95_latency_ms"],
            "notes":           "no_docker_no_resource_limits",
        })

        if i < args.numexecs - 1:
            print(f"    sleeping {args.sleep_between}s ...")
            time.sleep(args.sleep_between)

    # ── 6. Teardown ───────────────────────────────────────────────────────────
    print("\n[6/6] Tearing down ...")
    stop_subscriber(subscriber_proc)
    stop_capture(capture_proc)
    stop_hivemq(hivemq_proc)

    # ── Results ───────────────────────────────────────────────────────────────
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    print("\n" + "=" * 60)
    print("  Summary")
    print("=" * 60)
    for r in rows:
        print(f"  exec {r['execution']:2d}  loss={r['loss_pct']}%  "
              f"mean={r['mean_latency_ms']}ms  p95={r['p95_latency_ms']}ms  "
              f"elapsed={r['elapsed_s']}s")
    print(f"\nCSV  → {csv_path}")
    if not args.no_capture and capture_proc is not None:
        print(f"PCAP → {pcap_path}")


if __name__ == "__main__":
    main()
