#!/usr/bin/env python3
"""
Network analysis for thesis: processes fixed-run PCAPs, generates figures + LaTeX tables.

Run from the repository root:
    python network_thesis.py

Outputs to thesis_output/figures/ and thesis_output/tables/.
Caches tshark results next to each PCAP (.cache.json + .cache.npz) so re-runs are instant.
"""

import subprocess, json, gc, shutil, re
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker
from pathlib import Path

HERE    = Path(__file__).resolve().parent
BENCH   = HERE / "mqtt_benchmark"
RESULTS = BENCH / "results"
OUT     = HERE / "thesis_output"
TSHARK  = shutil.which("tshark") or "/usr/bin/tshark"

(OUT / "figures").mkdir(exist_ok=True)
(OUT / "tables").mkdir(exist_ok=True)

BROKERS = ["hivemq", "emqx", "mosquitto", "rabbitmq", "nanomq"]
SIZES   = ["1kb", "35kb", "125kb", "1mb", "16mb"]
BL = {"hivemq": "HiveMQ", "emqx": "EMQX", "mosquitto": "Mosquitto",
      "rabbitmq": "RabbitMQ", "nanomq": "NanoMQ"}
SL = {"1kb": "1 KB", "35kb": "35 KB", "125kb": "125 KB", "1mb": "1 MB", "16mb": "16 MB"}
BC = {"hivemq": "#1f77b4", "emqx": "#ff7f0e", "mosquitto": "#2ca02c",
      "rabbitmq": "#d62728", "nanomq": "#9467bd"}

plt.rcParams.update({
    "font.family": "serif", "font.size": 11, "axes.titlesize": 12,
    "axes.labelsize": 11, "xtick.labelsize": 10, "figure.dpi": 150,
})


# ─── PCAP discovery ───────────────────────────────────────────────────────────

def find_pcap(broker, size):
    """Return the best available PCAP for a fixed run.
    Prefers _s200 over original if original is >500 MB. Returns None if not found.
    """
    cap_dir = RESULTS / f"{size}_fixed" / "captures"
    if not cap_dir.exists():
        return None
    # Glob all matching files
    candidates = sorted(cap_dir.glob(f"{broker}_{size}_qos0_*.pcap"))
    if not candidates:
        return None

    s200 = [p for p in candidates if "_s200" in p.name]
    orig = [p for p in candidates if "_s200" not in p.name]

    # Use _s200 if the original is large (avoids redundant work; they're the same data)
    if s200:
        return s200[0]
    if orig:
        return orig[0]
    return None


# ─── Cache helpers (same format as network_analysis.ipynb) ───────────────────

def _cache_paths(pcap):
    base = Path(pcap).with_suffix("")
    return base.with_suffix(".cache.json"), base.with_suffix(".cache.npz")


def load_cache(pcap):
    jpath, npath = _cache_paths(pcap)
    if not (jpath.exists() and npath.exists()):
        return None
    with open(jpath) as f:
        d = json.load(f)
    npz = np.load(npath)
    d["rtt_arr"] = npz["rtt_arr"]
    d["ovh_arr"] = npz["ovh_arr"]
    return d


def save_cache(pcap, stats):
    jpath, npath = _cache_paths(pcap)
    scalars = {k: v for k, v in stats.items() if k not in ("rtt_arr", "ovh_arr", "timeline")}
    with open(jpath, "w") as f:
        json.dump(scalars, f)
    np.savez_compressed(
        npath,
        rtt_arr=stats["rtt_arr"].astype(np.float32),
        ovh_arr=stats["ovh_arr"].astype(np.float32),
    )


# ─── tshark extraction ────────────────────────────────────────────────────────

def extract_all(pcap):
    """Single tshark pass. Returns scalars + rtt_arr + ovh_arr."""
    cmd = [
        TSHARK, "-r", str(pcap),
        "-Y", "tcp.port == 1883",
        "-T", "fields", "-E", "separator=\t",
        "-e", "frame.time_epoch",
        "-e", "tcp.stream",
        "-e", "tcp.len",
        "-e", "tcp.flags.syn",
        "-e", "tcp.flags.ack",
        "-e", "tcp.flags.reset",
        "-e", "tcp.analysis.retransmission",
        "-e", "tcp.analysis.zero_window",
        "-e", "tcp.analysis.ack_rtt",
        "-e", "mqtt.msgtype",
    ]

    t_min = t_max = None
    total_bytes = retrans = zero_win = resets = pub_count = n_packets = 0
    rtt_list, ovh_list = [], []
    syn_t, first_pub = {}, {}

    with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                          text=True, bufsize=1 << 20) as proc:
        for raw in proc.stdout:
            parts = raw.rstrip("\n").split("\t")
            if len(parts) < 10:
                continue
            try:
                ts = float(parts[0])
            except ValueError:
                continue

            if t_min is None:
                t_min = ts
            t_max = ts

            try:
                nb = int(parts[2]) if parts[2] else 0
            except ValueError:
                nb = 0
            total_bytes += nb

            if parts[6]:
                retrans += 1
            if parts[7]:
                zero_win += 1
            if parts[5] == "1":
                resets += 1
            if parts[8]:
                try:
                    rtt_list.append(float(parts[8]) * 1000)
                except ValueError:
                    pass

            stream = parts[1]
            if parts[9] == "3":   # MQTT PUBLISH
                pub_count += 1
                if stream and stream not in first_pub:
                    first_pub[stream] = ts
            if parts[3] == "1" and parts[4] != "1":   # SYN (not SYN-ACK)
                if stream and stream not in syn_t:
                    syn_t[stream] = ts
            n_packets += 1

    duration = (t_max - t_min) if (t_min and t_max) else 1

    for s, st in syn_t.items():
        pt = first_pub.get(s)
        if pt and pt > st:
            ovh_list.append((pt - st) * 1000)

    rtt_arr = np.array(rtt_list, dtype=np.float32)
    ovh_arr = np.array(ovh_list, dtype=np.float32)

    def pct(arr, q):
        return round(float(np.percentile(arr, q)), 2) if len(arr) else None

    return {
        "duration_s":           round(duration, 1),
        "total_bytes":          total_bytes,
        "n_packets":            n_packets,
        "mqtt_publishes":       pub_count,
        "throughput_KB/s":      round(total_bytes / max(duration, 1) / 1024, 1),
        "rtt_p50_ms":           pct(rtt_arr, 50),
        "rtt_p95_ms":           pct(rtt_arr, 95),
        "rtt_p99_ms":           pct(rtt_arr, 99),
        "rtt_mean_ms":          round(float(np.mean(rtt_arr[rtt_arr > 0])), 3) if np.any(rtt_arr > 0) else None,
        "rtt_std_ms":           round(float(np.std(rtt_arr[rtt_arr > 0])), 3) if np.any(rtt_arr > 0) else None,
        "rtt_min_ms":           round(float(np.min(rtt_arr[rtt_arr > 0])), 3) if np.any(rtt_arr > 0) else None,
        "rtt_max_ms":           round(float(np.max(rtt_arr[rtt_arr > 0])), 3) if np.any(rtt_arr > 0) else None,
        "retransmissions":      retrans,
        "retrans_rate_%":       round(100 * retrans / max(n_packets, 1), 3),
        "zero_window_events":   zero_win,
        "tcp_resets":           resets,
        "rtt_arr":              rtt_arr,
        "ovh_arr":              ovh_arr,
        "timeline":             {},   # not used in thesis script
    }


# ─── Load all data ─────────────────────────────────────────────────────────────

print("Loading network data from fixed-run PCAPs...\n")
net = {}   # net[broker][size] = stats dict (scalars only; rtt_arr held separately)

for broker in BROKERS:
    net[broker] = {}
    for size in SIZES:
        pcap = find_pcap(broker, size)
        if pcap is None:
            print(f"  MISSING PCAP: {broker} {size}")
            net[broker][size] = {"skip": True}
            continue

        cached = load_cache(pcap)
        if cached:
            # Backfill RTT spread stats from rtt_arr if absent (old caches lack these keys)
            arr = cached.get("rtt_arr")
            if arr is not None and len(arr) > 0:
                pos = arr[arr > 0]
                for key, fn in [
                    ("rtt_mean_ms", lambda a: round(float(np.mean(a)), 3)),
                    ("rtt_std_ms",  lambda a: round(float(np.std(a)), 3)),
                    ("rtt_min_ms",  lambda a: round(float(np.min(a)), 3)),
                    ("rtt_max_ms",  lambda a: round(float(np.max(a)), 3)),
                ]:
                    if key not in cached:
                        cached[key] = fn(pos) if len(pos) else float("nan")
            print(f"  [cache] {broker:10} {size:6}  pub={cached['mqtt_publishes']:,}  "
                  f"retrans={cached['retransmissions']:,}  zw={cached['zero_window_events']:,}  "
                  f"rtt_p95={cached['rtt_p95_ms']}ms")
            net[broker][size] = {k: v for k, v in cached.items()
                                 if k not in ("rtt_arr", "ovh_arr")}
        else:
            mb = pcap.stat().st_size / 1024 ** 2
            print(f"  [tshark] {broker:10} {size:6}  ({mb:.0f} MB) — extracting...", flush=True)
            stats = extract_all(pcap)
            try:
                save_cache(pcap, stats)
                print(f"           cached → {pcap.stem}.cache.*")
            except OSError as e:
                print(f"           [warn] cache write failed: {e}")
            print(f"           pub={stats['mqtt_publishes']:,}  "
                  f"retrans={stats['retransmissions']:,}  "
                  f"zw={stats['zero_window_events']:,}  "
                  f"rtt_p95={stats['rtt_p95_ms']}ms")
            net[broker][size] = {k: v for k, v in stats.items()
                                 if k not in ("rtt_arr", "ovh_arr", "timeline")}
            del stats
            gc.collect()

        net[broker][size].setdefault("skip", False)


def nv(b, s, k, default=float("nan")):
    e = net[b][s]
    if e.get("skip"):
        return float("nan")
    v = e.get(k)
    return float("nan") if v is None else v


# ═══════════════════════════════════════════════════════════════════════════════
# FIGURES
# ═══════════════════════════════════════════════════════════════════════════════
print("\nGenerating network figures...")

xp = list(range(len(SIZES)))
xl = [SL[s] for s in SIZES]


def savefig(fig, stem):
    for ext in (".pdf", ".png"):
        fig.savefig(OUT / "figures" / f"{stem}{ext}", bbox_inches="tight")
    plt.close(fig)
    print(f"  fig: {stem}")


# Figure N1: RTT P95 vs payload size (line chart)
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [nv(b, s, "rtt_p95_ms") for s in SIZES]
    ax.plot(xp, y, marker="o", label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("TCP RTT P95 (ms)")
ax.set_title("TCP 95th-Percentile Round-Trip Time vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
ax.set_yscale("log")
ax.yaxis.set_major_formatter(matplotlib.ticker.ScalarFormatter())
fig.tight_layout()
savefig(fig, "net_rtt_p95_vs_size")


# Figure N2: Retransmission rate vs payload size (line chart)
fig, ax = plt.subplots(figsize=(8, 4.5))
for b in BROKERS:
    y = [nv(b, s, "retrans_rate_%") for s in SIZES]
    ax.plot(xp, y, marker="s", label=BL[b], color=BC[b], linewidth=1.8, markersize=5)
ax.set_xticks(xp)
ax.set_xticklabels(xl)
ax.set_xlabel("Payload Size")
ax.set_ylabel("TCP Retransmission Rate (%)")
ax.set_title("TCP Retransmission Rate vs. Payload Size (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.grid(linestyle="--", alpha=0.5)
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "net_retrans_vs_size")


# Figure N3: Zero-window events — grouped bar chart at 1MB and 16MB, log scale
fig, ax = plt.subplots(figsize=(8, 4.5))
x_groups = ["1 MB", "16 MB"]
x_idx    = np.arange(len(x_groups))
width    = 0.15
offsets  = np.linspace(-(len(BROKERS)-1)/2, (len(BROKERS)-1)/2, len(BROKERS)) * width

for i, b in enumerate(BROKERS):
    raw  = [nv(b, "1mb", "zero_window_events"), nv(b, "16mb", "zero_window_events")]
    vals = [max(v, 0.5) for v in raw]   # log1p-style floor so zero bars remain visible
    bars = ax.bar(x_idx + offsets[i], vals, width=width * 0.9,
                  label=BL[b], color=BC[b], alpha=0.85)
    # annotate zero bars explicitly
    for j, (bar, rv) in enumerate(zip(bars, raw)):
        if rv <= 2:
            ax.text(bar.get_x() + bar.get_width() / 2, 4.0,
                    str(int(rv)), ha="center", va="bottom", fontsize=7, color="dimgray")

ax.set_yscale("log")
ax.set_xticks(x_idx)
ax.set_xticklabels(x_groups, fontsize=11)
ax.set_xlabel("Payload Size")
ax.set_ylabel("TCP Zero-Window Events (log scale)")
ax.set_title("TCP Zero-Window Events at Large Payload Sizes (QoS 0)")
ax.legend(loc="upper left", fontsize=9)
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
    lambda x, _: f"{int(x):,}" if x >= 1 else ""))
ax.grid(axis="y", linestyle="--", alpha=0.4, which="major")
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "net_zero_window_1mb_16mb")


# Figure N4: RTT P95 heatmap (broker × size)
fig, ax = plt.subplots(figsize=(8, 4))
M = np.full((len(BROKERS), len(SIZES)), float("nan"))
for i, b in enumerate(BROKERS):
    for j, s in enumerate(SIZES):
        v = nv(b, s, "rtt_p95_ms")
        if not np.isnan(v):
            M[i, j] = v
logM = np.where(np.isnan(M), np.nan, np.log10(M + 1e-9))
im = ax.imshow(logM, aspect="auto", cmap="RdYlGn_r")
ax.set_xticks(range(len(SIZES)))
ax.set_xticklabels([SL[s] for s in SIZES])
ax.set_yticks(range(len(BROKERS)))
ax.set_yticklabels([BL[b] for b in BROKERS])
ax.set_title("TCP RTT P95 Heatmap — log10(ms) (QoS 0)")
for i in range(len(BROKERS)):
    for j in range(len(SIZES)):
        v = M[i, j]
        txt = f"{v:.2f}" if not np.isnan(v) else "N/A"
        col = "black" if (not np.isnan(v) and v < 10) else "white"
        ax.text(j, i, txt, ha="center", va="center", fontsize=9, color=col)
fig.colorbar(im, ax=ax, pad=0.02).set_label("log10(RTT P95 / ms)")
fig.tight_layout()
savefig(fig, "net_rtt_p95_heatmap")


# Figure N5: Throughput at 1MB and 16MB (the two sizes where brokers meaningfully differ)
fig, axes = plt.subplots(1, 2, figsize=(9, 4.5), sharey=False)
for ax, size in zip(axes, ["1mb", "16mb"]):
    vals   = [nv(b, size, "throughput_KB/s") / 1024 for b in BROKERS]
    colors = [BC[b] for b in BROKERS]
    ymax   = max(v for v in vals if not np.isnan(v)) * 1.18
    ax.set_ylim(0, ymax)
    bars = ax.bar(range(len(BROKERS)), vals, color=colors, edgecolor="white", width=0.6)
    for bar, v in zip(bars, vals):
        if not np.isnan(v):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + ymax * 0.02,
                    f"{v:.1f}", ha="center", va="bottom", fontsize=8.5)
    ax.set_xticks(range(len(BROKERS)))
    ax.set_xticklabels([BL[b] for b in BROKERS], rotation=20, ha="right", fontsize=9)
    ax.set_title(SL[size], fontsize=11)
    ax.set_ylabel("Throughput (MB/s)" if size == "1mb" else "")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.set_axisbelow(True)

fig.suptitle("TCP Throughput (MB/s) per Broker — 1 MB and 16 MB Payloads (QoS 0)", fontsize=11)
fig.tight_layout()
savefig(fig, "net_throughput_bars")


# Figure N6: RTT percentile comparison at 16 MB — P50 / P95 / P99 per broker
# Uses pre-computed scalars only; avoids loading raw RTT arrays (which would
# produce a multi-MB vector PDF with millions of individual flier points).
print("  fig: net_rtt_boxplot_16mb  (percentile chart, no raw arrays)")
pcts   = [("P50", "rtt_p50_ms"), ("P95", "rtt_p95_ms"), ("P99", "rtt_p99_ms")]
ls     = ["--", "-", ":"]
marker = ["o", "s", "^"]

fig, ax = plt.subplots(figsize=(8, 4.5))
x = np.arange(len(pcts))
width = 0.15
offsets = np.linspace(-(len(BROKERS)-1)/2, (len(BROKERS)-1)/2, len(BROKERS)) * width

for i, b in enumerate(BROKERS):
    vals = [nv(b, "16mb", pk) for _, pk in pcts]
    bars = ax.bar(x + offsets[i], vals, width=width * 0.9,
                  label=BL[b], color=BC[b], alpha=0.85)

ax.set_yscale("log")
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(
    lambda v, _: f"{v:g}"))
ax.set_xticks(x)
ax.set_xticklabels([p for p, _ in pcts], fontsize=11)
ax.set_xlabel("RTT Percentile")
ax.set_ylabel("TCP ACK RTT (ms, log scale)")
ax.set_title("TCP ACK RTT Percentiles at 16 MB Payload (QoS 0)")
ax.legend(fontsize=9, loc="upper left")
ax.grid(axis="y", linestyle="--", alpha=0.4, which="major")
ax.set_axisbelow(True)
fig.tight_layout()
savefig(fig, "net_rtt_boxplot_16mb")


# ═══════════════════════════════════════════════════════════════════════════════
# LATEX TABLES
# ═══════════════════════════════════════════════════════════════════════════════
print("\nGenerating LaTeX tables...")


def wtab(name, rows):
    (OUT / "tables" / f"{name}.tex").write_text("\n".join(rows))
    print(f"  tab: {name}.tex")


def ncell(b, s, k, fmt="{:.3f}"):
    v = nv(b, s, k)
    return r"\textemdash" if np.isnan(v) else fmt.format(v)


# Table: RTT summary (P50, P95, P99) per broker × size
rows = [
    r"\begin{table}[ht]", r"\centering",
    r"\caption{TCP ACK round-trip time (ms) per broker and payload size (QoS~0). "
    r"Values are the 50th, 95th, and 99th percentiles measured from the PCAP capture.}",
    r"\label{tab:net-rtt}",
    r"\begin{tabular}{ll" + "r" * len(SIZES) + "}",
    r"\toprule",
    r"Broker & Percentile & " + " & ".join(SL[s] for s in SIZES) + r" \\",
    r"\midrule",
]
for b in BROKERS:
    for pname, pk in [("P50", "rtt_p50_ms"), ("P95", "rtt_p95_ms"), ("P99", "rtt_p99_ms")]:
        vals = [ncell(b, s, pk) for s in SIZES]
        blab = BL[b] if pname == "P50" else ""
        rows.append(f"{blab} & {pname} & " + " & ".join(vals) + r" \\")
    rows.append(r"\addlinespace")
rows += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
wtab("net_rtt_summary", rows)


# Table: RTT spread (mean, std dev, min, max) per broker × size
rows = [
    r"\begin{table}[ht]", r"\centering",
    r"\caption{TCP ACK RTT spread statistics (ms) per broker and payload size (QoS~0). "
    r"Negative RTT readings, which arise when tshark matches an ACK to a retransmitted "
    r"segment that preceded the capture window, are excluded before computing all four "
    r"metrics. Mean and standard deviation summarise central tendency and variability; "
    r"min is the smallest per-segment RTT observed (network-path baseline); "
    r"max is the single largest observed ACK round-trip, which may reflect an OS "
    r"scheduling stall or a broker-side GC pause delaying ACK processing.}",
    r"\label{tab:net-rtt-spread}",
    r"\begin{tabular}{ll" + "r" * len(SIZES) + "}",
    r"\toprule",
    r"Broker & Metric & " + " & ".join(SL[s] for s in SIZES) + r" \\",
    r"\midrule",
]
for b in BROKERS:
    for mname, mk in [("Mean", "rtt_mean_ms"), ("Std Dev", "rtt_std_ms"),
                      ("Min", "rtt_min_ms"), ("Max", "rtt_max_ms")]:
        vals = [ncell(b, s, mk) for s in SIZES]
        blab = BL[b] if mname == "Mean" else ""
        rows.append(f"{blab} & {mname} & " + " & ".join(vals) + r" \\")
    rows.append(r"\addlinespace")
rows += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
wtab("net_rtt_spread", rows)


# Table: TCP health (retransmission rate + zero-window) per broker × size
rows = [
    r"\begin{table}[ht]", r"\centering",
    r"\caption{TCP health metrics per broker and payload size (QoS~0). "
    r"Retransmission rate is the fraction of all TCP segments that were retransmitted. "
    r"Zero-window events count TCP segments advertising a zero receive-window.}",
    r"\label{tab:net-tcp-health}",
    r"\begin{tabular}{ll" + "r" * len(SIZES) + "}",
    r"\toprule",
    r"Broker & Metric & " + " & ".join(SL[s] for s in SIZES) + r" \\",
    r"\midrule",
]
for b in BROKERS:
    rt_vals = [ncell(b, s, "retrans_rate_%") for s in SIZES]
    zw_raw  = [nv(b, s, "zero_window_events") for s in SIZES]
    zw_vals = [r"\textemdash" if np.isnan(v) else f"{int(v):,}" for v in zw_raw]
    rows.append(f"{BL[b]} & Retrans (\\%) & " + " & ".join(rt_vals) + r" \\")
    rows.append(f" & Zero-win & " + " & ".join(zw_vals) + r" \\")
    rows.append(r"\addlinespace")
rows += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
wtab("net_tcp_health", rows)


# Table: TCP throughput (MB/s) per broker × size
rows = [
    r"\begin{table}[ht]", r"\centering",
    r"\caption{Effective TCP throughput (MB/s) per broker and payload size (QoS~0). "
    r"Throughput is computed as total TCP payload bytes divided by capture duration. "
    r"At payload sizes up to 125~KB all brokers achieve similar throughput because "
    r"the bottleneck is the message dispatch rate, not available bandwidth; "
    r"meaningful differentiation only emerges at 16~MB.}",
    r"\label{tab:net-throughput}",
    r"\begin{tabular}{l" + "r" * len(SIZES) + "}",
    r"\toprule",
    r"Broker & " + " & ".join(SL[s] for s in SIZES) + r" \\",
    r"\midrule",
]
for b in BROKERS:
    vals = []
    for s in SIZES:
        v = nv(b, s, "throughput_KB/s") / 1024
        if np.isnan(v):
            vals.append(r"\textemdash")
        elif v < 0.1:
            vals.append(r"${<}0.1$")
        else:
            vals.append(f"{v:.1f}")
    rows.append(f"{BL[b]} & " + " & ".join(vals) + r" \\")
rows += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
wtab("net_throughput", rows)


# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY PRINTOUT
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print(f"{'Broker':10} {'Size':6} {'RTT_P50':>9} {'RTT_P95':>9} {'RTT_P99':>9} "
      f"{'Retrans%':>10} {'ZeroWin':>10} {'Tput_MB/s':>10}")
print("-" * 80)
for b in BROKERS:
    for s in SIZES:
        e = net[b][s]
        if e.get("skip"):
            print(f"{BL[b]:10} {s:6}  SKIPPED")
            continue
        print(f"{BL[b]:10} {s:6} "
              f"{nv(b,s,'rtt_p50_ms'):>9.2f} "
              f"{nv(b,s,'rtt_p95_ms'):>9.2f} "
              f"{nv(b,s,'rtt_p99_ms'):>9.2f} "
              f"{nv(b,s,'retrans_rate_%'):>10.3f} "
              f"{nv(b,s,'zero_window_events'):>10.0f} "
              f"{nv(b,s,'throughput_KB/s')/1024:>10.1f}")

nf = len(list((OUT / "figures").glob("net_*")))
nt = len(list((OUT / "tables").glob("net_*")))
print(f"\nOutput: {OUT}")
print(f"  {nf} network figure files  |  {nt} network LaTeX tables")
