# MQTT Broker Benchmark — Research Repository

This repository contains all analysis code and generated outputs for the Master's thesis
*"Reliability and Latency of MQTT Broker Implementations under QoS 0"*
(Jan-Petter Dåvøy, HVL, 2026).

The benchmark infrastructure and publisher/subscriber client live in two companion
repositories that must be cloned separately:

- **[Daavoy/mqtt_benchmark](https://github.com/Daavoy/mqtt_benchmark)** — benchmark
  orchestration, Docker Compose configs for all five brokers, and analysis notebooks.
  Forked from [kmolima/mqtt_benchmark](https://github.com/kmolima/mqtt_benchmark)
  (Lima et al., 2025) with extensions for the AUT0 single-broker topology, five broker
  overlays, synthetic payload generation, and TCP packet capture.
- **[Daavoy/virtualuwsn](https://github.com/Daavoy/virtualuwsn)** — the MQTT
  publisher and subscriber client used during the benchmark runs.

---

## 1. Prerequisites

- Docker and Docker Compose
- Python 3.9+ with `pip`
- `tshark` (part of Wireshark): `sudo apt install tshark`
- `editcap` (part of Wireshark, needed only for large PCAP pre-processing)

---

## 2. Set up the benchmark infrastructure

```bash
# Clone the benchmark orchestration repo
git clone https://github.com/Daavoy/mqtt_benchmark.git
cd mqtt_benchmark

# Clone the publisher/subscriber client alongside it
git clone https://github.com/Daavoy/virtualuwsn.git ../virtualuwsn
cd ../virtualuwsn
git submodule update --init --recursive
cd ../mqtt_benchmark

# Build the mqtt_client Docker image used by publishers and subscriber
docker build -t mqtt_client ../virtualuwsn

# Install Python dependencies for the orchestration scripts
pip install -r requirements.txt

# Create the required .env file from the example template
cp env.example .env
# Then edit .env and set your own PASSWORD1 / PASSWORD2 values
```

---

## 3. Run the benchmark

Synthetic payloads for all five sizes are already included in
`mqtt_benchmark/publisher/data/synthetic/`.

### Run all five brokers for a single payload size

```bash
cd mqtt_benchmark

# Run all brokers at 1 KB payload, 10 repetitions each
./run_broker_comparison.sh 1kb 10

# Run a specific broker only
BROKERS="emqx" ./run_broker_comparison.sh 16mb 10
```

Results (PCAP captures, subscriber logs, Prometheus CSVs) are written to
`mqtt_benchmark/results/<payload_size>_fixed/`.

### Run a single broker manually

```bash
python3 run_load_updated.py \
    --broker hivemq \
    --payload-size 1kb \
    --qos 0 \
    --numexecs 10 \
    --stats results/hivemq_1kb_qos0.csv
```

---

## 4. Reproduce thesis figures and tables

Once benchmark results are available in `mqtt_benchmark/results/`, run from this
repository's root:

```bash
bash reproduce_thesis.sh
```

This runs four scripts in sequence:

| Step | Script | Produces |
|------|--------|---------|
| 1 | `thesis_analysis.py` | Latency boxplots, heatmaps, loss/resource figures |
| 2 | `thesis_stats.py` | CDF figures, temporal stability plots, statistical test results |
| 3 | `network_thesis.py` | Second-run TCP RTT, zero-window, retransmission and throughput figures |
| 4 | `network_thesis_firstrun.py` | First-run vs. second-run TCP comparison figures |

The first run of steps 3 and 4 invokes `tshark` on each PCAP file (5–30 min per
16 MB capture). Results are cached as `.cache.json`/`.cache.npz` files next to the
PCAPs; subsequent runs complete in seconds.

Pre-generated figures are already included in `thesis_output/figures/`.

---

## 5. Large PCAP pre-processing (first run only)

For 16 MB captures, run these two helpers inside `mqtt_benchmark/` before step 3 above:

```bash
cd mqtt_benchmark

# Trim oversized PCAPs to 200-byte snaplen (keeps all headers, removes payload)
python3 strip_pcaps.py

# Pre-build tshark caches for 16 MB files outside the notebook kernel
python3 build_16mb_cache.py
```

---

## Repository layout

```
benchmark/
├── reproduce_thesis.sh          # entry point: runs all four scripts
├── thesis_analysis.py           # Step 1 — latency/reliability/resource analysis
├── thesis_stats.py              # Step 2 — statistical tests and CDFs
├── network_thesis.py            # Step 3 — second-run TCP/PCAP analysis
├── network_thesis_firstrun.py   # Step 4 — first-vs-second run TCP comparison
│
├── thesis_output/
│   └── figures/                 # all PDF and PNG figures (pre-generated)
│
└── local_hivemq_test/           # bare-metal HiveMQ sensitivity check (Section 6.3.1)
    ├── run_local_hivemq.py
    └── configs/
```

---

## Data availability

Raw PCAP captures and subscriber logs are stored in `mqtt_benchmark/results/`
(not tracked in git due to size). The `thesis_output/figures/` directory contains
the pre-generated figures produced from those captures.

---

## Citation

Lima, K., Oyetoyan, T.D., Heldal, R., Hasselbring, W. (2025).
*Evaluation of MQTT Bridge Architectures in a Cross-Organizational Context.*
