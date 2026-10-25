"""Reproducible cipher benchmarks for the legal-aid vault (Task 6).

Run from the repo root:

    python benchmarks/benchmark.py [--sizes 1,10,50] [--reps 5] [--warmup 1] [--out results/]

Part A measures individual algorithms on in-memory bytes:
  aes-gcm      AES-256-GCM (fresh 12-byte nonce, 32-byte key tag-verified decrypt)
  des-cbc-hmac DES-CBC + PKCS#7 + HMAC-SHA-256 (encrypt-then-MAC, fresh 8-byte IV)
  rc4-hmac     RC4 + HMAC-SHA-256 (fresh 16-byte key, verify before decrypt)

Part B measures the full pipeline via ``app.crypto.encrypt_file`` /
``decrypt_file`` on the same plaintext (owner=1, file_id=f"bench-<size>", ...).

Honest-comparison disclosure (also printed): the constructions are NOT
identical. AES-GCM includes authenticated-encryption overhead (AAD + tag).
DES/RC4 timings include a separate HMAC authenticate/deny step (HMAC is
computed inside an encryption rep and verified before any decryption work).
The auth overhead is part of the comparison BY DESIGN.

Unit convention: MB/s means MiB/s throughout -- MB/s = size_bytes / (2**20) /
seconds. Throughput is plaintext bytes processed per second in BOTH
directions: for encryption the plaintext is the completed work; for
decryption the recovered plaintext is the output -- that is the honest,
symmetric view.

All runs are in ONE environment; metadata (python/platform/cpu/dependency
versions, timestamp UTC ISO) is recorded in the summary JSON. Numbers are
real measured output of the machine that ran the script (never fabricated).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import importlib.metadata
import json
import os
import platform
import statistics
import sys
import time
import warnings
from datetime import datetime, timezone
from pathlib import Path

warnings.filterwarnings("ignore")  # dev-config warnings from importing app are benchmark noise

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from Crypto.Cipher import AES, ARC4, DES  # noqa: E402
from Crypto.Util.Padding import pad, unpad  # noqa: E402
import Crypto  # noqa: E402

from app.crypto import decrypt_file, encrypt_file  # noqa: E402


# ---------------------------------------------------------------- synthetic input

def make_plaintext(size_bytes: int, seed: int = 0xBADA55) -> bytes:
    """Deterministic pseudo-random plaintext of exactly size_bytes (untimed)."""
    out = bytearray()
    while len(out) < size_bytes:
        chunk = hashlib.sha256(
            seed.to_bytes(8, "little") + len(out).to_bytes(8, "little")
        ).digest()
        out += chunk
    return bytes(out[:size_bytes])


# ---------------------------------------------------------------- harness helpers

def timed_ns(fn, *args):
    """Run fn(*args) once, return (elapsed_seconds, fn return value)."""
    t0 = time.perf_counter_ns()
    result = fn(*args)
    return (time.perf_counter_ns() - t0) / 1e9, result


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def run_reps(label: str, size_mib: int, reps: int, warmup: int,
             enc_fn, dec_fn, pt: bytes, assert_rt: bool = False):
    """Warm up, then time >=reps encrypt + decrypt reps. Returns row dicts.

    Adaptive budget (recorded caveat if triggered): if a single warm-up
    projection suggests one rep would exceed ~5 minutes, timed reps are
    reduced for that config only and the reduction is recorded.

    assert_rt: after every decrypt rep, assert SHA-256(pt) == SHA-256(rt)
    (outside the timed interval). Used for the pipeline config.
    """
    crypt = enc_fn(pt)
    for _ in range(warmup):
        enc_fn(pt)
        dec_fn(crypt)
    # Rep-budget guard: one untimed projection iteration to estimate the cost
    # of a single rep (kept out of stats).
    proj_s, _ = timed_ns(enc_fn, pt)
    reps_effective = reps
    caveats: list[str] = []
    if size_mib == 50 and proj_s > 300.0:  # 5 minutes for a single rep
        reps_effective = 3
        caveats.append("reps=3-size-50: single projected rep >300s, reduced to 3")

    enc_times, dec_times, ct_sizes = [], [], []
    for _ in range(reps_effective):
        t, ct = timed_ns(enc_fn, pt)
        enc_times.append(t)
        ct_sizes.append(len(ct))
    pt_sha = sha256(pt)
    for _ in range(reps_effective):
        t2, rt = timed_ns(dec_fn, crypt)
        dec_times.append(t2)
        if assert_rt:
            assert sha256(rt) == pt_sha, "SHA-256 round-trip mismatch"

    pt_bytes = len(pt)
    mib = pt_bytes / (1024 * 1024)
    rows = []
    for direction, times in (("enc", enc_times), ("dec", dec_times)):
        med = statistics.median(times)
        stdev = statistics.stdev(times) if len(times) > 1 else 0.0
        rows.append({
            "config": label,
            "size_mib": size_mib,
            "direction": direction,
            "reps": reps_effective,
            "median_s": round(med, 6),
            "stdev_s": round(stdev, 6),
            "throughput_mib_s": round(mib / med, 4),
            "min_s": round(min(times), 6),
            "max_s": round(max(times), 6),
            "ct_size_bytes": len(crypt) if direction == "enc" else "",
            "storage_overhead_bytes": (len(crypt) - pt_bytes) if direction == "enc" else "",
        })
    return rows, caveats, ct_sizes


# ---------------------------------------------------------------- part A constructors

def aes_gcm_runners():
    key = os.urandom(32)

    def enc(pt: bytes) -> bytes:
        nonce = os.urandom(12)  # fresh nonce on every rep
        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        body, tag = c.encrypt_and_digest(pt)
        return nonce + tag + body

    def dec(blob: bytes) -> bytes:
        nonce, tag, body = blob[:12], blob[12:28], blob[28:]
        c = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        return c.decrypt_and_verify(body, tag)  # tag verification inside timing

    return enc, dec


def des_cbc_hmac_runners():
    key = os.urandom(8)
    mac_key = os.urandom(32)

    def enc(pt: bytes) -> bytes:
        iv = os.urandom(8)
        ct = DES.new(key, DES.MODE_CBC, iv=iv).encrypt(pad(pt, 8))
        mac = hmac.new(mac_key, iv + ct, hashlib.sha256).digest()
        return iv + mac + ct  # HMAC inside encryption time (encrypt-then-MAC)

    def dec(blob: bytes) -> bytes:
        iv, mac, ct = blob[:8], blob[8:40], blob[40:]
        if not hmac.compare_digest(
            hmac.new(mac_key, iv + ct, hashlib.sha256).digest(), mac
        ):
            raise ValueError("hmac")
        return unpad(DES.new(key, DES.MODE_CBC, iv=iv).decrypt(ct), 8)

    return enc, dec


def rc4_hmac_runners():
    key = os.urandom(16)
    mac_key = os.urandom(32)

    def enc(pt: bytes) -> bytes:
        ct = ARC4.new(key).encrypt(pt)
        return hmac.new(mac_key, ct, hashlib.sha256).digest() + ct

    def dec(blob: bytes) -> bytes:
        mac, ct = blob[:32], blob[32:]
        if not hmac.compare_digest(hmac.new(mac_key, ct, hashlib.sha256).digest(), mac):
            raise ValueError("hmac")
        return ARC4.new(key).decrypt(ct)

    return enc, dec


def pipeline_runners(master: bytes, size_mib: int):
    kwargs = {
        "master": master,
        "owner_id": 1,
        "file_id": f"bench-{size_mib}",
        "filename": "bench.bin",
        "mime": "application/octet-stream",
    }

    def enc(pt: bytes) -> bytes:
        return encrypt_file(pt, **kwargs)

    def dec(blob: bytes) -> bytes:
        return decrypt_file(blob, master=master, expect_owner=1,
                            expect_file_id=f"bench-{size_mib}")[0]

    return enc, dec


# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--sizes", default="1,10,50",
                    help="comma-separated sizes in MiB (ints)")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--out", default="results/")
    args = ap.parse_args()

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]

    out_dir = _REPO_ROOT / args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    cpu_model = "unmeasured"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass

    env_meta = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "cpu_model": cpu_model,
        "pycryptodome_version": Crypto.__version__,
        "flask_version": importlib.metadata.version("flask"),
    }

    all_rows: list[dict] = []
    all_caveats: list[str] = []
    throughput_by_size: dict[int, dict[str, float]] = {}
    ct_size_log: dict[str, list[int]] = {}
    mib = (1024 * 1024)
    master = bytes(range(32))

    print(f"Env: py={env_meta['python_version']} "
          f"pycryptodome={env_meta['pycryptodome_version']} "
          f"flask={env_meta['flask_version']} cpus={env_meta['cpu_count']}")
    print("DISCLOSURE: constructions differ by design. AES-GCM = authenticated "
          "encryption (AAD + 16B tag). DES-CBC/RC4 include a separate HMAC-SHA-256 "
          "authenticate step inside enc and a constant-time verify-before-decrypt "
          "inside dec. Comparison includes auth overhead on purpose.")
    print("Unit: MB/s == MiB/s = bytes/(2^20)/s; throughput is plaintext bytes "
          "per second in BOTH directions.")

    for size_mib in sizes:
        pt = make_plaintext(size_mib * mib)
        assert len(pt) == size_mib * mib
        configs = [
            ("aes-gcm", *aes_gcm_runners()),
            ("des-cbc-hmac", *des_cbc_hmac_runners()),
            ("rc4-hmac", *rc4_hmac_runners()),
            ("pipeline", *pipeline_runners(master, size_mib)),
        ]
        t_size = {}
        for label, enc_fn, dec_fn in configs:
            rows, caveats, ct_sizes = run_reps(
                label, size_mib, args.reps, args.warmup, enc_fn, dec_fn, pt,
                assert_rt=(label == "pipeline"))
            all_rows.extend(rows)
            all_caveats.extend(caveats)
            ct_size_log[f"{label}/{size_mib}MiB"] = ct_sizes
            for r in rows:
                t_size[f"{r['config']}-{r['direction']}"] = r["median_s"]
                print(f"{label:>12} {size_mib:>4} MiB {r['direction']}: "
                      f"median {r['median_s']:.3f}s stdev {r['stdev_s']:.3f}s "
                      f"throughput {r['throughput_mib_s']:.1f} MiB/s"
                      + (f" ct={r['ct_size_bytes']}B(+{r['storage_overhead_bytes']})"
                         if r['direction'] == 'enc' else ""))

        throughput_by_size[size_mib] = t_size

    summary = {
        "env": env_meta,
        "disclosure": (
            "Constructions are NOT identical: AES-GCM is authenticated encryption "
            "(AAD+tag inside enc, tag verify inside dec). DES-CBC and RC4 use a "
            "separate HMAC-SHA-256 authenticate/deny construct (MAC computed within "
            "enc; constant-time verify before any dec work). Comparison includes "
            "authentication overhead BY DESIGN per assignment."
        ),
        "unit_convention": "MB/s = MiB/s = size_bytes / (1024*1024) / seconds; "
                           "throughput = plaintext bytes processed per second in both directions.",
        "caveats": sorted(set(all_caveats)),
        "rows": all_rows,
        "ct_sizes_per_rep": ct_size_log,
        "sanity": {
            str(sz): t for sz, t in throughput_by_size.items()
        },
    }

    csv_path = out_dir / "benchmark_results.csv"
    json_path = out_dir / "benchmark_summary.json"
    fieldnames = ["config", "size_mib", "direction", "reps", "median_s", "stdev_s",
                  "throughput_mib_s", "min_s", "max_s", "ct_size_bytes",
                  "storage_overhead_bytes"]
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(all_rows)
    json_path.write_text(json.dumps(summary, indent=2) + "\n")

    # self-check: reopen both files and verify row counts
    with csv_path.open(newline="") as f:
        csv_rows = list(csv.DictReader(f))
    j = json.loads(json_path.read_text())
    expected = len(sizes) * 4 * 2
    assert len(csv_rows) == expected == len(j["rows"]), (
        f"row-count mismatch: csv={len(csv_rows)} json={len(j['rows'])} expected={expected}")

    largest = sizes[-1]
    srow = summary["sanity"][str(largest)]
    aes = srow.get("aes-gcm-enc", 0)
    des = srow.get("des-cbc-hmac-enc", 0)
    rc4 = srow.get("rc4-hmac-enc", 0)
    pipe = srow.get("pipeline-enc", 0)
    order = ", ".join(
        f"{name}" for name, v in sorted(
            [("AES", aes), ("DES", des), ("RC4", rc4)], key=lambda kv: kv[1]))
    print(f"SANITY: {largest} MiB enc throughput ordering (fastest first): {order}; "
          f"pipeline/AES overhead factor: {pipe / aes:.2f}x")

    print(f"OK rows={len(csv_rows)} -> {csv_path} ; {json_path}"
          + (f" ; caveats={'; '.join(summary['caveats'])}" if summary["caveats"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
