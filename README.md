# Legal-Aid Vault

Course-assignment Flask app: per-user file storage sealed with a layered
symmetric pipeline (AES-256-GCM → DES-CBC → RC4). **DES and RC4 are obsolete;
the stack is assignment only and must never hold real data** — see
`app/crypto.py` for the full security discussion.

## Setup

```bash
conda env create -f environment.yml   # or: pip install -r requirements.txt
cp .env.example .env                  # set MASTER_KEY + SECRET_KEY (32-byte hex master)
pytest
```

## Benchmarks

Part A measures individual algorithm constructions; part B measures the full
production pipeline (`app.crypto.encrypt_file`/`decrypt_file`):

| Config       | Construction (timed as-is) |
|--------------|----------------------------|
| `aes-gcm`    | AES-256-GCM, fresh 12 B nonce, tag verified inside decrypt — authenticated-encryption overhead included |
| `des-cbc-hmac` | DES-CBC + PKCS#7 + HMAC-SHA-256 encrypt-then-MAC — separate HMAC generated inside enc and **constant-time-verified before any decrypt work** |
| `rc4-hmac`   | RC4 + HMAC-SHA-256, same verify-before-decrypt construct |
| `pipeline`   | full envelope via `encrypt_file`/`decrypt_file` (fresh salt + nonces each rep) |

**Disclosure:** the constructions are NOT identical. AES includes
 authenticated-encryption overhead; DES/RC4 include a separate HMAC
 authenticate/deny step. The comparison includes authentication overhead BY
 DESIGN.

Honest unit convention: MB/s means **MiB/s**
(`bytes / (1024*1024) / seconds`), and throughput is *plaintext bytes
processed per second in BOTH directions* (input plaintext for enc, recovered
plaintext for dec). `perf_counter_ns`, ≥5 timed reps after 1 warm-up per
(config, size, direction); median + stdev; ciphertext size and storage
overhead recorded per enc row; pipeline SHA-256 round-trip equality asserted
every rep. If a single rep at 50 MiB would exceed ~5 minutes, reps drop to 3
for that config and the `reps=3-size-50` caveat is recorded in the summary.

Run:

```bash
conda run -n legalaid-vault python benchmarks/benchmark.py [--sizes 1,10,50] [--reps 5] [--warmup 1] [--out results/]
```

Outputs land in `results/benchmark_results.csv` and
`results/benchmark_summary.json` (both include environment metadata so numbers
reproduce). See those files for the latest measured run of this machine.
