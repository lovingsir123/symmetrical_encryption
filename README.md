# Legal-Aid Vault

Course-assignment Flask app: per-user file storage sealed with a layered
symmetric pipeline (AES-256-GCM → DES-CBC → RC4). **DES and RC4 are obsolete;
the stack is assignment only and must never hold real data** — see
`app/crypto.py` for the full security discussion.

## Scenario

A small legal-aid clinic needs a shared place for client files (contracts,
backups, media). The assignment: every uploaded file is encrypted on the
server *before* it hits the disk, each user sees only their own files, and the
key material is envelope-encrypted by a master key — so a stolen disk without
the master key gives the attacker ciphertext only.

## Architecture & data flow

Flask app (factory in `app/__init__.py`, routes in `app/routes.py`,
auth in `app/auth.py`, SQLite schema in `app/models.py`, storage/DB glue in
`db.py` + `app/storage.py`). On upload:

1. password login (Argon2 hashes in SQLite) + CSRF on every form;
2. extension + size validation (`ALLOWED_EXTENSIONS`, 64 MiB);
3. `app/crypto.py:encrypt_file` builds the envelope:
   AES-256-GCM encrypts both the plaintext and a JSON metadata block
   (filename, mime, size, owner, SHA-256) — 12 B nonces, tags included;
   the AES ciphertext is then additionally encrypted with DES-CBC
   (PKCS#7, 8-byte blocks, fresh IV) and then with RC4 — every layer key is
   an HKDF-SHA256 subkey derived from the master key plus a fresh per-file
   salt; DES and RC4 layers each carry a separate HMAC-SHA-256 over their
   ciphertext and are constant-time verified before any decrypt work on
   that layer;
4. the envelope blob lands as `instance/uploads/<blob>` and a metadata row
   (filename, owner, size, hash, blob id) lands in `instance/vault.db`;
   download reverses the chain: RC4 → DES → AES, layer tags verified, and
   the recovered SHA-256 must match the sealed value before the bytes are
   served.

## Setup

Requires Python 3.12 + pip dependencies (Flask, Flask-Login, Flask-WTF,
Argon2, PyCryptodome, python-dotenv, pytest).

Install a Miniforge environment (either way works):

```bash
mamba env create -f environment.yml
# or:
mamba create -n legalaid-vault python=3.12
conda activate legalaid-vault          # the editor shell needs it on PATH
python -m pip install -r requirements.txt
```

If `conda`/`mamba` are not on the default PATH, they live in the Miniforge
install directory (e.g. `~/miniforge3/bin`); activate it with
`source <path>/etc/profile.d/conda.sh`.

## Master key & configuration

Generate both secrets (32 bytes hex each):

```bash
python -c "import secrets; print(secrets.token_hex(32))"   # MASTER_KEY
python -c "import secrets; print(secrets.token_hex(32))"   # SECRET_KEY
```

Copy the example env file and fill it in — `.env` is git-ignored, never commit it:

```bash
cp .env.example .env
# SECRET_KEY=<session/CSRF secret hex>
# MASTER_KEY=<32-byte hex key>
```

Values stay in the environment: `app/config.py` reads `SECRET_KEY` and
`MASTER_KEY` via python-dotenv. `MASTER_KEY` must decode to exactly 32 bytes
or startup raises. Without them the app still boots with ephemeral dev
fall-backs (sessions and uploaded files do not survive a restart).

## Initialize the database

```bash
conda run -n legalaid-vault flask --app app init-db
```

Verified: prints `Database initialized.` (and is safe to re-run — the schema
uses `CREATE TABLE IF NOT EXISTS`). The command also creates `instance/` with
`vault.db` and `instance/uploads/`.

## Run locally

```bash
conda run -n legalaid-vault flask --app app run
```

Verified: `flask --app app run --port 5057` answered `/login` with HTTP 200.
The `app` package is discovered through its `create_app` factory; there is no
`python -m app` module entry point. Browse to `http://127.0.0.1:5000` and
register a user first — every file belongs to one account only.

## Tests

```bash
conda run -n legalaid-vault python -m pytest -q
```

Verified: 87 passed.

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

Verified probe (not written to `results/`):
`python benchmarks/benchmark.py --sizes 1 --reps 1 --warmup 0 --out /tmp/opencode/probe-res` →
`SANITY: 1 MiB enc throughput ordering (fastest first): AES, RC4, DES; pipeline/AES overhead factor: 43.31x; OK rows=8`.

Outputs land in `results/benchmark_results.csv` and
`results/benchmark_summary.json` (both include environment metadata so numbers
reproduce). See those files for the latest measured run of this machine.
Numbers are WSL2-specific (HP Omen, mixed thermal state) — treat them as
illustrations, not as cryptographic law.

## Supported file types & size limit

Exact `ALLOWED_EXTENSIONS` list (`app/config.py`; only the final filename
extension segment is validated):

```
pdf, doc, docx, xls, xlsx, ppt, pptx, txt, csv,
jpg, jpeg, png, mp4, mov, avi, mkv
```

`MAX_CONTENT_LENGTH = 64 * 1024 * 1024` (64 MiB) rejects bigger uploads with
an error page. To change it, edit that constant in `app/config.py` (or pass a
`config_overrides` dict to `create_app`) — but `encrypt_file` works on whole
in-memory plaintext, so respect RAM when raising.

## Limitations

- **DES-CBC** is 56-bit, broken by exhaustive search for decades. Its only
  role here is the assignment's mandated stack.
- **RC4** has well-known keystream biases; its WEP/SSL history is why it was
  prohibited in TLS. It is never the *only* integrity layer — the HMAC
  constructions wrap it — but RC4 itself authenticates nothing.
- **Stacking ≠ 3× security** — layered weak ciphers do not compose into strong
  security; the whole stack collapses to its weakest layer plus a shell of key
  envelopes. Also the pipeline offers far lower throughput than AES alone.
- **Temp-file cleanup** happens in the Flask lifecycle boundary of each
  request; a hard-kill of the server can leave orphaned temp artefacts (tests
  cover the normal path, not SIGHUP mid-request).
- **Benchmark numbers are WSL2 machine-specific.**
- **Prototype only.** Do NOT store real client data with this code.

## Production warning

This code is a course assignment, not a secure storage system. The mandated
DES+RC4 layers are individually obsolete and the stack's claimed "defense in
depth" is not a real guarantee. Before any real deployment, the correct move
is to replace the entire stack with one strong primitive (e.g.
libsodium sealed boxes / AWS-KMS data keys / Fernet with rotating keys) plus
proper key management — not to shore up the legacy layers.

## Repository layout

```
app/            application factory, routes, auth, crypto, storage, models, config
benchmarks/     benchmark.py (CLI: --sizes/--reps/--warmup/--out)
db.py           SQLite glue (per-request conn, teardown, init-db CLI)
docs/           implementation plan
results/        measured benchmark CSV + JSON summary (deliverables — tracked)
static/         style.css
templates/      Jinja2 pages (login/register/dashboard/error/base)
tests/          pytest suite (87 tests)
.env.example    placeholder env file (real .env is git-ignored)
AI_USAGE_TEMPLATE.md   AI usage disclosure template
environment.yml / requirements.txt  environment definitions
```
