## How AI tools were used (description)

I used an AI coding assistant (OpenCode with a GLM model) throughout the
project, in two clearly divided areas.

**Web pages and views — AI drafted, polished by me.** The layout and view
decisions were mine: the centered login and register cards, the dashboard
file table and its columns (including the SHA-256 column), the wide-table
layout, and the responsive ≤600px scroll rule. The AI drafted the
corresponding edits to the Jinja2 templates and `static/css/style.css` under
my direction; I reviewed each change in the running browser, adjusted or
rejected what did not match the look I wanted, and accepted the final result.

**Python backend — AI-assisted.** The AI implemented and iterated on the Python
side under my direction: the application factory, routes, auth/lockout logic,
SQLite models and glue, the layered AES→DES→RC4 encryption core
(`app/crypto.py`), the storage layer, the benchmark harness, and the pytest
suite. I reviewed, ran (`flask --app app run`, `pytest`), and decided what was
kept or changed — for example I chose the exact dashboard columns and the CSS
changes, and I verified every AI-written behavior against the running app
before accepting it (90 tests passing).

**Documentation — AI-drafted, polished by me.** `README.md` sections
(scenario, UU PDP/GDPR data classification, benchmark interpretation) and the
benchmark methodology text were drafted by the AI from the measured results and
edited by me before I accepted them. All benchmark numbers come from runs of
`benchmarks/benchmark.py` on my machine; no figure was invented.

## Shared conversation evidence

- **Share URL:** `ai-usage/session-chat.md`

## Screenshot evidence

- **Screenshot 1:** `ai-usage/screenshot-1.png`
- **Screenshot 2:** `ai-usage/screenshot-2.png`