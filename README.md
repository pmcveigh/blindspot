# Infra Assessor 0.1.2

Infra Assessor is an Ubuntu-first, local application for **authorised pre-sales infrastructure assessments** by MSPs and telecoms providers. It safely discovers hosts and common TCP services, turns normalised observations into explainable review findings, and produces professional HTML/PDF reports. It is not a penetration-testing or vulnerability-exploitation tool. All results remain in local SQLite storage; the application has no cloud backend or telemetry.

## Ubuntu installation

Python 3.13 and [`uv`](https://docs.astral.sh/uv/) are required. On a supported Ubuntu host:

```bash
sudo apt update
sudo apt install nmap
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone <repository-url> && cd blindspot
uv sync
uv run playwright install chromium
uv run infra-assessor
```

Open <http://127.0.0.1:8462>. Application data and logs are stored predictably in `~/.local/share/infra-assessor/`.

Playwright may report missing Chromium system libraries; `uv run playwright install --with-deps chromium` installs them but uses `sudo` through Playwright's installer. The application itself never invokes `sudo`.

## Authorised workflow

Create an assessment, enter a customer and a canonical private IPv4 network (for example `192.168.1.0/24`), and explicitly confirm authorisation. A background task runs conservative Nmap discovery, stores normalised devices/services, applies YAML rules, and presents results. HTML reports open in the browser; PDF export uses local headless Chromium.

Only networks wholly contained by `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16` are accepted. Public, IPv6, host-bit-set, and arbitrary targets are rejected before Nmap starts.

## Safety profile and privileges

The sole Nmap invocation is isolated in `scanner/nmap.py`. It uses TCP connect discovery, timing template T3, the top 1,000 TCP ports, light service/version detection, and XML output. It does **not** use NSE scripts, exploits, credential attacks, brute force, denial-of-service probes, remediation, or persistence. Scan only networks for which you have explicit written authority.

When run without root privileges, scanning continues using unprivileged TCP connect behavior and the UI/report records that OS/raw-packet discovery was unavailable. Root adds conservative `-O --osscan-limit`. The application never elevates itself. Administrators may optionally grant raw-network capabilities to the resolved Nmap binary, after their own security review:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
getcap "$(command -v nmap)"
```

Capability behavior varies by Nmap packaging; running as a dedicated, controlled local account is recommended.

## Development

```bash
uv sync --dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy infra_assessor
uv run uvicorn infra_assessor.app.main:app --reload --host 127.0.0.1 --port 8462
```

Tests parse a fixture and never scan a network.

## Architecture

- `scanner/`: the `NetworkScanner` protocol, one Nmap subprocess boundary, XML parser, normalised Pydantic observations, and conservative classification.
- `intelligence/`: typed YAML rule loading and deterministic finding generation.
- `storage/`: SQLAlchemy 2.x models and repository-backed local SQLite persistence.
- `web/`: FastAPI routes, server-rendered Jinja pages, HTMX progress polling, and static styling.
- `reporting/`: standalone customer-facing HTML and Playwright PDF generation.
- `app/`: settings, database dependency, logging, startup, and CLI composition.

Findings deliberately separate observed evidence, potential consideration, and recommendation. Device classifications include confidence and should be verified by a person.

## v0.1.2 limitations

- Optimised for small authorised lab/business subnets; there is no scheduling, multi-user access, topology, continuous monitoring, cloud sync, or automated remediation.
- Progress is stage-based. Inventory is committed after Nmap completes rather than streamed live.
- Cancellation applies to tasks in the current application process. In-progress assessments are not resumed after a server restart.
- TLS certificate inspection is not implemented, so expiry rules are intentionally omitted rather than making unsupported claims.
- Service and OS identification depend on Nmap evidence, reachability, firewall policy, privileges, and the Nmap fingerprint database.
- PDF export requires the separately installed Playwright Chromium browser.
