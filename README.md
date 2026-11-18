# CyberShield

![License: MIT](https://img.shields.io/badge/License-MIT-2fae8d) ![Node](https://img.shields.io/badge/Node-20%2B-339933) ![React](https://img.shields.io/badge/React-18-61dafb) ![AI agents](https://img.shields.io/badge/AI%20agents-6-7fb3f0)

Cybersecurity Incident Reporting & Tracking System. Incident intake, classification, assignment, and response tracking form the core product; six optional agent modules enrich that workflow.

## Run locally

1. Install Node.js 20+.
2. Run `npm install`.
3. Run `npm run dev` and open the Vite URL shown in the terminal. API listens on port 4000.

The checked-in-ignored local `.env` enables `DEMO_MODE=true`: the dashboard signs in to the API automatically and reads/writes demo incidents through authenticated REST routes. Demo data is held in API memory and resets when the API restarts. For MySQL persistence, install MySQL 8+, run `mysql -u root -p < database/schema.sql`, configure `.env` from `.env.example` with `DEMO_MODE=false`, a strong `JWT_SECRET`, and database credentials. The production login route uses bcryptjs password hashes; provision user accounts through a controlled admin workflow.

### Demo accounts (DEMO_MODE=true)

- `alex.admin@northstar.local` — Administrator
- `maya.analyst@northstar.local` — Security analyst
- `ethan.reporter@northstar.local` — Incident reporter
- `priya.viewer@northstar.local` — Read-only viewer

Password for every demo account: `demo1234`. The sign-in screen also offers one-click demo role buttons.

## Deploy to Render

The `render.yaml` blueprint builds the React frontend and serves it with the Express API as one web service. In Render, create a new Blueprint from this repository and deploy it with the generated `JWT_SECRET` and `DEMO_MODE=true` defaults. The free instance may sleep when idle, and demo incidents are in memory, so changes to demo data reset when the service restarts. AI agent features require setting `OPENAI_API_KEY` in the Render service environment.

## Full Stack-II mapping

- React dashboard and incident intake, with Redux Toolkit for UI state.
- Express REST API, validation, JWT authentication, and role-based assignment controls.
- MySQL relational schema with foreign keys, normalization, indexes, JSON audit metadata, and transactions around incident creation.
- Secure handling: parameterized SQL, bounded request size, content validation, least-privilege roles, and environment-based secrets.

## AI agent extensions

1. **OSINT collection** — enrich an incident's asset/domain context using approved sources.
2. **Vulnerability assessment** — map findings to CVEs and CVSS severity.
3. **Threat intelligence** — correlate historical attacks and MITRE ATT&CK techniques.
4. **Risk analysis & reporting** — prioritize exposure and produce incident PDF briefings.
5. **Target reconnaissance** — classify the entered target (domain, public/private IP, internal host, URL) and map its passive attack surface: DNS, certificate transparency, known subdomains, and risky non-production hostnames. Adapts findings and risk scoring to the target type.
6. **Network & exposure review** — perimeter-focused checks for the target: public reachability assumptions, category-specific controls (SPF/DKIM/DMARC for email, storage policies for cloud, MFA/conditional access for identity), and edge hardening steps.

Each agent card sends the selected incident and target input to the OpenAI Responses API and returns structured findings in the UI. Set `OPENAI_API_KEY` in the ignored local `.env`; `OPENAI_MODEL` can select an available model (default `gpt-4o-mini`). The OSINT, vulnerability, and threat-intelligence agents use the Responses API web search tool for public research. Private/internal targets are excluded from web search. Risk reporting uses the model without web search.

When no `OPENAI_API_KEY` is configured, agent runs fall back to a local heuristic analysis built from the incident record only (clearly labeled in the result, no external lookups) so the workflow stays usable offline.

- **OSINT collection** researches the user-entered public domain/IP with passive public sources. It does not probe or scan the target.
- **Vulnerability assessment** researches supplied product/version details against public sources and reports CVE/CVSS findings with sources; missing evidence is called out.
- **Threat intelligence** researches historical context and suggests MITRE ATT&CK mappings with source links. Actor attribution requires direct evidence.
- **Risk & reporting** evaluates the incident, explains risk drivers, suggests next steps, and opens a print-ready report that can be saved as PDF.
- **Target reconnaissance** and **Network & exposure** are target-driven: they read the target input and classify it (domain, public IP, private/internal, URL), then tailor their findings and risk score to what was entered. If the target field is left empty they fall back to the incident's own asset, so every agent is runnable in demo mode. Without an API key they still classify the target and produce the passive-surface checklist locally.

Incident details and the entered target are sent to OpenAI when an agent runs. Public-source agents may also search public web sources. Do not enter credentials, secrets, or assets you are not authorized to assess. Keep analyst review in the loop.

## Database concepts

The schema separates organizations, users, incidents, audit events, and agent runs. Incident sequences use a composite key per organization and year; report queries can use the status/severity and assignee indexes. Creation writes the incident and audit event in one transaction. MongoDB can be added as an optional document store for provider response snapshots; MySQL remains the source of truth.

## Credits & acknowledgments

- **Project & code** — CyberShield by [Prensenia](https://github.com/Prensenia), based on the original [cybershield](https://github.com/mehakcyberpro-web/cybershield) project by mehakcyberpro-web.
- **Open-source libraries** — [React](https://react.dev), [Vite](https://vitejs.dev), [Redux Toolkit](https://redux-toolkit.js.org), [Express](https://expressjs.com), [mysql2](https://github.com/sidorares/node-mysql2), [bcryptjs](https://github.com/dcodeIO/bcrypt.js), [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken), and [lucide-react](https://lucide.dev) icons.
- **Typography** — [DM Sans](https://fonts.google.com/specimen/DM+Sans) and [Manrope](https://fonts.google.com/specimen/Manrope) via Google Fonts.
- **AI enrichment** — agent research uses the [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses) when an `OPENAI_API_KEY` is configured; without a key the agents run a clearly labeled local heuristic analysis.

## License

Released under the [MIT License](./LICENSE).
