# CyberGuard — Backend (Sprint 1 scope)

CS-301 L Full Stack Web Development Lab, Air University Islamabad, Fall 2026.

This is the Clean Architecture backend solution for CyberGuard, scoped to what the
design doc schedules for **Sprint 1**: the project skeleton, the full database schema
(migrations for all 7 modules), and the Users/Auth module working end-to-end (JWT
register/login/refresh/logout + profile CRUD). Basic working CRUD is also included for
the other six modules (password checks, URL scans, PII scans, saved reports, wordlist,
alerts/notifications, plus a unified history view and the hygiene-score dashboard) so
the API runs end-to-end — the heuristic/ML depth for each (Maha's phishing rules, Zoya's
ML pipeline, Erum's PII detectors) is deepened in the later sprints per the Jira board.

**Important — read this first:** this solution was written in a sandboxed environment
with no access to NuGet, so none of it has been compiled or run yet. You (or GitHub
Actions CI) will be the first to actually build it. Expect to fix a handful of small
compile errors on the first `dotnet build` — that's normal here, not a sign anything is
fundamentally wrong. Treat the first build as part of Sprint 1's work.

## Project layout

```
cyberguard/
  CyberGuard.sln
  src/
    CyberGuard.Domain/          Entities, enums, heuristic engines (UrlRiskEngine, PiiDetector)
    CyberGuard.Application/     DTOs + use-case services, IApplicationDbContext & other ports
    CyberGuard.Infrastructure/  EF Core (Npgsql), Identity, JWT, geolocation, DI wiring
    CyberGuard.Api/             Controllers, Program.cs, appsettings.json, Dockerfile
    CyberGuard.Shared/          PasswordAnalyzer (meant to run client-side later)
  tests/
    CyberGuard.UnitTests/       PasswordAnalyzer + UrlRiskEngine tests (a starting point)
  .github/workflows/ci.yml      Build + test, then apply migrations to Supabase on main
  docker-compose.yml            API + local Postgres for development without touching prod
```

## 1. First-time setup

```bash
git clone https://github.com/EemanQAA/cyberguard.git
cd cyberguard
dotnet restore
```

Copy the example local settings file and fill in your own values (this file is
git-ignored — never commit real secrets):

```bash
cp src/CyberGuard.Api/appsettings.Development.json.example src/CyberGuard.Api/appsettings.Development.json
```

Edit it with:
- `ConnectionStrings:Default` — your Supabase **direct connection** string (Project
  Settings → Database → Connect → Direct connection → URI), password filled in.
- `Jwt:SigningKey` — any random string, 32+ characters (e.g. generate one with
  `openssl rand -base64 32`).

## 2. Create the database schema

The migration itself hasn't been generated yet (that needs the `dotnet-ef` tool, which
also needs internet access this sandbox didn't have). Do this once, from your own
machine:

```bash
dotnet tool install --global dotnet-ef
dotnet ef migrations add InitialCreate --project src/CyberGuard.Infrastructure --startup-project src/CyberGuard.Api
dotnet ef database update --project src/CyberGuard.Infrastructure --startup-project src/CyberGuard.Api
```

This creates the `Migrations/` folder and applies the schema (all 7 modules' tables,
plus Identity's tables) to your Supabase database. Commit the generated
`Migrations/` folder — migrations are code, not a local artifact.

## 3. Run it locally

```bash
dotnet run --project src/CyberGuard.Api
```

Swagger UI opens at `https://localhost:<port>/swagger` in Development. Try
`POST /api/v1/auth/register`, then `POST /api/v1/auth/login`, then use the returned
access token (Swagger's "Authorize" button) to call the other endpoints.

Or, to run API + a local Postgres together without touching Supabase at all:

```bash
docker compose up --build
```

## 4. Push your own work

Each member works on their own module branch and pushes daily, per the lab's
requirement:

```bash
git checkout -b feature/<your-name>-<module>
# ... make your changes ...
git add .
git commit -m "Describe what you did"
git push -u origin feature/<your-name>-<module>
```

Open a pull request into `main` — CI (`.github/workflows/ci.yml`) builds and tests it
automatically. Merging into `main` also runs the migration job against the live
Supabase database, using two GitHub Actions secrets you need to add once under
**Settings → Secrets and variables → Actions**:

| Secret name | Value |
|---|---|
| `SUPABASE_DB_CONNECTION` | The same direct connection string as above |
| `JWT_SIGNING_KEY` | The same signing key as above |

## 5. Where each person's work goes (matches the Jira board)

| Module | Owner | Jira epic |
|---|---|---|
| Users, Auth, app shell | Eeman | SCRUM-5 |
| Password checker, wordlist, history | Zoya | SCRUM-6 |
| URL scanner, ML integration, geolocation | Maha | SCRUM-7 |
| PII scanner, reports, dashboard | Erum | SCRUM-8 |
| Alerts & notifications | Eeman | SCRUM-9 |
| ML training pipeline | Zoya | SCRUM-10 |
| DevOps (Docker/CI) | Eeman (shared) | SCRUM-11 |
| Testing/docs/QA | Erum (shared) | SCRUM-12 |

Jira board: https://eemanqamar13.atlassian.net/jira/software/projects/SCRUM/boards

## 6. What's deliberately NOT in this Sprint-1 scaffold

- The ONNX phishing model and the ML training pipeline (`ml/`) — Sprint 3.
- ES256 asymmetric JWT keys with rotation — the design doc's target; this scaffold uses
  a simpler symmetric (HS256) key so Sprint 1 ships something that works. Swapping it in
  later only touches `JwtTokenService`.
- The Blazor Web App client — this is the API only.
