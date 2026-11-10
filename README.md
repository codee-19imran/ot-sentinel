# OT-Sentinel

**Offline Incident Response & Log Forensics Dashboard** for OT/ICS environments.

When an OT device (PLC/RTU) is suspected to be compromised, engineers manually
collect log files from the plant floor. OT-Sentinel is an **air-gapped, local
web tool** that ingests those logs, parses them, runs rule-based anomaly
detection, visualises the results, and exports a PDF incident report — all
without any cloud connectivity.

## Why it exists

Most OT security tooling is commercial (Nozomi, Claroty) or focuses on network
scanning. Log forensics on air-gapped networks has no simple open-source
package — until now. OT-Sentinel gives you:

- Local authentication (JWT in an HttpOnly cookie, no cloud IdP)
- CSV/TXT log ingestion from PLC/RTU exports
- Rule-based detection engine (brute force, unusual commands, off-hours activity)
- Interactive forensic dashboard (Chart.js + threat map, all bundled locally)
- One-click PDF incident report via Apache PDFBox

## Tech stack

| Layer      | Technology                          |
|------------|-------------------------------------|
| Backend    | Spring Boot 3.5 (Java 21)           |
| Security   | Spring Security + jjwt (JWT cookie) |
| Database   | Embedded H2 (file-based)            |
| Frontend   | Thymeleaf, Bootstrap 5 (local)      |
| Charts     | Chart.js 4 (local)                  |
| Threat map | Leaflet 1.9 (local)                 |
| PDF export | Apache PDFBox 3                     |

## Project structure

```
com.ot.sentinel
├── config / security          # SecurityConfig, JwtAuthenticationFilter, JwtUtil
├── controller                 # AuthController, DashboardController, ReportController
├── service                    # LogParserService, RawLogNormalizerService, AnomalyDetectionService, ReportService
├── repository                 # LogEntryRepository, IncidentRepository, UserRepository
├── model                      # LogEntry, Incident, User
└── resources                  # templates, movable static assets, sample dataset
```

## Getting started

```bash
# build & run (Gradle wrapper included)
./gradlew bootJar
java -jar build/libs/ot-sentinel-0.0.1-SNAPSHOT.jar

# or run directly in development
./gradlew bootRun
```

Open **http://localhost:8081/login** and sign in:

| Username   | Password     | Role     |
|------------|--------------|----------|
| `admin`    | `admin123`   | ADMIN    |
| `engineer` | `engineer123`| ENGINEER |

Upload `src/main/resources/sample-data/plc_logs.csv` on the dashboard. The
sample contains a brute-force burst, STOP/DELETE manipulation, and off-hours
traffic so every rule fires in the demo.

## Log formats & data normalisation

Real PLCs rarely export clean CSV. OT-Sentinel therefore accepts **two**
ingestion paths, both funnelling into the same canonical schema
`timestamp,sourceIp,command,status,deviceId`:

**1. Standard CSV** — `POST /logs/upload`

**2. Proprietary PLC text** — `POST /logs/upload-raw`

```
[2026-11-10 08:05:02] WARN Device=HMI-CONTROL-03 Source=192.168.1.50 Action=LOGIN Result=FAIL
```

`RawLogNormalizerService` parses those lines with a regex, maps the vendor's
status vocabulary onto the canonical one (`OK`/`PASS`/`GRANTED` → `SUCCESS`,
`FAIL`/`DENIED`/`ERROR`/`TIMEOUT` → `FAILURE`), and hands the result to the
standard parser. Unrecognised lines are counted and skipped, never fatal.

| Raw token | Normalised status |
|-----------|-------------------|
| `OK`, `PASS`, `SUCCESS`, `GRANTED`, `ACCEPTED`, `COMPLETE` | `SUCCESS` |
| `FAIL`, `FAILURE`, `ERROR`, `DENIED`, `REJECTED`, `TIMEOUT`, `REFUSED` | `FAILURE` |

Sample file: `src/main/resources/sample-data/raw_plc_logs.txt`.

Regenerate both samples (with timestamps relative to *now*, so the planted
attack scenarios always sit inside the detection windows):

```bash
python3 scripts/generate_sample_logs.py
```

## Detection rules

| Rule                | Severity | Trigger                                            |
|---------------------|----------|----------------------------------------------------|
| `BRUTE_FORCE`       | HIGH     | >5 failed logins from one IP in 60 min             |
| `UNUSUAL_COMMAND`   | MEDIUM   | STOP / DELETE / RESET / SHUTDOWN commands          |
| `OFF_HOURS_ACTIVITY`| MEDIUM   | ≥3 commands per IP during 00:00–05:59              |

All thresholds are configurable in `application.properties`:

```properties
ot-sentinel.rules.brute-force-threshold=5
ot-sentinel.rules.brute-force-window-minutes=60
ot-sentinel.rules.off-hours=0-5
```

## Key endpoints

| Method | Path                          | Description                     |
|--------|-------------------------------|---------------------------------|
| GET    | `/login`                      | Login page                      |
| POST   | `/api/auth/login`             | Sign in (sets JWT cookie)       |
| POST   | `/api/auth/logout`            | Clear JWT cookie                |
| GET    | `/dashboard`                  | Forensic dashboard              |
| POST   | `/logs/upload`                | Ingest CSV log file             |
| POST   | `/logs/upload-raw`            | Ingest proprietary PLC text log (auto-normalised) |
| POST   | `/incidents/detect`           | Re-run detection rules          |
| GET    | `/api/charts/command-frequency` | JSON: commands vs counts      |
| GET    | `/api/charts/status-distribution`| JSON: SUCCESS vs FAILURE     |
| GET    | `/api/charts/timeline`        | JSON: events per hour (24h)     |
| GET    | `/api/charts/top-ips`         | JSON: top 10 source IPs         |
| GET    | `/api/charts/incident-severity` | JSON: incidents by severity   |
| GET    | `/api/report/pdf`             | Download the incident report    |

## Configuration

Production overrides happen through environment variables:

```bash
JWT_SECRET="a-long-random-32+-character-secret"
JWT_EXPIRATION="86400000"
```

The H2 database is stored in `./ot_sentinel_db.mv.db` and is excluded from git
via `.gitignore`.

## Running tests

```bash
./gradlew test
```

Covers the CSV parser, the raw-text normaliser (field extraction, status
vocabulary mapping, malformed-line handling), every detection rule, JWT
issuance/validation/tamper detection, and PDF report generation (including
pagination).

## Roadmap ideas

- Multi-user role-based report approval workflow
- Pattern-matching detection (regex / stateful sequences)
- LLM-assisted narrative summaries for hand-over
- SIEM/webhook export (e.g., push to an external node on a one-way diode)
