# OT-Sentinel

**Offline Incident Response & Log Forensics Dashboard** for OT/ICS environments.

> **Documentation:** the full technical project report (architecture, data model, algorithm
> flows, test evidence, limitations and roadmap) is available in
> [`PROJECT_REPORT.md`](PROJECT_REPORT.md).

When an OT device (PLC/RTU) is suspected to be compromised, engineers manually
collect log files from the plant floor. OT-Sentinel is an **air-gapped, local
web tool** that ingests those logs, parses them, runs rule-based anomaly
detection, visualises the results, and exports a PDF incident report — all
without any cloud connectivity.

## Why it exists

Most OT security tooling is commercial (Nozomi, Claroty) or focuses on network
scanning. Log forensics on air-gapped networks has no simple open-source
package — until now. OT-Sentinel gives you:

- Local authentication (JWT in an HttpOnly cookie, no cloud IdP) with sign-in lockout
- CSV **and** proprietary raw-text log ingestion from PLC/RTU exports
- Rule-based detection engine (brute force, unusual commands, off-hours activity)
- Interactive forensic dashboard (Chart.js + fully offline threat map, all bundled locally)
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
├── security                    # SecurityConfig, JwtAuthenticationFilter, JwtUtil
├── controller                 # AuthController, DashboardController, ReportController
├── service                    # LogParserService, RawLogNormalizerService,
│                              # AnomalyDetectionService, ReportService, LoginAttemptService
├── repository                 # LogEntryRepository, IncidentRepository, UserRepository
│                              # + LabelCount / LogRow aggregation projections
├── model                      # LogEntry, Incident, User
└── resources
    ├── templates              # dashboard.html, login.html, fragments/design-system.html
    ├── static/lib             # Bootstrap, Chart.js, Leaflet (all served locally)
    └── sample-data            # plc_logs.csv, raw_plc_logs.txt
```

### Design system

All screens share one source of truth: `templates/fragments/design-system.html`
holds the semantic CSS custom properties (colour, typography scale, spacing,
radii, shadows, motion) that the login page and the dashboard both consume, so
the two can never drift apart.

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
| POST   | `/incidents/detect`           | Re-scan all stored logs (no re-upload) |
| GET    | `/api/charts/command-frequency` | JSON: commands vs counts      |
| GET    | `/api/charts/status-distribution`| JSON: SUCCESS vs FAILURE     |
| GET    | `/api/charts/timeline`        | JSON: events per hour (24h)     |
| GET    | `/api/charts/top-ips`         | JSON: top 10 source IPs         |
| GET    | `/api/charts/sources`         | JSON: every source IP (map)     |
| GET    | `/api/charts/incident-severity` | JSON: incidents by severity   |
| GET    | `/api/report/pdf`             | Download the incident report    |

## Configuration

Production overrides happen through environment variables:

```bash
JWT_SECRET="a-long-random-32+-character-secret"
JWT_EXPIRATION="86400000"
OT_SENTINEL_ADMIN_PASSWORD="..."        # seeded admin password
OT_SENTINEL_ENGINEER_PASSWORD="..."     # seeded engineer password
OT_SENTINEL_SHOW_CREDENTIALS=false      # hide the demo accounts on the login screen
```

Full property reference (`src/main/resources/application.properties`):

| Property | Default | Purpose |
|----------|---------|---------|
| `ot-sentinel.rules.brute-force-threshold` | `5` | Failed logins per IP that trigger `BRUTE_FORCE` |
| `ot-sentinel.rules.brute-force-window-minutes` | `60` | Sliding window of the brute-force rule |
| `ot-sentinel.rules.off-hours` | `0-5` | Hour range treated as "off hours" |
| `ot-sentinel.security.max-login-attempts` | `5` | Failed sign-ins before the account locks |
| `ot-sentinel.security.login-lockout-minutes` | `5` | Duration of the sign-in lockout |
| `ot-sentinel.demo.show-credentials` | `true` | Show the seeded accounts on the login screen |
| `ot-sentinel.h2-console.enabled` | `false` | Enable the embedded H2 console (requires a session) |
| `spring.jpa.hibernate.ddl-auto` | `update` | Keeps the ingested evidence across restarts |

### Security notes

- The JWT is carried in an `HttpOnly`, `SameSite=Lax` cookie (and `Secure` automatically
  when served over HTTPS), so cross-site requests cannot ride on the session.
- API calls that lose their session return `401` with a JSON body; browser navigation
  is redirected to the login page.
- The embedded H2 console is **disabled by default** - it exposes the raw evidence
  tables. Enable it only on an isolated machine.
- Repeated failed sign-ins lock the account for a configurable period.

### Air-gapped operation

Everything the dashboard needs is bundled: Bootstrap, Chart.js and Leaflet are served
from `static/lib`. The threat map draws its own graticule locally on a canvas and
renders the country outlines from a bundled Natural Earth GeoJSON, so **no external
tile server is contacted and no data leaves the machine**.

### Threat map & IP location register

The map only places a pin where an address has a **verified** location in the local
register (`static/lib/geo/ip-locations.csv`):

```
ip_range,label,latitude,longitude
8.8.8.0/24,Google Public DNS (Mountain View, US),37.3860,-122.0838
```

* Public ranges ship with their verified real-world coordinates.
* Private addresses (RFC1918) have **no public geolocation**. They are listed in the
  "Source IP locations" table as *internal - no public geolocation* and are **not**
  pinned, because placing them at a guessed position would fabricate evidence.
* Add your own plant sites to the same file (single address or CIDR block) and those
  devices are pinned at their real coordinates.

The map uses every distinct source address, not only the top ten - a single connection
from an unusual network is exactly what a map must show.

## Performance

The dashboard aggregates in the database (`GROUP BY` queries and narrow projections)
instead of loading the log table into the JVM, and the log table is indexed on
timestamp, status and source IP. Re-scanning stays responsive on large datasets.

## Running tests

```bash
./gradlew test
```

Covers the CSV parser (including header detection and unreadable timestamps), the
raw-text normaliser (field extraction, status vocabulary mapping, malformed-line
handling), every detection rule, the sign-in lockout, JWT issuance/validation/tamper
detection, and PDF report generation (including pagination).

## Roadmap ideas

- Multi-user role-based report approval workflow
- Pattern-matching detection (regex / stateful sequences)
- LLM-assisted narrative summaries for hand-over
- SIEM/webhook export (e.g., push to an external node on a one-way diode)
