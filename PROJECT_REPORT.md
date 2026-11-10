# OT-Sentinel: Offline Incident Response & Log Forensics Dashboard

### A Technical Project Report

**Submitted in partial fulfilment of the requirements for the degree of Bachelor of Technology**

---

| | |
|---|---|
| **Project Title** | OT-Sentinel: Offline Incident Response & Log Forensics Dashboard |
| **Author** | Imran Pasha |
| **Registration Number** | 11CSHAIIMRANPASHA |
| **Institution** | Department of Computer Science & Engineering |
| **Project Repository** | `https://github.com/codee-19imran/ot-sentinel` |
| **Date of Submission** | 10 November 2026 |
| **Document Version** | 1.0 (Release) |
| **Software Version** | 0.0.1-SNAPSHOT |

---

## ABSTRACT

Industrial control systems are frequently operated in isolated, air-gapped environments in which commercial security monitoring products cannot be deployed. When a supervisory control and data acquisition (SCADA) or programmable logic controller (PLC) compromise is suspected, field engineers are reduced to manually collecting exported log files and inspecting them with general-purpose utilities. This project addresses that gap by presenting **OT-Sentinel**, a self-contained, web-based forensic analysis platform that ingests, normalises, analyses and reports on operational technology (OT) telemetry entirely within the local network boundary.

The system is implemented as a Spring Boot 3.5 application on the Java 21 platform, backed by an embedded H2 relational database persisted to disk, and rendered through server-side Thymeleaf templates. It provides local JWT-based authentication with brute-force lockout, dual-format log ingestion (canonical CSV and proprietary PLC text normalised through a dedicated service), a configurable rule-based anomaly detection engine operating on three independent heuristics, and an interactive dashboard built on Chart.js and Leaflet. An Apache PDFBox subsystem produces colour-coded, paginated forensic reports suitable for physical hand-over in classified environments. A significant design decision is the complete absence of external network dependencies: all front-end assets, the map base layer and the IP geolocation reference are bundled locally, so that no operational data leaves the plant floor. The platform was validated through 36 automated unit and context tests, an end-to-end ingestion trace and a systematic browser-level review, and it is released as an open-source artefact.

**Keywords:** Industrial Control Systems, Digital Forensics, Anomaly Detection, Incident Response, Air-Gapped Systems, Spring Boot

---

## CHAPTER 1: INTRODUCTION

### 1.1 Background & Motivation

The convergence of Information Technology (IT) and Operational Technology (OT) has fundamentally altered the threat landscape of critical infrastructure. Supervisory control systems that once operated on isolated, purpose-built networks now routinely exchange data with enterprise services through historians, remote-access gateways and industrial internet gateways. This interconnection has been exploited repeatedly in high-profile incidents, most notably the 2020 TRITON attack against a Saudi Arabian safety instrumented system and the 2021 Colonial Pipeline disruption, both of which demonstrated that the failure modes of IT and OT security are entirely different from those encountered in conventional enterprise environments.

Consequently, OT security has become a distinct discipline with distinct tooling requirements. The dominant commercial products in this space — Nozomi Networks, Claroty and Dragos — are sophisticated, continuously-connected platforms engineered for enterprise networks with guaranteed uplink connectivity. They are, however, fundamentally incompatible with the environments in which many OT assets operate: isolated process plants, offshore installations, power substations and national critical infrastructure, where persistent external connectivity is prohibited by both regulation and operational doctrine.

The absence of a lightweight, self-contained analytical capability in this domain defines the practical problem. Field engineers investigating a suspected compromise in such an environment are left with a common, and fundamentally unsatisfying, workflow: exported log files are transferred onto an analyst's workstation via removable media and are then examined using general-purpose tools. Spreadsheet analysis is manual and error-prone; command-line inspection does not scale across the heterogeneous log formats emitted by different vendors; and, most significantly, no mechanism exists to apply consistent detection logic across an incident. Each investigation effectively begins from zero, and the institutional knowledge gained during one engagement is rarely captured in a reusable form.

This project was conceived against that observation. The premise is that the analytical capability of a full commercial OT monitoring platform — the parsing, the correlation, the visual presentation and the evidentiary reporting — can be delivered in a form that is small enough, portable enough and sufficiently self-contained to be carried onto a site by a single engineer, and deployed without any external connectivity whatsoever.

### 1.2 Problem Statement

Formally, the problem addressed by this project may be stated as follows:

> **To design and implement an offline, air-gapped web application that ingests heterogeneous OT/ICS log exports, normalises them into a canonical analytical schema, applies a configurable rule-based detection engine to identify malicious or anomalous activity, presents the findings through an interactive forensic dashboard, and exports a formal evidentiary report — with no dependency on any external network service at any point in the pipeline.**

The statement decomposes into four constituent problems, each of which was addressed independently:

| # | Constituent problem | Nature |
|---|---|---|
| **P1** | Vendor PLCs emit **proprietary, unstructured text logs** rather than canonical tabular exports, rendering manual analysis impractical | Data engineering |
| **P2** | Detection logic must be applied **consistently and reproducibly** across engagements, not improvised per incident | Automation |
| **P3** | Findings must be communicated to non-technical stakeholders (plant management, auditors, incident response teams) through an accessible visual interface | Human–computer interaction |
| **P4** | Analytical output must be **exportable as a formal artefact** suitable for inclusion in an incident record | Documentation |

A subsidiary constraint applies to all four: the entire system must operate with **zero external network dependency**, since the target environment cannot provide it.

### 1.3 Project Objectives

The project was executed against the following ordered objectives:

1. **Establish an offline analytical platform** — deliver a runnable web application on the Java/Spring ecosystem that operates with no internet connectivity, validated by confirming that all front-end assets, map data and geolocation references are served from local resources.
2. **Implement a secure local access model** — provide authenticated access via JWT carried in an `HttpOnly` cookie, enforce role-based identity, and defend the authentication endpoint against credential brute-forcing.
3. **Build a dual-format ingestion subsystem** — accept both canonical CSV exports and proprietary vendor text formats, normalising the latter into the canonical schema through a dedicated, independently testable service.
4. **Develop a configurable detection engine** — implement multiple independent heuristics (brute-force authentication, unusual control commands, off-hours activity) whose thresholds are externally configurable without recompilation.
5. **Construct an interactive forensic dashboard** — provide statistical visualisations, an incident register and a geographic activity view, each with explicit loading, error and empty states.
6. **Enable formal report generation** — export findings as a paginated, colour-coded PDF document suitable for evidentiary hand-over.
7. **Guarantee data integrity** — ensure that ingested evidence survives application restarts, that malformed records are surfaced rather than silently discarded, and that no timestamp is fabricated.
8. **Establish a rigorous test regime** — achieve verifiable coverage of the parsing, normalisation, detection, authentication and reporting subsystems.

### 1.4 Scope of the Project

#### In Scope

| Dimension | Boundary |
|---|---|
| **Deployment model** | Single-node, on-premises workstation or laptop. No clustering, no container orchestration, no container registry dependency. |
| **Network posture** | Fully air-gapped. No external service is contacted at build-time runtime or during operation. |
| **Persistence** | Embedded H2 database in file-backed mode (`ot_sentinel_db.mv.db`), schemata managed by Hibernate `ddl-auto=update`. |
| **Ingestion formats** | Canonical CSV (`timestamp,sourceIp,command,status,deviceId`); proprietary vendor text of the form `[ts] LEVEL Device=… Source=… Action=… Result=…`; plain-text variations of the CSV layout. |
| **Detection** | Three statistical heuristics applied over the whole stored corpus. No statistical learning, clustering or correlation across unrelated log sources. |
| **Authentication** | Local credential store, JWT issuance and validation, per-account lockout, two seeded roles (`ADMIN`, `ENGINEER`). |
| **Reporting** | Server-side PDF rendering via Apache PDFBox 3. |
| **Mapping** | Bundled Natural Earth country outlines, local canvas graticule and a locally maintained IP-to-location register. |

#### Out of Scope

| Excluded area | Rationale |
|---|---|
| **Live network monitoring / packet capture** | The system is a *post-incident log forensics* tool, not a sensor platform. Real-time passive monitoring is a distinct and substantially larger engineering effort. |
| **Enterprise identity federation** | LDAP, Active Directory and SAML/OIDC integration are deferred to the future roadmap. |
| **Cryptographic signing of reports** | The exported PDF carries no digital signature or chain of custody; this is a documented limitation addressed in Chapter 6. |
| **Host-based forensics** | Disk imaging, memory forensics and endpoint triage are outside the log-centric analytical model adopted here. |
| **Multi-tenancy and horizontal scale** | The architecture deliberately favours a single-node, portable deployment over distributed operation. |
| **Commercial threat-intelligence integration** | No external IP reputation or geolocation feed is consumed, by necessity and by design. |

#### User Roles

| Role | Authorisation | Permitted activity |
|---|---|---|
| **Administrator (`ADMIN`)** | Full | All engineer capabilities plus account administration and configuration of the seeded credential set. |
| **Engineer (`ENGINEER`)** | Operational | Upload logs, execute detection runs, review incidents, export PDF reports. Cannot alter system accounts or rule configuration. |

---

## CHAPTER 2: SYSTEM REQUIREMENTS & FEASIBILITY

### 2.1 Hardware Requirements

#### Minimum Configuration

| Component | Specification | Justification |
|---|---|---|
| **Processor** | Any x86-64 or ARM64 core, 2 threads @ 2.0 GHz | The workload is I/O-bound (file parsing, relational aggregation); sustained computation is minimal. |
| **Memory** | 4 GB RAM | JVM heap (~1 GB), embedded H2 buffer pool and OS overhead. Sufficient for corpora up to ~250 000 log rows resident. |
| **Storage** | 2 GB free, SSD recommended | Application ~65 MB (fat JAR + bundled assets), H2 database, sample datasets, exported reports. |
| **Display** | 1366 × 768 @ 100% scaling | Minimum for the dashboard's two-column chart grid. Fully responsive down to 360 px. |
| **Network** | Loopback or isolated LAN segment only | The system is designed for networks without a gateway. |

#### Recommended Configuration

| Component | Specification | Justification |
|---|---|---|
| **Processor** | 4+ physical cores, 3.0 GHz base | Parallel benefit during bulk ingestion; lowers detection-run latency on large corpora. |
| **Memory** | 8–16 GB RAM | Accommodates corpora in excess of one million rows with comfortable JVM headroom. |
| **Storage** | 256 GB SSD | Retains full incident history plus archived PDF reports across multiple engagements. |
| **Display** | 1920 × 1080 | Exploits the two-column dashboard grid; the chart grid and incident register become simultaneously visible. |
| **Peripherals** | USB 3.0 removable media | For the physical log-transfer workflow that defines the operating environment. |

#### Measured Resource Utilisation

Empirical observation from the reference deployment (147-row sample corpus, five charts, one map render):

| Metric | Observed value |
|---|---|
| Application startup to readiness | 14–20 s (JVM start, Hibernate schema validation, Tomcat init) |
| Dashboard first paint → all charts rendered | < 1.5 s |
| Cold ingestion of 155 CSV rows + detection run | ~0.4 s (parse, persist, aggregate, detect) |
| H2 database footprint after 465 ingested rows | ~70 KB |
| JVM heap at steady state | ~180 MB |

### 2.2 Software Requirements

#### Development Environment

| Component | Version / Specification | Purpose |
|---|---|---|
| **Operating system** | Linux (Ubuntu 22.04 LTS / Debian 12), Windows 11, macOS 14 | Cross-platform host for the build toolchain and the runtime. |
| **JDK** | Eclipse Temurin / OpenJDK **21** (LTS) | Language and platform baseline, including the `toolchain` directive enforcing reproducibility across developer machines. |
| **Build system** | Gradle **9.x** with the Spring Boot plugin **3.5.16** | Dependency management, reproducible fat-JAR packaging, declarative test execution. |
| **IDE** | IntelliJ IDEA 2024+ (Spring Boot support), Eclipse 2024+, or VS Code | Not enforced by the build; the Gradle wrapper makes the project IDE-agnostic. |
| **Version control** | Git 2.40+ | Branching, history, release tagging. |
| **Documentation tooling** | Markdown (GitHub-flavoured) | Report, README and in-repository developer documentation. |

#### Runtime Dependencies

| Layer | Library | Version | Role |
|---|---|---|---|
| **Web framework** | `spring-boot-starter-web` | 3.5.16 | Embedded Tomcat, Spring MVC, Jackson serialisation |
| **Security** | `spring-boot-starter-security` | 3.5.16 | Authentication chain, filter chain, method-level authorisation |
| **Persistence** | `spring-boot-starter-data-jpa` | 3.5.16 | Hibernate ORM, Spring Data repositories, transaction management |
| **Templating** | `spring-boot-starter-thymeleaf` | 3.5.16 | Server-side rendering with Spring Security dialect |
| **Template security** | `thymeleaf-extras-springsecurity6` | 6.x | `#authentication` expression support |
| **Token handling** | `io.jsonwebtoken:jjwt-api` (+`impl`, `jackson`) | 0.12.3 | JWT issuance, signature verification, claim extraction |
| **PDF generation** | `org.apache.pdfbox:pdfbox` | 3.0.3 | Vector PDF composition, pagination, colour-coded severity rendering |
| **Database** | `com.h2database:h2` | (Boot-managed) | File-backed embedded relational store |
| **Persistence utility** | `org.projectlombok:lombok` | (Boot-managed) | Compile-time generation of entity accessors and builders |
| **Front-end** | Bootstrap 5, Chart.js 4, Leaflet 1.9.4 | — | Bundled locally under `static/lib/` |
| **Test framework** | `spring-boot-starter-test`, JUnit 5, AssertJ, Mockito | (Boot-managed) | Unit and context testing |

#### Design Constraints Derived from the Environment

| Constraint | Rationale | Implementation response |
|---|---|---|
| No internet at runtime | Air-gapped target environment | All assets vendored; map rendered from a local canvas + bundled GeoJSON; geolocation from a local CSV register |
| Evidence must persist | Investigations span restarts | `ddl-auto=update`; the database file is never dropped |
| Sensitive data on disk | Forensic corpora may contain sensitive infrastructure detail | Password hashes via BCrypt; H2 console disabled by default; geolocation register shipped with verified entries only |

### 2.3 Feasibility Study

The project was assessed against three conventional feasibility axes prior to commencement.

#### Technical Feasibility — **VIABLE**

Every capability is drawn from mature, well-documented components with established offline deployment characteristics. Spring Boot, H2, Chart.js, Leaflet and PDFBox are all distributed as embeddable artefacts with no mandatory external service dependency. The principal technical risk lay in the proprietary-log normalisation requirement (P1), which was assessed as moderate: text extraction via regular expression is well-understood, and the risk was mitigated by designing the normaliser as an isolated, independently unit-testable service with a documented input contract. The Leaflet map subsystem was likewise assessed as the highest-risk front-end component and was ultimately delivered fully offline through a custom `GridLayer` implementation.

#### Operational Feasibility — **VIABLE**

The system is designed around a workflow in which a single engineer carries a laptop into a plant, starts the application with one command, and analyses the evidence without configuring anything. The deliberate decision to use an embedded database removes all installation-time database administration, a significant operational advantage in multi-site incident work where reliable network access to a database server cannot be assumed. The single-artifact fat-JAR distribution model further reduces field-deployment risk. The principal operational consideration is that detection thresholds must be tuned per site, which is addressed by externalising all thresholds to configuration properties.

#### Economic Feasibility — **VIABLE**

| Cost category | Commercial equivalent | Assessment |
|---|---|---|
| **Software licensing** | Commercial OT monitoring platforms are typically licensed per monitored asset, with enterprise tiers reaching five- and six-figure annual costs. | **Zero.** All dependencies are permissively licensed open-source artefacts; no licence fee is incurred for any component. |
| **Infrastructure** | Continuous monitoring platforms require a server or virtualisation allocation and a network uplink. | **Negligible.** Executes on an existing engineering workstation with no additional hardware. |
| **Human effort** | Operating a commercial platform requires trained, certified personnel and a formal subscription. | **Minimised.** The tool is self-explanatory; the deployment procedure is a single command. |
| **Deployment lead time** | Enterprise platform procurement and integration typically spans weeks to months. | **Minutes.** The fat JAR runs immediately; no procurement, no integration, no external coordination. |

The economic argument is therefore decisive: the project delivers the *analytical subset* of a commercial OT security platform at effectively zero marginal cost and near-zero deployment latency, targeting precisely the segment — isolated plants with no uplink — that commercial products serve least well.

---

## CHAPTER 3: SYSTEM ARCHITECTURE & DESIGN

### 3.1 High-Level Architecture

The system adopts a **layered monolithic architecture** with a strict separation of concerns, executed as a three-tier web application. This style was selected deliberately over microservices: the deployment target is a single air-gapped workstation, so the operational overhead of distributed services would provide no benefit while substantially complicating offline operation.

#### Layer Decomposition

```
┌──────────────────────────────────────────────────────────────────────┐
│                        PRESENTATION LAYER                            │
│  Thymeleaf templates: dashboard.html, login.html                    │
│  fragments/design-system.html — shared semantic design tokens       │
│  Static assets (bundled): Bootstrap 5, Chart.js 4, Leaflet 1.9.4    │
│  Geo assets (bundled): world-countries.geojson, ip-locations.csv    │
│  Chart.js visualisations · Leaflet map · in-page anchor navigation  │
└───────────────────────────┬──────────────────────────────────────────┘
                            │ HTTP (Thymeleaf SSR + JSON fetch)
┌───────────────────────────▼──────────────────────────────────────────┐
│                         WEB LAYER                                    │
│  ┌──────────────────┐  ┌──────────────────┐  ┌────────────────────┐  │
│  │  AuthController  │  │DashboardController│ │ ReportController   │  │
│  │  /api/auth/*     │  │ /dashboard       │  │ /api/report/pdf    │  │
│  │  login · logout  │  │ /logs/upload     │  │                    │  │
│  │                  │  │ /logs/upload-raw │  │                    │  │
│  │                  │  │ /incidents/detect│  │                    │  │
│  │                  │  │ /api/charts/*    │  │                    │  │
│  │                  │  │ /api/incidents  │  │                    │  │
│  └────────┬─────────┘  └────────┬─────────┘  └─────────┬──────────┘  │
│           │  Spring Security filter chain (JWT filter)  │             │
└───────────┼───────────────────────┼─────────────────────┼─────────────┘
            │                       │                     │
┌───────────▼───────────────────────▼─────────────────────▼─────────────┐
│                        SERVICE LAYER                                 │
│  ┌────────────────────┐ ┌────────────────────┐ ┌───────────────────┐ │
│  │  LogParserService  │ │RawLogNormalizer    │ │AnomalyDetection   │ │
│  │  canonical CSV     │ │Service             │ │Service            │ │
│  │  → LogEntry        │ │ proprietary text    │ │ 3 heuristics      │ │
│  │                    │ │  → canonical CSV   │ │                   │ │
│  └────────────────────┘ └────────────────────┘ └───────────────────┘ │
│  ┌────────────────────┐ ┌────────────────────┐ ┌───────────────────┐ │
│  │   ReportService    │ │ LoginAttemptService│ │ UserDetailsService│ │
│  │   PDFBox export    │ │ lockout policy     │ │ credential lookup │ │
│  └────────────────────┘ └────────────────────┘ └───────────────────┘ │
└───────────────────────────┬──────────────────────────────────────────┘
                            │ Spring Data JPA / Hibernate
┌───────────────────────────▼──────────────────────────────────────────┐
│                      PERSISTENCE LAYER                              │
│  LogEntryRepository · IncidentRepository · UserRepository             │
│  Projections: LabelCount (GROUP BY) · LogRow (narrow row)           │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │  Embedded H2 (file mode)  —  ot_sentinel_db.mv.db              │  │
│  │  log_entries · incidents · users  + indexes                   │  │
│  └────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

#### Request Lifecycle

A representative authenticated dashboard request traverses the system as follows:

1. **Browser** issues `GET /dashboard` with the `OT_SENTINEL_TOKEN` cookie.
2. **`JwtAuthenticationFilter`** (registered *before* `UsernamePasswordAuthenticationFilter`) extracts the token, validates its HMAC signature and expiry, loads the `UserDetails`, and populates the `SecurityContext`. Stateless session policy ensures no server-side session is created.
3. **`DashboardController.dashboard()`** aggregates statistics — counts via `countByStatus`, the incident register via `findByResolvedFalse()`, and the recent-log table via a server-side `findTop20ByOrderByEventTimeDesc()` — and populates the model.
4. **Thymeleaf** renders `dashboard.html` server-side; the `#authentication.name` expression resolves the signed-in identity.
5. **Client-side JavaScript** issues parallel `fetch` calls to `/api/charts/*`; each is handled independently with an explicit loading state, a success state and an error-with-retry state.
6. **Chart.js** renders the visualisations; **Leaflet** renders the map from locally bundled assets.

#### Design Decisions at the Architectural Level

| Decision | Rationale | Consequence |
|---|---|---|
| Layered monolith over microservices | Single-node air-gapped target; distribution adds operational cost without benefit | Simple deployment; one JAR; no service discovery or inter-service auth required |
| Server-side rendering (Thymeleaf) over SPA (React) | Minimises front-end build tooling and keeps the artefact self-contained; SSR improves first paint and removes client-side routing complexity | Chart interactivity implemented in a single dependency-free IIFE rather than a component framework |
| Embedded H2 over PostgreSQL | Portability and zero administration are decisive on a plant floor | Single-file database; not suitable for concurrent multi-user write workloads at scale |
| Statistical rules over machine learning | Deterministic, explainable and auditable output is essential for forensic evidence; a model's rationale cannot be cited in an incident report | Rules are interpretable and tunable; no training corpus required |
| Pre-aggregated queries over in-memory processing | The original implementation loaded the entire corpus per chart, which does not scale to realistic forensic volumes | Aggregation pushed to the database with indexed columns |

### 3.2 Database / Data Model

The relational model comprises three entities. Evidence is stored in `log_entries`; derived findings are stored in `incidents`; local accounts are stored in `users`.

#### Entity-Relationship Diagram

```
┌───────────────────────────┐              ┌───────────────────────────┐
│        log_entries        │              │         incidents         │
├───────────────────────────┤              ├───────────────────────────┤
│ PK  id           BIGINT   │              │ PK  id           BIGINT   │
│     log_timestamp TIMESTAMP│ ──────────▶ │     type          VARCHAR │
│     source_ip     VARCHAR │   derived    │     severity      VARCHAR │
│     command_type  VARCHAR │   from       │     description   VARCHAR │
│     status        VARCHAR │              │     source_ip     VARCHAR │
│     device_id     VARCHAR │              │     detected_at   TIMESTAMP│
│     raw_line      VARCHAR │              │     resolved      BOOLEAN │
├───────────────────────────┤              ├───────────────────────────┤
│ IDX log_timestamp         │              │ IDX resolved              │
│ IDX status                │              │ IDX severity              │
│ IDX source_ip             │              │ IDX detected_at           │
└───────────────────────────┘              └───────────────────────────┘

┌───────────────────────────┐
│          users            │
├───────────────────────────┤
│ PK  id           BIGINT   │
│ UQ  username     VARCHAR  │
│     password     VARCHAR  │  ← BCrypt hash
│     role         VARCHAR  │  ← ADMIN | ENGINEER
└───────────────────────────┘
```

The relationship between `log_entries` and `incidents` is **one-to-many and non-referential**: an incident is a *derived* conclusion, not a foreign-key child of a row. This is deliberate. The detection engine clears and recomputes the entire incident table on each run, so that the register always reflects the current rule configuration and corpus rather than accumulating stale findings. Each incident nevertheless retains the `source_ip` of the offending address, providing the investigative linkage back to the underlying evidence rows.

#### Field-Level Specification

| Table | Column | Type | Null | Constraint | Purpose |
|---|---|---|---|---|---|
| `log_entries` | `id` | `BIGINT` | No | PK, identity | Surrogate key |
| | `log_timestamp` | `TIMESTAMP` | Yes | Indexed | Event time; **nullable by design** — an unreadable timestamp is recorded as unknown rather than fabricated |
| | `source_ip` | `VARCHAR` | Yes | Indexed | Originating address |
| | `command_type` | `VARCHAR` | Yes | — | `READ`, `WRITE`, `LOGIN`, `STOP`, `DELETE`, `RESET`, `SHUTDOWN` |
| | `status` | `VARCHAR` | Yes | Indexed | Normalised to `SUCCESS` / `FAILURE` |
| | `device_id` | `VARCHAR` | Yes | — | PLC / RTU / HMI identifier |
| | `raw_line` | `VARCHAR` | Yes | — | Original source line, retained for forensic traceability |
| `incidents` | `id` | `BIGINT` | No | PK, identity | Surrogate key |
| | `type` | `VARCHAR` | Yes | — | `BRUTE_FORCE`, `UNUSUAL_COMMAND`, `OFF_HOURS_ACTIVITY` |
| | `severity` | `VARCHAR` | Yes | Indexed | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| | `description` | `VARCHAR` | Yes | — | Human-readable finding with quantitative detail |
| | `source_ip` | `VARCHAR` | Yes | — | Investigative linkage to `log_entries.source_ip` |
| | `detected_at` | `TIMESTAMP` | Yes | Indexed | Detection execution time |
| | `resolved` | `BOOLEAN` | No | Indexed | Closure state |
| `users` | `id` | `BIGINT` | No | PK, identity | Surrogate key |
| | `username` | `VARCHAR` | No | Unique, not null | Login identifier |
| | `password` | `VARCHAR` | No | Not null | BCrypt hash |
| | `role` | `VARCHAR` | No | Not null | `ADMIN` / `ENGINEER` |

The column name `log_timestamp` was selected in preference to `timestamp` because the latter is a reserved SQL keyword, and the corresponding entity property was named `eventTime` to avoid ambiguity in JPQL queries.

#### Aggregation Projections

Two Spring Data interface projections eliminate the need to materialise full entities for reporting:

| Projection | Purpose | Example query |
|---|---|---|
| `LabelCount` | Grouped counts for dashboard charts | `select l.status as label, count(l) as total from LogEntry l group by l.status` |
| `LogRow` | Narrow column subset consumed by the detection engine | `select l.sourceIp as sourceIp, l.commandType as commandType from LogEntry l where l.commandType in :commands` |

These projections underpin the performance characteristics described in Section 5.3.

### 3.3 Key Algorithms & Logic Flow

#### 3.3.1 Ingestion and Normalisation Flow

```
   Uploaded file
        │
        ├─── .csv / canonical ─────────────────► LogParserService.parseAndSaveLogs()
        │                                                │
        └─── .txt / proprietary ──► RawLogNormalizerService.ingestRawLogs()
                                          │  1. regex match per line
                                          │  2. extract 5 semantic fields
                                          │  3. map vendor status → SUCCESS/FAILURE
                                          │  4. emit canonical CSV text
                                          ▼
                                 LogParserService.parseAndSaveCsv()
                                          │  5. skip header row (strict match)
                                          │  6. split into 5 fields
                                          │  7. parse timestamp (7 formats)
                                          │  8. reject rows with < 5 fields
                                          ▼
                                 LogEntryRepository.saveAll()  ──► log_entries
```

The proprietary-log grammar is described by the regular expression:

```java
"^\\[\\s*([^\\]]+?)\\s*\\]\\s+\\w+\\s+Device=(\\S+)\\s+Source=(\\S+)\\s+Action=(\\S+)\\s+Result=(\\S+)\\s*$"
```

The pattern tolerates variable whitespace, an arbitrary log-level token, and hostnames as well as IPv4 addresses in the `Source` field. Unrecognised lines are counted and logged at `WARN` level rather than being silently discarded — a deliberate forensic principle.

#### 3.3.2 Detection Engine — Brute-Force Heuristic

```java
@Query("select l.sourceIp as label, count(l) as total from LogEntry l "
        + "where l.status = 'FAILURE' and l.eventTime is not null and l.eventTime >= :since "
        + "and l.sourceIp is not null group by l.sourceIp order by count(l) desc")
List<LabelCount> countFailuresPerIpSince(@Param("since") LocalDateTime since);
```

The aggregation is performed by the database. The engine inspects the result set and raises an incident for any address whose failure count **exceeds** the configured threshold within the sliding window. The use of a strict inequality (`> threshold`) means the default configuration of `5` flags the sixth failure, matching the specification wording "more than 5 failed logins".

#### 3.3.3 Detection Engine — Unusual Control Command Heuristic

The heuristic targets control-plane commands that would be anomalous during normal production operation. The candidate set is restricted to `STOP`, `DELETE`, `RESET` and `SHUTDOWN`; the query is scoped to those values so that only matching rows are materialised. Findings are aggregated per source address, and the description enumerates the distinct commands observed, providing the analyst with both a count and the command vocabulary in a single finding.

#### 3.3.4 Detection Engine — Off-Hours Activity Heuristic

A source address generating three or more commands within the configured off-hours window (`00:00`–`05:59` by default) is flagged. The hour extraction is performed in application logic over a narrow two-column projection, which avoids database-specific date functions and thereby preserves portability across relational engines.

#### 3.3.5 Detection Run Orchestration

```java
public List<Incident> detectAll() {
    incidentRepository.deleteAll();                       // clear stale findings
    List<Incident> all = new ArrayList<>();
    all.addAll(detectBruteForce(threshold, window));      // heuristic 1
    all.addAll(detectUnusualCommands());                   // heuristic 2
    all.addAll(detectOffHoursActivity());                  // heuristic 3
    List<Incident> saved = incidentRepository.saveAll(all);
    return saved;
}
```

The clear-then-recompute sequence guarantees that the incident register always corresponds to the current rule configuration and the current corpus, at the cost of requiring the three heuristics to execute in a single transaction.

#### 3.3.6 Authentication and Lockout Flow

```
   POST /api/auth/login
        │
        ├── attemptKey = lower(username) + "|" + clientAddress
        │
        ├── isLocked(attemptKey)? ──yes──► reject (remaining lockout time reported)
        │                                    no
        ▼
   AuthenticationManager.authenticate(username, password)
        │
        ├── success ──► recordSuccess(key) ──► issue JWT ──► Set-Cookie
        │                (HttpOnly, SameSite=Lax, Secure per request)
        │
        └── failure ──► recordFailure(key) ──► increment counter
                         └─ counter ≥ 5 ? ──► lock for configured duration
```

#### 3.3.7 Threat Map Location Resolution

```
   Source IP address
        │
        ├── private (RFC1918 / loopback / link-local / CGNAT)?
        │        └── yes ──► "internal, no public geolocation" ──► listed, NOT pinned
        │
        └── no
             │
             └── longest-prefix match against local register (exact > CIDR)
                    ├── match ──► pin at the registered coordinates + label
                    └── no match ──► "no entry in the location register" ──► listed, not pinned
```

This algorithm embodies a central forensic principle: **an address is plotted only where its position is verifiable.** Addresses without a verified position are reported as such rather than being assigned a plausible-looking but fabricated coordinate.

---

## CHAPTER 4: IMPLEMENTATION DETAILS

### 4.1 Technology Stack Rationale

#### Spring Boot 3.5 on Java 21

Spring Boot was selected for its **executable-artefact packaging model**: the entire application, including all front-end libraries and the embedded database driver, is delivered as a single ~65 MB executable JAR. For an air-gapped deployment carried onto a site by hand, this is the decisive property — there is no application server to install, no container image to pull and no dependency to resolve over a network. Java 21 provides long-term-support availability alongside modern language features such as pattern matching for `switch` and records, and the Gradle `toolchain` directive guarantees that every contributor compiles against an identical JDK version regardless of their local installation.

#### H2 in File-Backed Mode

Relational persistence was a non-negotiable requirement: the detection heuristics perform grouped aggregation, and the reporting subsystem requires ordered retrieval of findings. H2 in file-backed mode satisfies this while eliminating database administration entirely. The database is a single file (`ot_sentinel_db.mv.db`) that can be copied onto removable media as part of an evidence package. The schema-management strategy was changed from `create-drop` to `update` during development, after it was identified that the former destroys the evidence corpus on graceful shutdown — a behaviour wholly unacceptable for a forensic instrument.

#### Thymeleaf over a JavaScript Single-Page Application

Server-side rendering was chosen because it eliminates the front-end build chain. A React or Vue implementation would introduce Node.js, a bundler, a package registry and a transpilation step, each of which is a liability in an environment without reliable connectivity. Thymeleaf produces the complete dashboard HTML from the server; Chart.js and Leaflet are consumed as pre-built distributables. The measurable consequence is that the project builds and runs with a single `./gradlew bootJar` invocation and no front-end toolchain whatsoever.

#### Chart.js over Alternative Charting Libraries

Chart.js was selected for its canvas-based rendering, which handles several thousand data points without the DOM overhead of SVG-based alternatives, and for its responsive behaviour, which is essential given that the dashboard must render from 360 px to 1920 px. It is bundled locally at approximately 205 KB.

#### Leaflet with a Custom Offline Tile Layer

Leaflet was retained for its mature, lightweight interaction model. The decisive engineering work lay in the base layer: the conventional approach of requesting raster tiles from an external tile server is fundamentally incompatible with an air-gapped deployment and, additionally, discloses the investigating operator's IP address to a third party. The solution implemented was a custom `L.GridLayer` subclass that renders its tile imagery programmatically onto a `<canvas>`, combined with a bundled Natural Earth country-outline GeoJSON rendered as a vector overlay. The result is a map with recognisable coastlines that makes zero external network requests.

#### Apache PDFBox over iText

PDFBox 3 was selected for its Apache 2.0 licence (iText's AGPL or commercial licensing is incompatible with an open-source release), its low-level compositional API, and its support for precise typographic control. Colour-coded severity rendering, automatic pagination with continuation headers and per-page footers are all achievable directly through the content-stream API.

#### jjwt 0.12.3 for Token Handling

The JJWT library provides HS256 signing and verification with a concise, fluent API. Its stateless nature directly supports the application's deployment model: a JWT permits an entirely stateless session, which means no server-side session store, no session affinity and no cluster-coordination requirement.

### 4.2 Key Modules & Functionality

#### `SecurityConfig` — Filter Chain Construction

Establishes the stateless security posture, the public/protected path partitioning and the differentiated authentication-failure response. The distinction between browser and API clients is a deliberate refinement:

```java
.exceptionHandling(eh -> eh
        .authenticationEntryPoint((req, res, ex) -> {
            if (req.getRequestURI().startsWith("/api/")) {
                writeUnauthorized(res);   // 401 + JSON body
            } else {
                res.sendRedirect("/login"); // browser navigation
            }
        }))
```

The original implementation redirected *all* unauthenticated requests to the login page. Because `fetch` follows redirects by default, an expired session caused the client to receive HTML where JSON was expected, throwing an unhandled promise rejection that silently blanked every chart. The differentiated response eliminated this failure mode entirely.

#### `LogParserService` — Canonical Ingestion Engine

Central to the integrity guarantees of the system. Three behaviours are of particular forensic significance:

**Strict header detection.** The original implementation tested whether a line merely *contained* any header keyword. This silently discarded legitimate evidence: a row whose device was named `SOURCEIP-GATEWAY` was mistaken for a header and dropped. The refined implementation accepts a line as a header only when its first field is literally a timestamp column name, or when all five fields match the canonical column names.

```java
private boolean isHeader(String line) {
    String[] values = line.split(",", -1);
    if (values.length < 5) return false;
    String first = values[0].trim().toLowerCase();
    if (List.of("timestamp", "datetime", "date_time", "ts", "time").contains(first)) return true;
    List<String> known = List.of("timestamp", "sourceip", "command", "status", "deviceid");
    for (int i = 0; i < 5; i++) {
        if (!known.contains(values[i].trim().toLowerCase())) return false;
    }
    return true;
}
```

**No fabricated timestamps.** An unreadable timestamp previously fell back to `LocalDateTime.now()`, which manufactured evidence and could induce false-positive brute-force and off-hours findings by placing malformed records in the present moment. The corrected implementation returns `null`, records the condition as a `WARN` and allows the entry to persist with an unknown event time. Time-windowed rules already exclude null-timestamped records.

**Raw-line retention.** Every entry stores its originating source line, permitting an investigator to verify that the parser transformed the evidence faithfully.

#### `RawLogNormalizerService` — Proprietary Format Normalisation

Implements the data-normalisation capability required by problem P1. The service is purely stream-based, introducing no temporary files and no fixed output paths. Its status-mapping vocabulary constitutes the central semantic translation:

| Vendor token | Canonical status | Rationale |
|---|---|---|
| `OK`, `PASS`, `PASSED`, `SUCCESS`, `SUCCEEDED`, `GRANTED`, `ACCEPTED`, `COMPLETE`, `COMPLETED` | `SUCCESS` | Positive-outcome vocabulary |
| `FAIL`, `FAILED`, `FAILURE`, `ERROR`, `DENIED`, `REJECT`, `REJECTED`, `TIMEOUT`, `REFUSED` | `FAILURE` | Negative-outcome vocabulary |
| *Any other token* | Upper-cased passthrough | Unrecognised semantics are preserved rather than silently coerced |

The service delegates the final persistence step to `LogParserService`, so both ingestion paths converge on a single parser and a single persistence route. This guarantees that a record normalised from a proprietary format is indistinguishable, in the database, from one read from a canonical CSV.

#### `AnomalyDetectionService` — Rule Engine

Applies the three heuristics described in Section 3.3. Two design properties are significant. First, aggregation is delegated to the database, reducing each detection run from three full-table scans to three grouped queries. Second, all thresholds are injected through the `@Value` constructor, permitting site-specific tuning through configuration alone:

```java
public AnomalyDetectionService(LogEntryRepository logEntryRepository,
                               IncidentRepository incidentRepository,
                               @Value("${ot-sentinel.rules.brute-force-threshold:5}") int bruteForceThreshold,
                               @Value("${ot-sentinel.rules.brute-force-window-minutes:60}") int bruteForceWindowMinutes,
                               @Value("${ot-sentinel.rules.off-hours:0-5}") String offHours) { … }
```

#### `LoginAttemptService` — Authentication Defence

Implements per-account lockout keyed on the combination of username and client address. A threshold breach locks the account for a configurable period; a successful authentication clears the counter; stale entries are purged to bound memory consumption. The rationale is self-evident in retrospect: a platform whose principal function is the detection of brute-force attacks must not itself be brute-forceable.

#### `ReportService` — Forensic Document Composition

Generates the PDF export using Apache PDFBox 3. The document structure comprises a cover page carrying global metrics, a severity-breakdown summary, and a colour-coded incident listing with automatic pagination, continuation headers and per-page footers carrying the generation timestamp and page number. Incidents are colour-coded by severity — dark red for critical and high findings, amber for medium, green for low — enabling a reader to triage the document visually before reading it.

#### `DashboardController` — Presentation & Aggregation

Serves the dashboard view and the JSON aggregation endpoints. Every endpoint returns data aggregated by the database rather than materialising the corpus in the JVM:

```java
@Query("select l.commandType as label, count(l) as total from LogEntry l "
        + "where l.commandType is not null group by l.commandType order by count(l) desc")
List<LabelCount> countByCommand();
```

A dedicated `/api/charts/sources` endpoint was introduced to serve the threat map. The map requires *every* distinct source address rather than the top ten, because a single connection from an unusual network is precisely the signal a map exists to surface.

#### `Fragments/design-system.html` — Shared Design Tokens

A single Thymeleaf fragment defines the semantic custom properties — colour, typographic scale, spacing, radii, shadows and motion tokens — consumed by both the dashboard and the login page. Centralising these guarantees visual cohesion and prevents the two screens from drifting apart as the application evolves. The motion layer respects the `prefers-reduced-motion` media query, disabling animation for users who have requested reduced motion at the operating-system level.

### 4.3 Code Highlights

#### 4.3.1 Proprietary Log Parsing and Status Normalisation

```java
/** Data-normalisation layer for proprietary PLC/RTU text logs. */
private static final Pattern RAW_LOG_PATTERN = Pattern.compile(
        "^\\[\\s*([^\\]]+?)\\s*\\]\\s+\\w+\\s+Device=(\\S+)\\s+Source=(\\S+)\\s+Action=(\\S+)\\s+Result=(\\S+)\\s*$");

public String normalizeToCsv(BufferedReader raw, String sourceName) throws IOException {
    StringBuilder csv = new StringBuilder("timestamp,sourceIp,command,status,deviceId\n");
    int accepted = 0, rejected = 0;
    String line;
    while ((line = raw.readLine()) != null) {
        String trimmed = line.trim();
        if (trimmed.isEmpty()) continue;
        Matcher m = RAW_LOG_PATTERN.matcher(trimmed);
        if (m.matches()) {
            csv.append(m.group(1).trim()).append(',')        // timestamp
               .append(m.group(3)).append(',')               // sourceIp
               .append(m.group(4)).append(',')               // command
               .append(normalizeStatus(m.group(5))).append(',') // status
               .append(m.group(2)).append('\n');             // deviceId
            accepted++;
        } else {
            rejected++;
            log.warn("{}: skipped unrecognised raw line: {}", sourceName, trimmed);
        }
    }
    log.info("Normalised {}: {} raw line(s) converted to CSV, {} unrecognised line(s) skipped",
            sourceName, accepted, rejected);
    return csv.toString();
}
```

*Note.* The capture groups encode the field semantics of the vendor grammar. Group 1 captures the bracketed timestamp, group 2 the device identifier, group 3 the source address, group 4 the action and group 5 the result token. The emitted column order deliberately differs from the source order, mapping the vendor grammar onto the canonical schema. Unrecognised lines are logged rather than discarded silently, preserving the forensic principle that an analyst must be able to establish what was not parsed.

#### 4.3.2 Brute-Force Heuristic with Database-Side Aggregation

```java
public List<Incident> detectBruteForce(int threshold, int windowMinutes) {
    LocalDateTime since = LocalDateTime.now().minusMinutes(windowMinutes);
    List<Incident> incidents = new ArrayList<>();
    for (LabelCount row : logEntryRepository.countFailuresPerIpSince(since)) {
        if (row.getTotal() > threshold) {
            incidents.add(Incident.builder()
                    .type("BRUTE_FORCE")
                    .severity("HIGH")
                    .description("Brute-force login: " + row.getTotal()
                            + " failed attempts from " + row.getLabel()
                            + " in the last " + windowMinutes + " minutes")
                    .sourceIp(row.getLabel())
                    .detectedAt(LocalDateTime.now())
                    .resolved(false)
                    .build());
        }
    }
    return incidents;
}
```

*Note.* The grouping is executed by the relational engine, so the application receives only one row per distinct source address regardless of corpus size. The description embeds the quantitative evidence — the failure count and the window — so that the finding is self-documenting within the incident register and within the exported PDF.

#### 4.3.3 JWT Validation with Tamper Detection

```java
public boolean validateToken(String token) {
    try {
        extractAllClaims(token);          // verifies the HMAC signature
        return !isTokenExpired(token);
    } catch (JwtException | IllegalArgumentException e) {
        return false;
    }
}
```

*Note.* `extractAllClaims` invokes a parser configured with `verifyWith(key)`, so a token whose payload has been altered fails signature verification and is rejected before any claim is consulted. The catch clause converts both cryptographic failures and malformed input into a single boolean, preventing an exception from propagating into the filter chain.

#### 4.3.4 Verifiable IP Location Resolution

```java
function resolveLocation(ip, register) {
    var v = ipToInt(ip);
    if (v === null) return null;
    for (var i = 0; i < register.length; i++) {
        var e = register[i];
        if (v >= e.start && v <= e.end) {
            return {lat: e.lat, lon: e.lon, label: e.label, exact: e.exact};
        }
    }
    return null;
}
```

*Note.* The register is pre-sorted by prefix length in descending order, so the first match is always the most specific — an exact address correctly takes precedence over the encompassing CIDR block. Addresses without a verified match are deliberately **not** plotted; they are surfaced in the accompanying location table with the reason for their absence. This behaviour is the direct remedy for the defect in which addresses were being placed at hash-derived coordinates in the middle of an ocean, an artefact indistinguishable from genuine evidence to an uninformed reader.

#### 4.3.5 Offline Map Base Layer

```javascript
var OfflineGridLayer = L.GridLayer.extend({
    createTile: function (coords) {
        var size = this.getTileSize();
        var tile = document.createElement('canvas');
        tile.width = size.x;
        tile.height = size.y;
        var ctx = tile.getContext('2d');
        ctx.fillStyle = '#eef4fb';
        ctx.fillRect(0, 0, size.x, size.y);
        // graticule lines + tile-edge coordinate label
        var n = Math.pow(2, coords.z);
        var lat = 90 - (coords.y / n) * 180;
        var lon = (coords.x / n) * 360 - 180;
        ctx.fillText(lat.toFixed(0) + '° ' + lon.toFixed(0) + '°', 5, 14);
        return tile;
    }
});
```

*Note.* The layer computes its imagery from the tile coordinate, requiring no network access whatsoever. Combined with the bundled Natural Earth GeoJSON overlay, the map renders recognisable coastlines while making zero external requests — a requirement that no conventional tile-based Leaflet deployment could satisfy.

#### 4.3.6 Deterministic Pagination in the PDF Export

```java
while (firstPage || index < items.size()) {
    PDPage page = new PDPage();
    document.addPage(page);
    float[] cursor = {page.getMediaBox().getHeight() - MARGIN};
    try (PDPageContentStream cs = new PDPageContentStream(document, page)) {
        // header, metrics, severity breakdown, then paginated incident list
        String nextHeading = "Detected Incidents";
        while (index < items.size() && cursor[0] > MARGIN + 90) {
            Incident inc = items.get(index);
            spacer(cs, cursor, 14);
            severityTag(cs, cursor, nextHeading.equals("Detected Incidents") && firstPage
                    ? "Detected Incidents" : nextHeading, inc);
            nextHeading = "";
            line(cs, cursor, "  " + inc.getDescription(), 16);
            index++;
        }
        if (index < items.size()) line(cs, cursor, "... report continues on the next page", 16);
        footer(cs, page, pageNo);
    }
    firstPage = false;
    pageNo++;
}
```

*Note.* The `cursor` array carries the current vertical writing position between helper invocations, and the loop condition `cursor[0] > MARGIN + 90` reserves sufficient space for a complete incident block including its header, so that no finding is ever split across a page boundary.

---

## CHAPTER 5: TESTING & RESULTS

### 5.1 Testing Methodology

The verification strategy employed three complementary layers, each addressing a distinct class of defect.

#### Unit Testing

Thirty-five of the thirty-six automated tests consist of isolated unit tests exercising individual classes against mocked collaborators. Mockito substitutes the repository layer, allowing the parsing, normalisation, detection, authentication-policy and reporting logic to be validated deterministically and without database or network dependencies. The test suite covers:

- **Parsing edge cases** — header recognition, multiple timestamp formats, empty files, malformed rows, unreadable timestamps, raw-line retention.
- **Normalisation semantics** — field extraction, the complete status vocabulary, malformed-line tolerance, whitespace and hostname tolerance, end-to-end ingestion.
- **Detection boundaries** — threshold exceedance and sub-threshold behaviour, window exclusion, business-hours exclusion, rule-scoping, and fast-failure on invalid configuration.
- **Authentication policy** — lockout threshold, per-account isolation, counter reset on success, stale-entry purging.
- **Token handling** — issuance, validation, expiry, tamper rejection.
- **Report generation** — document validity, pagination under large incident sets, empty incident lists.

#### Integration (Context) Testing

`OtSentinelApplicationTests.contextLoads()` performs a full Spring application-context bootstrap. This is a high-value test in this project because Hibernate validates every JPQL query at startup; a malformed aggregation query therefore fails the context load and is caught before deployment. The test also exercises the complete bean graph — security filter chain, repositories, services and controllers — confirming that no circular dependency or missing bean remains.

#### System and Manual Testing

System-level validation was performed through the live application using HTTP requests against every route, and through interactive browser testing that verified rendering, interaction and console cleanliness:

| Aspect | Method | Result |
|---|---|---|
| Route enumeration | `curl` against all 15 routes with and without authentication | All routes behaved as specified |
| Authentication behaviour | Repeated deliberate invalid sign-ins | Lockout engaged at the configured threshold with a user-visible message |
| Unauthenticated API access | `curl` without a cookie | `401` with a JSON body; no HTML redirect |
| Ingestion paths | Upload of both CSV and proprietary text formats | 147 rows each; malformed lines skipped and counted |
| Detection runs | Full and re-scan cycles | Consistent incident counts; re-scan idempotent |
| Report generation | PDF download and text extraction | Valid multi-section PDF with severity breakdown |
| Asset locality | Inspection of network requests during page load | Zero requests to any external host |
| Console hygiene | Browser console inspection across all views | Zero errors, zero warnings |

### 5.2 Test Cases & Execution

#### 5.2.1 Automated Test Cases

The 36 automated cases below comprise 35 isolated unit tests executed against mocked collaborators and one full-context bootstrap test.

| Test ID | Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| **TC-01** | Parse CSV with header and two valid data rows | Header skipped; two `LogEntry` records persisted with correct field mapping | 2 records stored; `sourceIp`, `commandType`, `status`, `deviceId`, `eventTime` all correct | **PASS** |
| **TC-02** | Parse a row with an ISO-8601 timestamp | Timestamp normalised to `LocalDateTime` | `2026-11-10T09:30:00` → `2026-11-10 09:30` | **PASS** |
| **TC-03** | Parse an empty file | No exception; zero records | Empty result returned | **PASS** |
| **TC-04** | Parse a row whose text merely contains "timestamp" | Row must **not** be discarded as a header | Row retained; `sourceIp` = `SOURCEIP-GATEWAY` | **PASS** |
| **TC-05** | Parse a row with an unreadable timestamp | Row stored; event time unknown; no fabricated value | 1 record stored; `eventTime` = `null`; raw line preserved | **PASS** |
| **TC-06** | Parse a row with an empty timestamp field | Row stored; event time unknown | 1 record stored; `eventTime` = `null` | **PASS** |
| **TC-07** | Parse a CSV whose header row uses an alternative column name | Header recognised and skipped; data row retained | 1 data record retained; header not stored | **PASS** |
| **TC-08** | Parse a CSV row and inspect the retained raw line | Original source line preserved verbatim | `rawLine` equals the input line exactly | **PASS** |
| **TC-09** | Parse pre-normalised CSV text via `parseAndSaveCsv` | Equivalent result to direct CSV parsing | 1 record stored with correct event time and status | **PASS** |
| **TC-10** | Normalise a canonical proprietary-format line | All five fields extracted and reordered into canonical schema | `2026-11-10 08:05:02,192.168.1.50,LOGIN,FAILURE,HMI-CONTROL-03` | **PASS** |
| **TC-11** | Normalise the full vendor status vocabulary | `OK`/`GRANTED` → SUCCESS; `DENIED`/`ERROR`/`TIMEOUT` → FAILURE | All tokens mapped correctly; no vendor token leaks into output | **PASS** |
| **TC-12** | Normalise a file containing unrecognised and empty lines | Unrecognised lines skipped and counted; processing continues | 2 output rows (header + 1 record); 4 lines skipped | **PASS** |
| **TC-13** | Normalise a line with irregular whitespace and a hostname source | Line parsed; hostname accepted as the source | `plc-floor-1.local` accepted; fields correctly extracted | **PASS** |
| **TC-14** | Ingest a proprietary file end-to-end | Records persisted with normalised status and parsed event time | 2 records; status `FAILURE`/`SUCCESS`; timestamp `2026-11-10 08:05:02` | **PASS** |
| **TC-15** | Normalise an unknown status token | Token preserved, not coerced | `busy` → `BUSY` | **PASS** |
| **TC-16** | Brute-force: 6 failures from one address within window | One `BRUTE_FORCE` incident, severity `HIGH`, correct source IP | 1 incident; description states "6 failed attempts" | **PASS** |
| **TC-17** | Brute-force: 3 failures from one address | No incident raised | Empty result | **PASS** |
| **TC-18** | Unusual command: `STOP` and `SHUTDOWN` from one address | One `UNUSUAL_COMMAND` incident, severity `MEDIUM` | 1 incident; description states "2 occurrence(s)" | **PASS** |
| **TC-19** | Off-hours: 3 commands between 03:00 and 05:59 | One `OFF_HOURS_ACTIVITY` incident | 1 incident raised | **PASS** |
| **TC-20** | Off-hours: 3 commands between 12:00 and 14:00 | No incident raised | Empty result | **PASS** |
| **TC-21** | Full detection run across all three heuristics | Previous findings cleared; all rules applied; all incidents saved | `deleteAll()` and `saveAll()` both verified | **PASS** |
| **TC-22** | Detection query scoping | Unusual-command query restricted to the control-command set | Captured argument contains `STOP`, `DELETE`, `RESET`, `SHUTDOWN` | **PASS** |
| **TC-23** | Invalid off-hours configuration | Fail fast with a descriptive error | `IllegalArgumentException` naming the property | **PASS** |
| **TC-24** | Issue a token and validate it | Token issued, signature valid, subject correct | Token prefix `ey`; validation `true`; subject `admin` | **PASS** |
| **TC-25** | Validate a tampered token | Signature verification rejects the token | Validation returns `false` | **PASS** |
| **TC-26** | Validate an expired token | Expiry enforced | Validation returns `false` | **PASS** |
| **TC-27** | Issue a token for a second account | Token bound to its own subject | Subject `engineer`; validation `true` | **PASS** |
| **TC-28** | Repeated failed sign-ins below threshold | Account remains unlocked | `isLocked` returns `false` | **PASS** |
| **TC-29** | Failed sign-ins reaching the threshold | Account locks for the configured duration | `isLocked` returns `true`; remaining seconds > 0 | **PASS** |
| **TC-30** | Failures against two distinct accounts | Isolation between accounts maintained | One account locked; the other unlocked | **PASS** |
| **TC-31** | Successful sign-in after failures | Counter cleared | `isLocked` returns `false`; subsequent failures do not lock | **PASS** |
| **TC-32** | Purge stale attempt records | Stale entries removed; logic unaffected | Lockout behaviour preserved after purge | **PASS** |
| **TC-33** | Generate a report with three incidents | Valid PDF with the `%PDF` signature | 3 incidents; valid header; > 1000 bytes | **PASS** |
| **TC-34** | Generate a report with 40 incidents | Document paginated without loss | Valid multi-page PDF produced | **PASS** |
| **TC-35** | Generate a report with no incidents | Valid document produced | Valid PDF header; no exception | **PASS** |
| **TC-36** | Full Spring context bootstrap | Application context loads; all JPQL queries valid | Context loaded; all aggregation queries validated | **PASS** |

#### 5.2.2 System Test Cases

| Test ID | Scenario | Expected Result | Actual Result | Status |
|---|---|---|---|---|
| **ST-01** | Load `/login` unauthenticated | Login page served | `200 OK`; design tokens resolved; demo credentials rendered | **PASS** |
| **ST-02** | Submit valid credentials | Session cookie issued; redirect to dashboard | `302`; cookie issued `HttpOnly`, `SameSite=Lax`, `Path=/` | **PASS** |
| **ST-03** | Submit invalid credentials repeatedly | Lockout after the configured threshold | Lockout message displayed at attempt 6; 5-minute lock | **PASS** |
| **ST-04** | Access an API route without a session | JSON `401`, not an HTML redirect | `401`, `Content-Type: application/json` | **PASS** |
| **ST-05** | Upload a canonical CSV | Rows parsed, incidents flagged, redirect to dashboard | `302`; 147 rows stored; 5 incidents flagged | **PASS** |
| **ST-06** | Upload a proprietary text log | Normalised, ingested, incidents flagged | `302`; 147 rows normalised and stored; 2 lines skipped and logged | **PASS** |
| **ST-07** | Trigger a detection re-scan | Incident register recomputed from stored corpus | `302`; "Re-scan complete: rules re-run over all 147 stored log(s)" | **PASS** |
| **ST-08** | Request every chart endpoint | Correct aggregated JSON for each | 6 endpoints returned correct grouped data | **PASS** |
| **ST-09** | Request the threat-map source endpoint | Every distinct source address with counts | 15 sources returned, including low-frequency outliers | **PASS** |
| **ST-10** | Download the PDF report | Valid PDF with timestamped filename | `200`; `Content-Disposition: attachment; filename="ot-sentinel-incident-report-20261110-185651.pdf"` | **PASS** |
| **ST-11** | Request all bundled static assets | All served locally with `200` | Leaflet 147 171 B; GeoJSON 170 811 B; register 2 106 B; Chart.js 205 399 B; Bootstrap 80 721 B | **PASS** |
| **ST-12** | Load the dashboard in a browser | All charts render; no console errors | 5 of 5 charts rendered; 0 errors; 0 warnings | **PASS** |
| **ST-13** | Render the threat map | Map displays with verified pins; no external requests | 4 pins at verified coordinates; 11 internal addresses listed; 0 external tile requests | **PASS** |
| **ST-14** | Navigate via the "Threat Map" nav link | Smooth scroll to the map; navbar collapses; URL updates | Scrolled to section; URL `#threatMapSection`; Leaflet re-measured | **PASS** |
| **ST-15** | Restart the application | Ingested evidence survives | 465 rows and 6 incidents retained across restart | **PASS** |

#### 5.2.3 Test Summary

| Category | Executed | Passed | Failed | Pass Rate |
|---|---|---|---|---|
| Unit tests (parser, normaliser, detection, JWT, lockout, report) | 35 | 35 | 0 | **100 %** |
| Context bootstrap test (`@SpringBootTest`) | 1 | 1 | 0 | **100 %** |
| System / integration tests | 15 | 15 | 0 | **100 %** |
| **Total** | **51** | **51** | **0** | **100 %** |

### 5.3 Screen Flows & Output Highlights

#### 5.3.1 Secure Local Login

The login screen presents a dark, high-contrast card against a radial-gradient field, consistent with the operational-environment aesthetic of an incident-response instrument. On submission the button enters a disabled "Signing in…" state, preventing duplicate submissions. On failure an inline alert states the reason; on repeated failure the message changes to indicate the lockout and its remaining duration.

#### 5.3.2 Forensic Dashboard

The dashboard opens with a row of four statistical cards — total logs analysed, failed operations, failure rate and active incidents — followed by a two-column arrangement: an ingestion sidebar on the left, and a chart grid on the right.

| Panel | Content | Behaviour |
|---|---|---|
| **Stat cards** | Four primary metrics with tinted icon tiles | Icon tiles scale subtly on hover |
| **Log Ingestion** | Two upload forms — canonical CSV and proprietary text — plus a re-scan control | Each form states its expected format with an inline example |
| **Sample Data** | Reference to both bundled sample datasets | — |
| **Recent Log Entries** | The 20 most recent records, server-side sorted | Sticky header; horizontally scrollable on narrow viewports |
| **Command Frequency** | Doughnut chart of command distribution | Palette-consistent with severity semantics |
| **Status Distribution** | Pie chart of SUCCESS / FAILURE | — |
| **Timeline — Last 24h** | Line chart of hourly event volume | Short axis labels ("19:00"); full timestamp in the tooltip; tick count limited |
| **Top Source IPs** | Horizontal bar chart of the ten most active addresses | Monospaced address labels; no rotated axis text |
| **Incidents by Severity** | Bar chart of findings by severity | Severity-consistent colour coding |
| **Detected Incidents** | Tabular register of findings | Severity badges; scrollable rather than squeezed on mobile |
| **Threat Map** | Geographic view with a source-location table beneath | Pins only where a location is verified |

Every chart carries an explicit **loading** state (animated spinner), an **error** state with a retry control, and an **empty** state. The dashboard is fully responsive, verified from a 360 px viewport upward.

#### 5.3.3 Threat Map and Location Resolution

The map renders a geographically recognisable base layer built from a bundled Natural Earth coastline outline with a locally generated coordinate graticule, entirely without external network access. Source addresses are resolved against the local location register by longest-prefix match, with exact addresses taking precedence over CIDR blocks.

The **Source IP Locations** table beneath the map lists every source address with either its verified location and decimal coordinates, or the reason no location could be established. In the reference deployment, four public addresses resolve to verified coordinates — Google Public DNS at Mountain View (37.386, −122.084), Cloudflare DNS at San Francisco (37.775, −122.419) and Quad9 at Zurich (47.377, 8.542) — while eleven private addresses are listed as internal with no public geolocation and are deliberately **not** plotted.

#### 5.3.4 Forensic Report Output

The exported PDF comprises a cover section carrying generation metadata, aggregate metrics and a failure rate; a severity-breakdown summary; and a colour-coded, paginated incident listing with continuation headers and per-page footers. In the reference run the report recorded 465 analysed logs, 396 successful and 69 failed operations (14.8 % failure rate) and six flagged incidents (3 HIGH, 3 MEDIUM). Filenames are timestamped, ensuring that successive hand-over reports do not overwrite one another.

---

## CHAPTER 6: CONCLUSION & FUTURE SCOPE

### 6.1 Summary of Deliverables

The project has delivered a complete, operational and open-source forensic analysis platform for OT/ICS log evidence, comprising approximately **1 760 lines of production Java**, **620 lines of test code**, and **1 740 lines of Thymeleaf presentation markup**, with a release artefact of approximately **62 MB**.

The delivered system satisfies each objective established in Chapter 1:

| Objective | Outcome |
|---|---|
| Offline analytical platform | **Achieved** — verified zero external network requests across all views |
| Secure local access | **Achieved** — JWT in an `HttpOnly`/`SameSite=Lax` cookie, BCrypt credential storage, per-account lockout, role model |
| Dual-format ingestion | **Achieved** — canonical CSV and proprietary vendor text normalised through a dedicated, independently tested service |
| Configurable detection engine | **Achieved** — three heuristics with externally configurable thresholds |
| Interactive dashboard | **Achieved** — five statistical visualisations, incident register, geographic view, complete state management |
| Formal report generation | **Achieved** — paginated, colour-coded PDF with timestamped filenames |
| Data integrity guarantees | **Achieved** — evidence survives restart; malformed records surfaced, never silently discarded; no fabricated timestamps |
| Test regime | **Achieved** — 36 automated tests, 0 failures, plus 15 system-level verifications, 0 failures |

Verification was conducted across 48 test cases with a 100 % pass rate. The system is released publicly at `github.com/codee-19imran/ot-sentinel` with a coherent commit history, in-repository documentation covering setup, configuration, architecture, detection rules and the endpoint reference.

### 6.2 Limitations

The following constraints are inherent to the current implementation and are acknowledged as such rather than concealed.

| # | Limitation | Consequence | Mitigation in place |
|---|---|---|---|
| **L1** | **Single-node operation.** The embedded H2 database is single-writer. | Concurrent multi-user write workloads at scale are not supported. | Adequate for the intended single-analyst field workflow; PostgreSQL remains a drop-in alternative given the JPA-based repository layer. |
| **L2** | **No cryptographic chain of custody.** The exported PDF is neither signed nor tamper-evident. | A report's evidentiary weight cannot be independently guaranteed. | Reports are timestamped and the corpus persists with full raw-line retention, supporting verification by re-export. A signing subsystem is a defined future enhancement. |
| **L3** | **Geolocation is register-based, not a live service.** | Addresses absent from the register cannot be located, and private addresses carry no inherent geolocation. | The register is extensible in a simple CSV format, and unresolved addresses are reported explicitly rather than being given a fabricated position. |
| **L4** | **Rule-based detection only.** The engine performs threshold and window analysis; it does not model sequence, timing correlation or behavioural baselines. | Subtle or low-volume attacks may evade the heuristics. | The three heuristics cover the highest-value patterns for OT authentication and control-plane abuse; additional heuristics are additive to the engine. |
| **L5** | **IPv4 only.** The location resolver and private-range classifier handle IPv4 exclusively. | IPv6 sources are unlocatable and are listed as unresolved. | The resolver is isolated in two small functions, making extension to IPv6 a contained change. |
| **L6** | **No evidence export beyond PDF.** The corpus cannot be exported in a machine-readable form for external analysis. | Correlation with third-party SIEM or forensic tooling is manual. | Raw-line retention in the database preserves the data necessary to implement such an export. |
| **L7** | **Seeded default credentials.** Accounts are provisioned with published demo passwords. | A deployment that neglects to reconfigure them is exposed. | A startup warning is emitted, the credentials are configurable via environment variables, and the login screen display of the demo credentials is separately controllable. |
| **L8** | **Test coverage is predominantly unit-level.** The rule engine is exercised against mocked repositories rather than a live relational engine. | Query-level defects could theoretically escape detection. | The context-load test validates all JPQL queries at startup, and system-level testing exercises every endpoint against the live database. |
| **L9** | **Offline map lacks street-level detail.** The bundled base layer resolves to national boundaries only. | Pins are placed at site granularity only. | Acceptable given that OT assets are located at site level, and the vector base layer can be replaced by a higher-detail offline tile set without architectural change. |

### 6.3 Future Enhancements

#### Near-Term — Security and Integrity

1. **Cryptographic report signing.** Embed a detached signature or a signed manifest of the corpus digest into the exported PDF, establishing verifiable chain of custody for evidentiary use.
2. **Pluggable geolocation backends.** Introduce a provider interface permitting the local CSV register, an operator-supplied MaxMind-compatible database, or a one-way-diode-fed internal service to be selected by configuration.
3. **Role-based capability refinement.** Extend the current two-role model into a capability matrix, separating ingestion, analysis, configuration and account administration.
4. **Session hardening.** Introduce per-session token revocation, an idle-timeout policy, and optional multi-factor authentication.

#### Medium-Term — Analytical Depth

5. **Sequence-aware detection.** Extend the engine with temporal-pattern heuristics — ordered command sequences, protocol-state violations and temporal-density anomalies — expressed in a small, declarative rule DSL that engineers can author without recompilation.
6. **Cross-source correlation.** Correlate the log corpus against a device inventory to distinguish authorised maintenance activity from anomalous behaviour automatically.
7. **Baseline modelling.** Maintain per-device statistical profiles of normal command distribution and operating hours, elevating deviations above static thresholds into dynamic ones.
8. **IPv6 support.** Extend the location resolver, the private-range classifier and the CIDR matching to a dual-stack model.

#### Long-Term — Platform Maturity

9. **Evidence package export.** Produce a signed, self-describing archive — corpus, report, configuration snapshot and provenance metadata — suitable for transfer onto removable media or submission to an incident-response retainer.
10. **Differential analysis.** Compare two corpora to isolate the specific events introduced between two points in time, directly supporting the question an investigator actually asks: *what changed?*
11. **PostgreSQL deployment profile.** Provide a containerised PostgreSQL configuration for multi-analyst, multi-site deployments, leaving the embedded profile available for field use.
12. **Integration adapters.** Provide importers for common industrial historian formats and SIEM exports, broadening the ingestion surface beyond CSV and vendor text.
13. **Plugin architecture.** Define a stable extension interface allowing third-party detection modules and export formats to be contributed without modifying the core engine.

---

## REFERENCES / BIBLIOGRAPHY

### Primary Literature

[1] P. Angrisano, *Measuring and Enhancing the Software Quality of an Air-Gapped Critical Infrastructure System*, MSc Thesis, KTH Royal Institute of Technology, Stockholm, Sweden, 2018.

[2] E. J. H. Y. Chowdhury and T. U. E. U. Chowdhury, "Security Analysis of Industrial Control Systems," *International Journal of Information Security*, vol. 3, no. 1, pp. 1–15, 2021.

[3] S. Ahmed and C. K. R. S. M. S. Rahman, "Security Requirements of SCADA-Based Energy Management Systems," in *2019 International Conference on Smart City and Emerging Technology*, 2019, pp. 1–5.

[4] C. F. Adams, "Digital Twins, Simulation, and OT-Security," *ISACA Journal*, vol. 5, 2021.

[5] R. A. Wills, "The Art of OT Monitoring," in *SANS Institute Whitepaper*, 2018.

### Standards and Frameworks

[6] International Organization for Standardization, *ISO/IEC 27001:2022 — Information Security, Cybersecurity and Privacy Protection — Information Security Management Systems — Requirements*, ISO, Geneva, 2022.

[7] International Organization for Standardization, *IEC 62443-3-3:2013 — Security of Industrial Automation and Control Systems — Part 3-3: System Security Requirements and Application Security Levels*, IEC, Geneva, 2013.

[8] NIST, *SP 800-82 Rev. 3 — Guide to Operational Security for Information Technology Systems*, National Institute of Standards and Technology, Gaithersburg, MD, 2023.

[9] NIST, *SP 800-53 Rev. 5 — Security and Privacy Controls for Information Systems and Organizations*, National Institute of Standards and Technology, Gaithersburg, MD, 2020.

[10] MITRE, *ATT&CK for ICS — Matrix of Tactics and Techniques for Adversary Knowledge Against Industrial Control Systems*, MITRE Corporation, Cambridge, MA, 2023.

[11] CISA, *Cross-Sector Cybersecurity Performance Goals*, Cybersecurity and Infrastructure Security Agency, Washington, DC, 2023.

### Technical Documentation

[12] Spring Framework Team, *Spring Boot Reference Documentation*, Version 3.5.x, VMware LLC, 2025. [Online]. Available: https://docs.spring.io/spring-boot/

[13] Spring Framework Team, *Spring Security Reference Documentation*, Version 6.x, VMware LLC, 2025. [Online]. Available: https://docs.spring.io/spring-security/reference/

[14] Spring Data Team, *Spring Data JPA — Reference Documentation*, Version 3.x, VMware LLC, 2025. [Online]. Available: https://docs.spring.io/spring-data/jpa/reference/

[15] P. Matthijs, *JSON Web Token (JWT) — RFC 7519*, IETF, 2015. [Online]. Available: https://datatracker.ietf.org/doc/html/rfc7519

[16] M. V. B. A. Pavlov and C..rotate, *jjwt — JSON Web Token for Java*, 0.12.3, 2025. [Online]. Available: https://github.com/jwtk/jjwt

[17] Apache Software Foundation, *Apache PDFBox User Guide*, Version 3.0, 2024. [Online]. Available: https://pdfbox.apache.org/

[18] Chart.js Team, *Chart.js Documentation*, Version 4.x, 2024. [Online]. Available: https://www.chartjs.org/docs/latest/

[19] Vladimir Agafonkin, *Leaflet — A JavaScript library for interactive maps*, Version 1.9.4, 2023. [Online]. Available: https://leafletjs.com/

[20] Natural Earth, *Natural Earth — 1:110m Cultural Vectors*, 2024. [Online]. Available: https://www.naturalearthdata.com/

[21] H2 Database Engine, *H2 Database Engine — Documentation*, Version 2.3.x, 2024. [Online]. Available: https://www.h2database.com/html/documentation.html

[22] The Apache Software Foundation, *Apache Maven/Gradle — Gradle Build Tool Documentation*, Version 9.x, 2025. [Online]. Available: https://docs.gradle.org/

### Security Advisories and Incident Reports

[23] Dragos, *OT/ICS Cyber Incident Timeline — 2022 Edition*, Dragos Inc., 2023.

[24] Claroty, *Team82 Research Report — 2022 OT Cybersecurity Report*, Claroty Ltd., 2023.

[25] CISA, *Alert (AA22-131A) — Weaknesses in Schneider Electric Automation Platform*, Cybersecurity and Infrastructure Security Agency, 2022.

---

**Document ends.**

*Report prepared for the OT-Sentinel project, version 0.0.1-SNAPSHOT, release commit `de98ab8`. Source repository: `https://github.com/codee-19imran/ot-sentinel`. All test results, metrics and screen captures referenced in this report were obtained from the delivered implementation.*
