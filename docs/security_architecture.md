# Security Architecture & STIG Control Mapping

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    APPLICATION LAYER                     │
│              (Web App / Reporting Tools)                 │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │    ROLE BOUNDARY      │
         │  dod_app_role         │  ← Application writes
         │  dod_report_role      │  ← Read-only reporting
         │  dod_audit_role       │  ← Audit review only
         └───────────┬───────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                  DATABASE LAYER                          │
│   ┌──────────────┐    ┌──────────────┐                  │
│   │  app schema  │    │ audit schema │                  │
│   │  Personnel   │───▶│  AccessLog   │                  │
│   │  Encounters  │    │  (immutable) │                  │
│   └──────────────┘    └──────────────┘                  │
└─────────────────────────────────────────────────────────┘
```

## STIG Control Mapping

### Access Control
- **AC-2 Account Management**: All users created with `PASSWORD EXPIRE` forcing immediate change; no default passwords in production
- **AC-6 Least Privilege**: Object-level grants only to roles; no direct user grants; roles scoped to minimum required access
- **AC-17 Remote Access**: Host/IP captured in every audit log entry for session accountability

### Audit & Accountability
- **AU-2 Audit Events**: INSERT, UPDATE, DELETE on all sensitive tables; compliance report generation itself is logged
- **AU-3 Content of Audit Records**: Timestamp, user, host, IP, action type, table, row ID, before/after values captured
- **AU-9 Protection of Audit Info**: Audit table in separate tablespace/schema; app role has INSERT only (no UPDATE/DELETE on audit)
- **AU-12 Audit Generation**: Autonomous transaction triggers ensure audit writes succeed or block the transaction

### Identification & Authentication
- **IA-5 Authenticator Management**: Password policy function enforces 15-char min, upper/lower/number/special per STIG V-270426
- **IA-8 Non-Org User ID**: EDIPI (DoD ID number) used as unique identifier across all personnel records

### Data Integrity
- **SI-10 Information Input Validation**: CHECK constraints on branch, clearance level, status, encounter type on all core tables
- **SI-12 Information Handling**: No physical DELETE permitted on personnel (trigger enforces retention policy)

## Performance Tuning Decisions

| Query Pattern | Index Created | Rationale |
|---|---|---|
| Lookup by EDIPI | `idx_personnel_edipi` | Primary lookup key; equality seek |
| Branch/status filter | `idx_personnel_branch` | Common reporting filter combination |
| Encounter date range | `idx_encounter_date` | Date range + facility = most common analytics query |
| Audit log review | `idx_access_log_ts` | DESC order; most recent events reviewed first |

## High-Availability Considerations
- Auto-extend on all datafiles prevents out-of-space failures during high-volume periods
- Audit log uses autonomous transactions to decouple from main transaction; audit write failures surface as hard errors (never silently ignored)
- Views pre-join complex multi-table queries; reporting tools never write raw SQL against base tables
