# RDBMS Implementation & Security Lab (DoD Focus)

**Independent Project Portfolio | January 2026 – Present**  
**Tools:** Oracle 19c, MS SQL Server 2022, PL/SQL, T-SQL

---

## Overview

This lab simulates the design, implementation, and security hardening of a relational database environment aligned with **Department of Defense (DoD) IT standards**, specifically targeting the **Defense Health Agency (DHA)** operational context. All data is simulated and does not represent real personnel or medical records.

The project demonstrates hands-on capability across the full database lifecycle: schema design, security implementation, PL/SQL/T-SQL development, audit logging, and compliance validation.

---

## Project Structure

```
rdbms-security-lab/
├── oracle/
│   ├── 01_schema_setup.sql          # Tablespaces, users, roles, tables, indexes
│   └── 02_security_procedures.sql   # PL/SQL package, triggers, optimized views
├── sqlserver/
│   ├── 01_sqlserver_schema.sql      # Database, schemas, tables, indexes, stored procs
│   └── 02_compliance_testing.sql    # Validation & compliance test suite
└── docs/
    ├── security_architecture.md     # STIG control mapping & architecture notes
    └── performance_tuning_log.md    # Query optimization decisions
```

---

## Key Capabilities Demonstrated

### Security Architecture (DoD STIG Aligned)
- **Least-privilege role model** — three-tier role separation: `app`, `reporting`, and `audit` roles with scoped object-level grants
- **Mandatory audit logging** — autonomous transaction triggers capture all DML on sensitive tables (personnel, healthcare encounters) with before/after values, session user, hostname, and IP
- **Data retention enforcement** — triggers block physical DELETE operations; status flags enforce DoD data retention policy
- **Password policy validation** — PL/SQL function enforces 15-character minimum, complexity requirements per STIG V-270426
- **Schema isolation** — separate tablespaces (Oracle) and schemas (SQL Server) for application data vs. audit data

### PL/SQL Development (Oracle)
- `dod_security_pkg` — centralized security package with autonomous transaction audit writes, clearance validation, compliance reporting, and password policy enforcement
- `vw_branch_readiness` — optimized reporting view joining personnel and encounter data with YTD windowing
- Row-level audit triggers on all sensitive tables

### T-SQL Development (SQL Server)
- `usp_UpsertPersonnel` — transactional upsert with integrated audit logging and full error handling/rollback
- `usp_ComplianceReport` — audit summary procedure with after-hours access detection
- `report.BranchReadiness` — cross-table reporting view with aggregate readiness metrics

### Compliance Testing
- Automated validation scripts verify: schema separation, dangerous login detection, TRUSTWORTHY setting, trigger functionality, role permissions, and index utilization
- Designed to be run as part of a deployment checklist before production release

---

## DoD Standards Referenced

| Standard | Area | Implementation |
|---|---|---|
| DISA Oracle STIG | Audit logging | Autonomous transaction audit triggers |
| DISA SQL Server STIG | DB hardening | TRUSTWORTHY OFF, schema isolation |
| STIG V-270426 | Password policy | 15-char min, complexity enforcement |
| DoD 8570 IA Controls | Least privilege | Three-tier role model |
| HIPAA / DHA Policy | Data retention | No-delete policy via trigger enforcement |

---

## How to Run

### Oracle (Oracle Live SQL or local 19c+)
```sql
-- Run in order:
@oracle/01_schema_setup.sql
@oracle/02_security_procedures.sql
```

### SQL Server (SQL Server Express or Azure SQL free tier)
```sql
-- Run in order:
-- 01_sqlserver_schema.sql
-- 02_compliance_testing.sql
```

---

## Skills Highlighted

`Oracle 19c` `MS SQL Server 2022` `PL/SQL` `T-SQL` `DISA STIG` `Database Security` `Audit Logging` `Role-Based Access Control` `Stored Procedures` `Query Optimization` `DoD IT` `DHA` `High Availability Design`
