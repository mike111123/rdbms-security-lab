-- ============================================================
-- RDBMS Security Lab: Oracle Schema Setup
-- DoD IT / DHA Compliance Focus
-- Author: Independent Project Portfolio
-- Date: January 2026
-- ============================================================

-- Create tablespaces for data separation (security best practice)
CREATE TABLESPACE dod_data
    DATAFILE 'dod_data01.dbf' SIZE 100M AUTOEXTEND ON NEXT 10M MAXSIZE 500M
    EXTENT MANAGEMENT LOCAL SEGMENT SPACE MANAGEMENT AUTO;

CREATE TABLESPACE dod_audit
    DATAFILE 'dod_audit01.dbf' SIZE 50M AUTOEXTEND ON NEXT 5M MAXSIZE 200M
    EXTENT MANAGEMENT LOCAL SEGMENT SPACE MANAGEMENT AUTO;

-- ============================================================
-- USERS & ROLES (Least Privilege / DoD IA Controls)
-- ============================================================

-- Application role (read/write to app tables only)
CREATE ROLE dod_app_role;
-- Read-only reporting role
CREATE ROLE dod_report_role;
-- DBA audit role
CREATE ROLE dod_audit_role;

-- Application schema owner
CREATE USER dod_app_owner IDENTIFIED BY "Ch@ngeMe_Vault!"
    DEFAULT TABLESPACE dod_data
    TEMPORARY TABLESPACE temp
    QUOTA UNLIMITED ON dod_data
    PASSWORD EXPIRE;

-- Reporting user (read-only)
CREATE USER dod_reporter IDENTIFIED BY "Ch@ngeMe_Vault!"
    DEFAULT TABLESPACE dod_data
    TEMPORARY TABLESPACE temp
    QUOTA 0 ON dod_data
    PASSWORD EXPIRE;

-- Audit user
CREATE USER dod_auditor IDENTIFIED BY "Ch@ngeMe_Vault!"
    DEFAULT TABLESPACE dod_audit
    TEMPORARY TABLESPACE temp
    QUOTA UNLIMITED ON dod_audit
    PASSWORD EXPIRE;

-- Grant minimal privileges per STIG requirements
GRANT CREATE SESSION TO dod_app_owner;
GRANT CREATE SESSION TO dod_reporter;
GRANT CREATE SESSION TO dod_auditor;
GRANT dod_app_role TO dod_app_owner;
GRANT dod_report_role TO dod_reporter;
GRANT dod_audit_role TO dod_auditor;

-- ============================================================
-- CORE TABLES
-- ============================================================

-- Personnel registry (simulated DoD personnel)
CREATE TABLE dod_app_owner.personnel (
    personnel_id     NUMBER(10)    GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    edipi            CHAR(10)      NOT NULL UNIQUE,           -- DoD ID
    last_name        VARCHAR2(50)  NOT NULL,
    first_name       VARCHAR2(50)  NOT NULL,
    rank_grade       VARCHAR2(10),
    branch           VARCHAR2(20)  CHECK (branch IN ('ARMY','NAVY','USAF','USMC','USCG','SPACE','CIVILIAN')),
    unit_code        VARCHAR2(20),
    clearance_level  VARCHAR2(20)  CHECK (clearance_level IN ('UNCLASSIFIED','CUI','SECRET','TOP SECRET','TS/SCI')),
    status           VARCHAR2(10)  DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','INACTIVE','SEPARATED')),
    created_by       VARCHAR2(50)  DEFAULT SYS_CONTEXT('USERENV','SESSION_USER'),
    created_date     TIMESTAMP     DEFAULT SYSTIMESTAMP,
    modified_date    TIMESTAMP
) TABLESPACE dod_data;

-- Healthcare encounters
CREATE TABLE dod_app_owner.healthcare_encounters (
    encounter_id     NUMBER(12)    GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    personnel_id     NUMBER(10)    NOT NULL REFERENCES dod_app_owner.personnel(personnel_id),
    encounter_date   DATE          NOT NULL,
    facility_code    VARCHAR2(20)  NOT NULL,
    encounter_type   VARCHAR2(30)  CHECK (encounter_type IN ('ROUTINE','URGENT','EMERGENCY','DENTAL','BEHAVIORAL','PREVENTIVE')),
    diagnosis_code   VARCHAR2(10),                            -- ICD-10
    provider_id      NUMBER(10),
    disposition      VARCHAR2(30),
    classification   VARCHAR2(20)  DEFAULT 'UNCLASSIFIED',
    created_date     TIMESTAMP     DEFAULT SYSTIMESTAMP
) TABLESPACE dod_data;

-- System access log (audit trail)
CREATE TABLE dod_app_owner.access_log (
    log_id           NUMBER(15)    GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_timestamp    TIMESTAMP     DEFAULT SYSTIMESTAMP NOT NULL,
    db_user          VARCHAR2(50)  DEFAULT SYS_CONTEXT('USERENV','SESSION_USER'),
    os_user          VARCHAR2(50)  DEFAULT SYS_CONTEXT('USERENV','OS_USER'),
    host_name        VARCHAR2(100) DEFAULT SYS_CONTEXT('USERENV','HOST'),
    ip_address       VARCHAR2(45)  DEFAULT SYS_CONTEXT('USERENV','IP_ADDRESS'),
    action_type      VARCHAR2(20)  NOT NULL,
    table_affected   VARCHAR2(50),
    row_id_affected  NUMBER,
    old_value        CLOB,
    new_value        CLOB,
    session_id       NUMBER        DEFAULT SYS_CONTEXT('USERENV','SESSIONID')
) TABLESPACE dod_audit;

-- ============================================================
-- INDEXES
-- ============================================================
CREATE INDEX idx_personnel_edipi    ON dod_app_owner.personnel(edipi);
CREATE INDEX idx_personnel_branch   ON dod_app_owner.personnel(branch, status);
CREATE INDEX idx_encounter_date     ON dod_app_owner.healthcare_encounters(encounter_date, facility_code);
CREATE INDEX idx_encounter_person   ON dod_app_owner.healthcare_encounters(personnel_id);
CREATE INDEX idx_access_log_ts      ON dod_app_owner.access_log(log_timestamp);
CREATE INDEX idx_access_log_user    ON dod_app_owner.access_log(db_user);

-- ============================================================
-- GRANTS TO ROLES
-- ============================================================
GRANT SELECT, INSERT, UPDATE ON dod_app_owner.personnel          TO dod_app_role;
GRANT SELECT, INSERT, UPDATE ON dod_app_owner.healthcare_encounters TO dod_app_role;
GRANT INSERT                 ON dod_app_owner.access_log          TO dod_app_role;

GRANT SELECT ON dod_app_owner.personnel              TO dod_report_role;
GRANT SELECT ON dod_app_owner.healthcare_encounters  TO dod_report_role;

GRANT SELECT ON dod_app_owner.access_log             TO dod_audit_role;

COMMIT;
