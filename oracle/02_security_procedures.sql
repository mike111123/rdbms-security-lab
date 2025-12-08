-- ============================================================
-- RDBMS Security Lab: PL/SQL Security Procedures & Triggers
-- DoD STIG / IAVM Compliance Implementation
-- Author: Independent Project Portfolio
-- Date: January 2026
-- ============================================================

-- ============================================================
-- PACKAGE: dod_security_pkg
-- Centralizes all security enforcement logic
-- ============================================================

CREATE OR REPLACE PACKAGE dod_app_owner.dod_security_pkg AS

    -- Log any DML action to the audit trail
    PROCEDURE log_action(
        p_action_type    IN VARCHAR2,
        p_table_affected IN VARCHAR2,
        p_row_id         IN NUMBER    DEFAULT NULL,
        p_old_value      IN CLOB      DEFAULT NULL,
        p_new_value      IN CLOB      DEFAULT NULL
    );

    -- Validate clearance level before data access
    FUNCTION validate_clearance(
        p_personnel_id   IN NUMBER,
        p_required_level IN VARCHAR2
    ) RETURN BOOLEAN;

    -- Check if current DB session user is authorized for sensitive ops
    FUNCTION is_authorized_user(
        p_required_role IN VARCHAR2
    ) RETURN BOOLEAN;

    -- Generate compliance report summary
    PROCEDURE generate_compliance_report(
        p_start_date IN DATE,
        p_end_date   IN DATE
    );

    -- Enforce password policy check (manual call for app-layer integration)
    FUNCTION check_password_policy(
        p_password IN VARCHAR2
    ) RETURN VARCHAR2;  -- Returns 'PASS' or failure reason

END dod_security_pkg;
/

CREATE OR REPLACE PACKAGE BODY dod_app_owner.dod_security_pkg AS

    -- ----------------------------------------------------------
    PROCEDURE log_action(
        p_action_type    IN VARCHAR2,
        p_table_affected IN VARCHAR2,
        p_row_id         IN NUMBER    DEFAULT NULL,
        p_old_value      IN CLOB      DEFAULT NULL,
        p_new_value      IN CLOB      DEFAULT NULL
    ) AS
        PRAGMA AUTONOMOUS_TRANSACTION;  -- Write audit log independent of main txn
    BEGIN
        INSERT INTO dod_app_owner.access_log (
            action_type, table_affected, row_id_affected,
            old_value, new_value
        ) VALUES (
            p_action_type, p_table_affected, p_row_id,
            p_old_value, p_new_value
        );
        COMMIT;
    EXCEPTION
        WHEN OTHERS THEN
            -- Audit log failures must never silently swallow errors
            RAISE_APPLICATION_ERROR(-20001,
                'CRITICAL: Audit log write failed. Action blocked. ' || SQLERRM);
    END log_action;

    -- ----------------------------------------------------------
    FUNCTION validate_clearance(
        p_personnel_id   IN NUMBER,
        p_required_level IN VARCHAR2
    ) RETURN BOOLEAN AS
        v_clearance  VARCHAR2(20);
        v_level_num  NUMBER;
        v_req_num    NUMBER;

        -- Map clearance strings to numeric levels for comparison
        FUNCTION clearance_to_num(p_lvl IN VARCHAR2) RETURN NUMBER AS
        BEGIN
            RETURN CASE p_lvl
                WHEN 'UNCLASSIFIED' THEN 1
                WHEN 'CUI'          THEN 2
                WHEN 'SECRET'       THEN 3
                WHEN 'TOP SECRET'   THEN 4
                WHEN 'TS/SCI'       THEN 5
                ELSE 0
            END;
        END;
    BEGIN
        SELECT clearance_level INTO v_clearance
        FROM   dod_app_owner.personnel
        WHERE  personnel_id = p_personnel_id
          AND  status = 'ACTIVE';

        v_level_num := clearance_to_num(v_clearance);
        v_req_num   := clearance_to_num(p_required_level);

        RETURN v_level_num >= v_req_num;

    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            log_action('CLEARANCE_CHECK_FAIL', 'PERSONNEL', p_personnel_id,
                       NULL, 'Personnel not found or inactive');
            RETURN FALSE;
    END validate_clearance;

    -- ----------------------------------------------------------
    FUNCTION is_authorized_user(
        p_required_role IN VARCHAR2
    ) RETURN BOOLEAN AS
        v_count NUMBER;
    BEGIN
        SELECT COUNT(*) INTO v_count
        FROM   session_privs
        WHERE  UPPER(privilege) = UPPER(p_required_role);

        RETURN v_count > 0;
    END is_authorized_user;

    -- ----------------------------------------------------------
    PROCEDURE generate_compliance_report(
        p_start_date IN DATE,
        p_end_date   IN DATE
    ) AS
        v_total_sessions    NUMBER;
        v_failed_logins     NUMBER;
        v_after_hours       NUMBER;
        v_sensitive_access  NUMBER;
    BEGIN
        -- Total distinct sessions in window
        SELECT COUNT(DISTINCT session_id)
        INTO   v_total_sessions
        FROM   dod_app_owner.access_log
        WHERE  log_timestamp BETWEEN p_start_date AND p_end_date;

        -- After-hours access (outside 0600-1800 local)
        SELECT COUNT(*)
        INTO   v_after_hours
        FROM   dod_app_owner.access_log
        WHERE  log_timestamp BETWEEN p_start_date AND p_end_date
          AND  (TO_NUMBER(TO_CHAR(log_timestamp, 'HH24')) < 6
             OR TO_NUMBER(TO_CHAR(log_timestamp, 'HH24')) >= 18);

        -- Access to sensitive tables
        SELECT COUNT(*)
        INTO   v_sensitive_access
        FROM   dod_app_owner.access_log
        WHERE  log_timestamp BETWEEN p_start_date AND p_end_date
          AND  table_affected IN ('PERSONNEL','HEALTHCARE_ENCOUNTERS')
          AND  action_type IN ('SELECT','UPDATE','DELETE');

        DBMS_OUTPUT.PUT_LINE('=== DoD RDBMS COMPLIANCE REPORT ===');
        DBMS_OUTPUT.PUT_LINE('Period: ' || TO_CHAR(p_start_date,'YYYY-MM-DD')
                             || ' to ' || TO_CHAR(p_end_date,'YYYY-MM-DD'));
        DBMS_OUTPUT.PUT_LINE('-----------------------------------');
        DBMS_OUTPUT.PUT_LINE('Total Sessions:          ' || v_total_sessions);
        DBMS_OUTPUT.PUT_LINE('After-Hours Access:      ' || v_after_hours);
        DBMS_OUTPUT.PUT_LINE('Sensitive Table Access:  ' || v_sensitive_access);
        DBMS_OUTPUT.PUT_LINE('===================================');

        -- Log the report generation itself
        log_action('COMPLIANCE_REPORT', 'ACCESS_LOG', NULL, NULL,
            'Report generated for ' || TO_CHAR(p_start_date,'YYYY-MM-DD')
            || ' to ' || TO_CHAR(p_end_date,'YYYY-MM-DD'));
    END generate_compliance_report;

    -- ----------------------------------------------------------
    FUNCTION check_password_policy(
        p_password IN VARCHAR2
    ) RETURN VARCHAR2 AS
    BEGIN
        IF LENGTH(p_password) < 15 THEN
            RETURN 'FAIL: Minimum 15 characters required (DoD STIG V-270426)';
        END IF;
        IF NOT REGEXP_LIKE(p_password, '[A-Z]') THEN
            RETURN 'FAIL: Must contain at least one uppercase letter';
        END IF;
        IF NOT REGEXP_LIKE(p_password, '[a-z]') THEN
            RETURN 'FAIL: Must contain at least one lowercase letter';
        END IF;
        IF NOT REGEXP_LIKE(p_password, '[0-9]') THEN
            RETURN 'FAIL: Must contain at least one number';
        END IF;
        IF NOT REGEXP_LIKE(p_password, '[^A-Za-z0-9]') THEN
            RETURN 'FAIL: Must contain at least one special character';
        END IF;
        RETURN 'PASS';
    END check_password_policy;

END dod_security_pkg;
/

-- ============================================================
-- TRIGGERS: Enforce audit logging on sensitive tables
-- ============================================================

-- Audit trigger on personnel table
CREATE OR REPLACE TRIGGER dod_app_owner.trg_personnel_audit
    AFTER INSERT OR UPDATE OR DELETE
    ON dod_app_owner.personnel
    FOR EACH ROW
DECLARE
    v_action VARCHAR2(10);
    v_old    CLOB;
    v_new    CLOB;
BEGIN
    v_action := CASE
        WHEN INSERTING THEN 'INSERT'
        WHEN UPDATING  THEN 'UPDATE'
        WHEN DELETING  THEN 'DELETE'
    END;

    IF UPDATING OR DELETING THEN
        v_old := 'EDIPI=' || :OLD.edipi
              || ', NAME=' || :OLD.last_name || ',' || :OLD.first_name
              || ', CLEARANCE=' || :OLD.clearance_level
              || ', STATUS=' || :OLD.status;
    END IF;

    IF INSERTING OR UPDATING THEN
        v_new := 'EDIPI=' || :NEW.edipi
              || ', NAME=' || :NEW.last_name || ',' || :NEW.first_name
              || ', CLEARANCE=' || :NEW.clearance_level
              || ', STATUS=' || :NEW.status;
    END IF;

    dod_app_owner.dod_security_pkg.log_action(
        v_action, 'PERSONNEL',
        CASE WHEN DELETING THEN :OLD.personnel_id ELSE :NEW.personnel_id END,
        v_old, v_new
    );
END trg_personnel_audit;
/

-- Prevent direct deletion of personnel; use status = INACTIVE instead
CREATE OR REPLACE TRIGGER dod_app_owner.trg_personnel_nodelete
    BEFORE DELETE ON dod_app_owner.personnel
    FOR EACH ROW
BEGIN
    RAISE_APPLICATION_ERROR(-20010,
        'Direct DELETE on PERSONNEL is prohibited. '
        || 'Set STATUS=INACTIVE per DoD data retention policy.');
END trg_personnel_nodelete;
/

-- Audit trigger on healthcare encounters
CREATE OR REPLACE TRIGGER dod_app_owner.trg_encounter_audit
    AFTER INSERT OR UPDATE OR DELETE
    ON dod_app_owner.healthcare_encounters
    FOR EACH ROW
DECLARE
    v_action VARCHAR2(10);
BEGIN
    v_action := CASE
        WHEN INSERTING THEN 'INSERT'
        WHEN UPDATING  THEN 'UPDATE'
        WHEN DELETING  THEN 'DELETE'
    END;

    dod_app_owner.dod_security_pkg.log_action(
        v_action, 'HEALTHCARE_ENCOUNTERS',
        CASE WHEN DELETING THEN :OLD.encounter_id ELSE :NEW.encounter_id END,
        CASE WHEN UPDATING OR DELETING
             THEN 'encounter_type=' || :OLD.encounter_type || ', diagnosis=' || :OLD.diagnosis_code
             ELSE NULL END,
        CASE WHEN INSERTING OR UPDATING
             THEN 'encounter_type=' || :NEW.encounter_type || ', diagnosis=' || :NEW.diagnosis_code
             ELSE NULL END
    );
END trg_encounter_audit;
/

-- ============================================================
-- OPTIMIZED PL/SQL QUERIES (Performance + High-Availability)
-- ============================================================

-- View: Readiness summary per branch (used by healthcare dashboard)
CREATE OR REPLACE VIEW dod_app_owner.vw_branch_readiness AS
SELECT
    p.branch,
    COUNT(DISTINCT p.personnel_id)                        AS total_personnel,
    COUNT(DISTINCT CASE WHEN p.status = 'ACTIVE'
                        THEN p.personnel_id END)          AS active_count,
    COUNT(e.encounter_id)                                 AS total_encounters_ytd,
    COUNT(CASE WHEN e.encounter_type = 'BEHAVIORAL'
               THEN 1 END)                               AS behavioral_health_count,
    ROUND(COUNT(e.encounter_id) /
          NULLIF(COUNT(DISTINCT p.personnel_id),0), 2)   AS encounters_per_person,
    MAX(e.encounter_date)                                 AS last_encounter_date
FROM dod_app_owner.personnel p
LEFT JOIN dod_app_owner.healthcare_encounters e
       ON p.personnel_id = e.personnel_id
      AND e.encounter_date >= TRUNC(SYSDATE, 'YYYY')
GROUP BY p.branch;

GRANT SELECT ON dod_app_owner.vw_branch_readiness TO dod_report_role;

COMMIT;
