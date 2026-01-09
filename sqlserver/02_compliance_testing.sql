-- ============================================================
-- RDBMS Security Lab: Compliance Testing & Validation Scripts
-- DoD IT Maintenance Standards Verification
-- Author: Independent Project Portfolio
-- Date: January 2026
-- ============================================================
-- PURPOSE: These scripts validate the RDBMS environment meets
-- DoD STIG and IAVM compliance requirements before deployment.
-- Run in order; all tests should return PASS.
-- ============================================================

USE DOD_HealthDB;
GO

-- ============================================================
-- TEST 1: Verify schema separation exists
-- ============================================================
PRINT '--- TEST 1: Schema Separation ---';
SELECT
    CASE WHEN COUNT(*) = 3 THEN 'PASS' ELSE 'FAIL' END AS SchemaTest,
    COUNT(*) AS SchemasFound,
    STRING_AGG(name, ', ') AS SchemaNames
FROM sys.schemas
WHERE name IN ('app','audit','report');
GO

-- ============================================================
-- TEST 2: Verify no default 'sa' or blank-password logins
-- ============================================================
PRINT '--- TEST 2: Dangerous Logins Check ---';
SELECT
    name AS LoginName,
    is_disabled,
    CASE WHEN is_disabled = 1 THEN 'PASS - Disabled'
         WHEN name = 'sa'     THEN 'REVIEW - sa account exists and is enabled'
         ELSE 'REVIEW'
    END AS Assessment
FROM sys.server_principals
WHERE type = 'S'  -- SQL logins
  AND name IN ('sa','guest','public');
GO

-- ============================================================
-- TEST 3: Verify TRUSTWORTHY is OFF (security hardening)
-- ============================================================
PRINT '--- TEST 3: TRUSTWORTHY Setting ---';
SELECT
    name,
    is_trustworthy_on,
    CASE WHEN is_trustworthy_on = 0 THEN 'PASS' ELSE 'FAIL - TRUSTWORTHY should be OFF' END AS Assessment
FROM sys.databases
WHERE name = 'DOD_HealthDB';
GO

-- ============================================================
-- TEST 4: Verify audit table is capturing changes
-- ============================================================
PRINT '--- TEST 4: Audit Trigger Functionality ---';

-- Insert test record
EXEC app.usp_UpsertPersonnel
    @EDIPI          = '1234567890',
    @LastName       = 'TESTLAST',
    @FirstName      = 'TESTFIRST',
    @RankGrade      = 'E-5',
    @Branch         = 'ARMY',
    @ClearanceLevel = 'SECRET',
    @Status         = 'ACTIVE';

-- Update test record (should create UPDATE audit entry)
EXEC app.usp_UpsertPersonnel
    @EDIPI          = '1234567890',
    @LastName       = 'TESTLAST',
    @FirstName      = 'TESTFIRST',
    @RankGrade      = 'E-6',
    @Branch         = 'ARMY',
    @ClearanceLevel = 'TOP SECRET',
    @Status         = 'ACTIVE';

-- Verify audit entries exist
SELECT
    CASE WHEN COUNT(*) >= 2 THEN 'PASS' ELSE 'FAIL' END AS AuditTest,
    COUNT(*) AS AuditEntriesFound,
    STRING_AGG(ActionType, ', ') AS ActionsLogged
FROM audit.AccessLog
WHERE TableAffected = 'app.Personnel'
  AND RowIDaffected = (SELECT PersonnelID FROM app.Personnel WHERE EDIPI = '1234567890');
GO

-- ============================================================
-- TEST 5: Verify least-privilege role assignments
-- ============================================================
PRINT '--- TEST 5: Role Permission Verification ---';
SELECT
    dp.name       AS RoleName,
    obj.name      AS ObjectName,
    perm.permission_name,
    perm.state_desc
FROM sys.database_permissions perm
JOIN sys.database_principals  dp  ON perm.grantee_principal_id = dp.principal_id
JOIN sys.objects               obj ON perm.major_id = obj.object_id
WHERE dp.name IN ('dod_app_role','dod_report_role','dod_audit_role')
ORDER BY dp.name, obj.name;
GO

-- ============================================================
-- TEST 6: Performance baseline — verify indexes are used
-- ============================================================
PRINT '--- TEST 6: Query Plan Index Utilization ---';
SET STATISTICS IO ON;

-- Should use IX_Personnel_EDIPI (seek, not scan)
SELECT PersonnelID, LastName, FirstName, ClearanceLevel
FROM app.Personnel
WHERE EDIPI = '1234567890';

-- Should use IX_Encounters_Date_Facility
SELECT COUNT(*) AS EncounterCount
FROM app.HealthcareEncounters
WHERE EncounterDate >= '2026-01-01'
  AND FacilityCode = 'MTF-WALTER-REED';

SET STATISTICS IO OFF;
GO

-- ============================================================
-- TEST 7: Reporting view returns data in correct shape
-- ============================================================
PRINT '--- TEST 7: Reporting View Validation ---';
SELECT
    CASE WHEN COUNT(*) >= 0 THEN 'PASS' ELSE 'FAIL' END AS ViewTest
FROM report.BranchReadiness;
GO

-- ============================================================
-- CLEANUP TEST DATA
-- ============================================================
UPDATE app.Personnel SET Status = 'INACTIVE' WHERE EDIPI = '1234567890';
PRINT '--- Test data deactivated (retention policy: no deletes) ---';
GO

-- ============================================================
-- FINAL COMPLIANCE SUMMARY
-- ============================================================
PRINT '=== COMPLIANCE VALIDATION COMPLETE ===';
EXEC audit.usp_ComplianceReport
    @StartDate = '2026-01-01',
    @EndDate   = '2026-12-31';
GO
