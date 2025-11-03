-- ============================================================
-- RDBMS Security Lab: MS SQL Server Implementation
-- DoD IT / DHA Compliance Focus
-- Author: Independent Project Portfolio
-- Date: January 2026
-- ============================================================

USE master;
GO

-- Create the database with appropriate settings
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'DOD_HealthDB')
BEGIN
    CREATE DATABASE DOD_HealthDB
        ON PRIMARY (
            NAME = DOD_HealthDB_data,
            FILENAME = 'C:\SQLData\DOD_HealthDB.mdf',
            SIZE = 100MB, MAXSIZE = 1GB, FILEGROWTH = 10MB
        )
        LOG ON (
            NAME = DOD_HealthDB_log,
            FILENAME = 'C:\SQLData\DOD_HealthDB_log.ldf',
            SIZE = 20MB, MAXSIZE = 200MB, FILEGROWTH = 5MB
        );
END
GO

-- Enable encrypted connections requirement (DoD STIG MS SQL Server)
-- ALTER DATABASE DOD_HealthDB SET ENCRYPTION ON;  -- Requires TDE cert setup
-- Trustworthy OFF is the secure default
ALTER DATABASE DOD_HealthDB SET TRUSTWORTHY OFF;
ALTER DATABASE DOD_HealthDB SET DB_CHAINING OFF;
GO

USE DOD_HealthDB;
GO

-- ============================================================
-- SCHEMAS (logical separation per DoD data classification)
-- ============================================================
CREATE SCHEMA app    AUTHORIZATION dbo;
CREATE SCHEMA audit  AUTHORIZATION dbo;
CREATE SCHEMA report AUTHORIZATION dbo;
GO

-- ============================================================
-- CORE TABLES
-- ============================================================

CREATE TABLE app.Personnel (
    PersonnelID     INT           IDENTITY(1,1) PRIMARY KEY,
    EDIPI           CHAR(10)      NOT NULL UNIQUE,
    LastName        NVARCHAR(50)  NOT NULL,
    FirstName       NVARCHAR(50)  NOT NULL,
    RankGrade       VARCHAR(10),
    Branch          VARCHAR(20)   CHECK (Branch IN ('ARMY','NAVY','USAF','USMC','USCG','SPACE','CIVILIAN')),
    UnitCode        VARCHAR(20),
    ClearanceLevel  VARCHAR(20)   CHECK (ClearanceLevel IN ('UNCLASSIFIED','CUI','SECRET','TOP SECRET','TS/SCI')),
    Status          VARCHAR(10)   NOT NULL DEFAULT 'ACTIVE'
                                  CHECK (Status IN ('ACTIVE','INACTIVE','SEPARATED')),
    CreatedBy       NVARCHAR(50)  NOT NULL DEFAULT SYSTEM_USER,
    CreatedDate     DATETIME2     NOT NULL DEFAULT SYSDATETIME(),
    ModifiedDate    DATETIME2
);

CREATE TABLE app.HealthcareEncounters (
    EncounterID     INT           IDENTITY(1,1) PRIMARY KEY,
    PersonnelID     INT           NOT NULL REFERENCES app.Personnel(PersonnelID),
    EncounterDate   DATE          NOT NULL,
    FacilityCode    VARCHAR(20)   NOT NULL,
    EncounterType   VARCHAR(30)   CHECK (EncounterType IN
                                  ('ROUTINE','URGENT','EMERGENCY','DENTAL','BEHAVIORAL','PREVENTIVE')),
    DiagnosisCode   VARCHAR(10),
    ProviderID      INT,
    Disposition     VARCHAR(30),
    Classification  VARCHAR(20)   DEFAULT 'UNCLASSIFIED',
    CreatedDate     DATETIME2     NOT NULL DEFAULT SYSDATETIME()
);

CREATE TABLE audit.AccessLog (
    LogID           BIGINT        IDENTITY(1,1) PRIMARY KEY,
    LogTimestamp    DATETIME2     NOT NULL DEFAULT SYSDATETIME(),
    DBUser          NVARCHAR(50)  NOT NULL DEFAULT SYSTEM_USER,
    HostName        NVARCHAR(100) DEFAULT HOST_NAME(),
    AppName         NVARCHAR(100) DEFAULT APP_NAME(),
    ActionType      VARCHAR(20)   NOT NULL,
    TableAffected   VARCHAR(50),
    RowIDaffected   INT,
    OldValue        NVARCHAR(MAX),
    NewValue        NVARCHAR(MAX)
);
GO

-- ============================================================
-- INDEXES
-- ============================================================
CREATE NONCLUSTERED INDEX IX_Personnel_EDIPI
    ON app.Personnel(EDIPI);

CREATE NONCLUSTERED INDEX IX_Personnel_Branch_Status
    ON app.Personnel(Branch, Status)
    INCLUDE (LastName, FirstName, RankGrade);

CREATE NONCLUSTERED INDEX IX_Encounters_Date_Facility
    ON app.HealthcareEncounters(EncounterDate, FacilityCode)
    INCLUDE (PersonnelID, EncounterType, DiagnosisCode);

CREATE NONCLUSTERED INDEX IX_AccessLog_Timestamp
    ON audit.AccessLog(LogTimestamp DESC);
GO

-- ============================================================
-- STORED PROCEDURES
-- ============================================================

-- Upsert personnel with audit logging
CREATE OR ALTER PROCEDURE app.usp_UpsertPersonnel
    @EDIPI          CHAR(10),
    @LastName       NVARCHAR(50),
    @FirstName      NVARCHAR(50),
    @RankGrade      VARCHAR(10)  = NULL,
    @Branch         VARCHAR(20)  = NULL,
    @UnitCode       VARCHAR(20)  = NULL,
    @ClearanceLevel VARCHAR(20)  = 'UNCLASSIFIED',
    @Status         VARCHAR(10)  = 'ACTIVE'
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @PersonnelID INT;
    DECLARE @OldValues   NVARCHAR(MAX);
    DECLARE @NewValues   NVARCHAR(MAX);
    DECLARE @Action      VARCHAR(10);

    BEGIN TRY
        BEGIN TRANSACTION;

        -- Check if record exists
        SELECT @PersonnelID = PersonnelID,
               @OldValues   = CONCAT('EDIPI=',EDIPI,',Name=',LastName,',',FirstName,
                                     ',Clearance=',ClearanceLevel,',Status=',Status)
        FROM app.Personnel
        WHERE EDIPI = @EDIPI;

        SET @NewValues = CONCAT('EDIPI=',@EDIPI,',Name=',@LastName,',',@FirstName,
                                ',Clearance=',@ClearanceLevel,',Status=',@Status);

        IF @PersonnelID IS NULL
        BEGIN
            INSERT INTO app.Personnel (EDIPI, LastName, FirstName, RankGrade,
                                       Branch, UnitCode, ClearanceLevel, Status)
            VALUES (@EDIPI, @LastName, @FirstName, @RankGrade,
                    @Branch, @UnitCode, @ClearanceLevel, @Status);

            SET @PersonnelID = SCOPE_IDENTITY();
            SET @Action = 'INSERT';
        END
        ELSE
        BEGIN
            UPDATE app.Personnel
            SET    LastName       = @LastName,
                   FirstName      = @FirstName,
                   RankGrade      = @RankGrade,
                   Branch         = @Branch,
                   UnitCode       = @UnitCode,
                   ClearanceLevel = @ClearanceLevel,
                   Status         = @Status,
                   ModifiedDate   = SYSDATETIME()
            WHERE  PersonnelID = @PersonnelID;

            SET @Action = 'UPDATE';
        END;

        -- Audit log
        INSERT INTO audit.AccessLog (ActionType, TableAffected, RowIDaffected, OldValue, NewValue)
        VALUES (@Action, 'app.Personnel', @PersonnelID, @OldValues, @NewValues);

        COMMIT TRANSACTION;
        SELECT @PersonnelID AS PersonnelID, @Action AS ActionPerformed;
    END TRY
    BEGIN CATCH
        ROLLBACK TRANSACTION;
        INSERT INTO audit.AccessLog (ActionType, TableAffected, OldValue, NewValue)
        VALUES ('ERROR', 'app.Personnel', @OldValues,
                CONCAT('ERROR: ', ERROR_MESSAGE(), ' Line:', ERROR_LINE()));
        THROW;
    END CATCH;
END;
GO

-- Compliance summary report
CREATE OR ALTER PROCEDURE audit.usp_ComplianceReport
    @StartDate DATE,
    @EndDate   DATE
AS
BEGIN
    SET NOCOUNT ON;

    SELECT
        ActionType,
        TableAffected,
        COUNT(*)                              AS EventCount,
        COUNT(DISTINCT DBUser)                AS UniqueUsers,
        MIN(LogTimestamp)                     AS FirstEvent,
        MAX(LogTimestamp)                     AS LastEvent
    FROM audit.AccessLog
    WHERE LogTimestamp BETWEEN @StartDate AND @EndDate
    GROUP BY ActionType, TableAffected
    ORDER BY EventCount DESC;

    -- After-hours access summary (risk indicator)
    SELECT
        DBUser,
        COUNT(*) AS AfterHoursAccess,
        MIN(LogTimestamp) AS FirstAfterHours,
        MAX(LogTimestamp) AS LastAfterHours
    FROM audit.AccessLog
    WHERE LogTimestamp BETWEEN @StartDate AND @EndDate
      AND (DATEPART(HOUR, LogTimestamp) < 6 OR DATEPART(HOUR, LogTimestamp) >= 18)
    GROUP BY DBUser
    ORDER BY AfterHoursAccess DESC;
END;
GO

-- ============================================================
-- ROLES & PERMISSIONS (Least Privilege)
-- ============================================================
CREATE ROLE dod_app_role;
CREATE ROLE dod_report_role;
CREATE ROLE dod_audit_role;

-- App role permissions
GRANT SELECT, INSERT, UPDATE ON app.Personnel             TO dod_app_role;
GRANT SELECT, INSERT, UPDATE ON app.HealthcareEncounters  TO dod_app_role;
GRANT INSERT                  ON audit.AccessLog           TO dod_app_role;
GRANT EXECUTE ON app.usp_UpsertPersonnel                  TO dod_app_role;

-- Report role (read-only)
GRANT SELECT ON app.Personnel             TO dod_report_role;
GRANT SELECT ON app.HealthcareEncounters  TO dod_report_role;

-- Audit role
GRANT SELECT ON audit.AccessLog             TO dod_audit_role;
GRANT EXECUTE ON audit.usp_ComplianceReport TO dod_audit_role;

-- ============================================================
-- REPORTING VIEW
-- ============================================================
CREATE OR ALTER VIEW report.BranchReadiness AS
SELECT
    p.Branch,
    COUNT(DISTINCT p.PersonnelID)                                           AS TotalPersonnel,
    SUM(CASE WHEN p.Status = 'ACTIVE' THEN 1 ELSE 0 END)                   AS ActiveCount,
    COUNT(e.EncounterID)                                                    AS TotalEncountersYTD,
    SUM(CASE WHEN e.EncounterType = 'BEHAVIORAL' THEN 1 ELSE 0 END)        AS BehavioralHealthCount,
    ROUND(CAST(COUNT(e.EncounterID) AS FLOAT)
          / NULLIF(COUNT(DISTINCT p.PersonnelID),0), 2)                    AS EncountersPerPerson,
    MAX(e.EncounterDate)                                                    AS LastEncounterDate
FROM app.Personnel p
LEFT JOIN app.HealthcareEncounters e
       ON p.PersonnelID = e.PersonnelID
      AND e.EncounterDate >= DATEFROMPARTS(YEAR(GETDATE()),1,1)
GROUP BY p.Branch;
GO

GRANT SELECT ON report.BranchReadiness TO dod_report_role;
GO
