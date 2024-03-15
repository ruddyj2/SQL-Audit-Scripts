


SQL Server Security Audit: Scripts to help you or where can you find more information
==============================================================================================


The scripts listed below will help you configure several of the security options on SQL Server and also run some of the checks to see if there are potential issues.

### Check SQL Server Audit level

This will check to see what your current login audit level is set to capture.

       DECLARE @AuditLevel int
       EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', 
          N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', 
          N'AuditLevel', @AuditLevel OUTPUT
       SELECT CASE WHEN @AuditLevel = 0 THEN 'None'
          WHEN @AuditLevel = 1 THEN 'Successful logins only'
          WHEN @AuditLevel = 2 THEN 'Failed logins only'
          WHEN @AuditLevel = 3 THEN 'Both failed and successful logins' 
          END AS [AuditLevel] 

### Configure number of SQL Server logs

This script will change the setting so that you stored 48 SQL Server error log archives.  This will allow us to have a good amount of history from our error logs.

    EXEC master.dbo.xp_instance_regwrite N'HKEY_LOCAL_MACHINE', 
           N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', 
           N'NumErrorLogs', REG_DWORD, 48



### Create alert, operator and notification for the security events

We will setup these components so when there is an issue we can be alerted by SQL Server.

Create operator:

    EXEC msdb.dbo.sp_add_operator @name=N'NotifyDBA_Group', 
      @enabled=1, 
      @email_address=N'NotifyDBAs@company.com'

Create alert for severity 14 events (these are security related errors):

    EXEC msdb.dbo.sp_add_alert @name = N'Sev. 14 Errors - Permissions', 
      @severity = 14, 
      @include_event_description_in = 1

Create notification:

    EXEC msdb.dbo.sp_add_notification @alert_name = N'Sev. 14 Errors - Permissions', 
    @operator_name = N'NotifyDBA_Group', @notification_method = 1



### Find failed login events in SQL Server error log

This will allow us to search the SQL Server error log for failed logins.  This command below will search the active SQL Server error log.

    EXEC master.dbo.xp_readerrorlog 0, 1, 'login failed', null, NULL, NULL, N'desc'


### Check that Builtin\\Administrators group removed from sysadmins role

This command will check to see if the builtin administrator account has been removed.

    SELECT r.name  as SrvRole, u.name  as LoginName  
    FROM sys.server_role_members m JOIN
      sys.server_principals r ON m.role_principal_id = r.principal_id  JOIN
      sys.server_principals u ON m.member_principal_id = u.principal_id 
    WHERE u.name = 'BUILTIN\\Administrators'


### Find members of the "Local Administrators" group on SQL Server

If for some reason you want to keep the BUILTIN\\Administrators login you need to check who are the members of the "Local Administrators" group.

Note, that you will get results from the extended procedure below only if the BUILTIN\\Administrators group exists as login on SQL Server.

    EXEC master.sys.xp_logininfo 'BUILTIN\\Administrators','members'

### Find Sysadmins server role's members (and other server level roles)

This will show all logins and what server level roles each login has been assigned.

    EXEC master.sys.sp_helpsrvrolemember


### Find db_owner database role's members in each database

This will give you a list of database owners for each database.

    EXEC master.sys.sp_MSforeachdb '
    PRINT ''?''
    EXEC [?].dbo.sp_helprolemember ''db_owner'''

### Find logins mapped to the "dbo" user in each database

This will find all users that are mapped to the dbo schema.

    EXEC master.sys.sp_MSforeachdb '
    PRINT ''?''
    EXEC [?].dbo.sp_helpuser ''dbo'''

### Check password policies and expiration for the SQL logins

This will check whether the password policy is turn on or off.

    SELECT name  FROM sys.sql_logins 
     WHERE  is_policy_checked=0 OR is_expiration_checked = 0


### Check that Production and Test databases are segregated (on different SQL Servers)

This will look for the value of "Test" or "Dev" in all your database names.

    SELECT name FROM master.sys.databases 
     WHERE name LIKE '%Test%' OR name LIKE '%Dev%'

### Check that sample databases (AdventureWorks, Pubs etc.) are not present on Production SQL Servers

This will check to see if these sample databases are present on your server.

    SELECT name FROM master.sys.databases 
     WHERE name IN ('pubs', 'Northwind') OR name LIKE 'Adventure Works%'

### Verify that "sa" login has been renamed and/or disabled and has password policy/expiration enabled

This will check whether the sa password exists and if it does if the password policy is turned on for this login.

    SELECT l.name, CASE WHEN l.name = 'sa' THEN 'NO' ELSE 'YES' END as Renamed,
      s.is_policy_checked, s.is_expiration_checked, l.is_disabled
    FROM sys.server_principals AS l
     LEFT OUTER JOIN sys.sql_logins AS s ON s.principal_id = l.principal_id
    WHERE l.sid = 0x01



### Check server configuration options

This will check different server configuration settings such as: allow updates, cross db ownership chaining, clr enabled, SQL Mail XPs, Database Mail XPs, xp_cmdshell and Ad Hoc Distributed Queries.

    SELECT name, value_in_use FROM sys.configurations
     WHERE configuration_id IN (16391, 102, 400, 1562, 16386, 16385, 16390, 16393)



### CONNECT or other permissions granted to the "guest" user

This will list what permission the guest user has.

    SET NOCOUNT ON
    CREATE TABLE #guest_perms 
     ( db SYSNAME, class_desc SYSNAME, 
      permission_name SYSNAME, ObjectName SYSNAME NULL)
    EXEC master.sys.sp_MSforeachdb
    'INSERT INTO #guest_perms
     SELECT ''?'' as DBName, p.class_desc, p.permission_name, 
       OBJECT_NAME (major_id, DB_ID(''?'')) as ObjectName
     FROM [?].sys.database_permissions p JOIN [?].sys.database_principals l
      ON p.grantee_principal_id= l.principal_id 
     WHERE l.name = ''guest'' AND p.[state] = ''G'''

    SELECT db AS DatabaseName, class_desc, permission_name, 
     CASE WHEN class_desc = 'DATABASE' THEN db ELSE ObjectName END as ObjectName, 
     CASE WHEN DB_ID(db) IN (1, 2, 4) AND permission_name = 'CONNECT' THEN 'Default' 
      ELSE 'Potential Problem!' END as CheckStatus
    FROM #guest_perms
    DROP TABLE #guest_perms

Guest user by default has CONNECT permissions to the master, msdb and tempdb databases. Any other permissions will be returned by this query as potential problem.

### SQL Server Authentication mode

If this returns 0 the server uses both Windows and SQL Server security.  If the value is 1 it is only setup for Windows Authentication.

    SELECT SERVERPROPERTY ('IsIntegratedSecurityOnly')


### SQL Server version

There are many different ways to find the SQL Server version. Here are some of them:

    SELECT @@VERSION

.

    SELECT SERVERPROPERTY('ProductVersion') AS ProductVersion,
     SERVERPROPERTY('ProductLevel') AS ProductLevel

The 'ProductLevel' property above will show Service Pack level as well (if it has been installed).

    EXEC master.sys.xp_msver


### Database users, permissions and application roles

This will give a list of permissions for each user.

    -- list of the users
    EXEC sys.sp_helpuser
    -- database permissions
    EXEC sys.sp_helprotect
    -- roles membership
    EXEC sys.sp_helprolemember
    -- list of the database application roles
    SELECT name FROM sys.database_principals WHERE type = 'A'


### Location of Data and Log files

Quickly find databases that use only one drive:

    SET NOCOUNT ON
    CREATE TABLE #db_drives (db SYSNAME, drive_count INT)
    EXEC master.sys.sp_MSforeachdb
    'INSERT INTO #db_drives
     SELECT ''?'' AS DBName, 
      COUNT (DISTINCT LEFT(physical_name, CHARINDEX( ''\\'', physical_name,0)))
     FROM [?].sys.database_files'
      
    SELECT db AS DatabaseName
     FROM #db_drives 
    WHERE drive_count = 1 AND DB_ID(db) > 4
    DROP TABLE #db_drives

Check data and log files drives for the current database ('DriveLetter' column in the query below):

    SELECT name, type_desc, physical_name, 
     LEFT(physical_name, CHARINDEX( '\\', physical_name,0)) AS DriveLetter
    FROM sys.database_files

### Check enabled Network Protocols

The query below will show if the Named Pipes protocol is enabled on SQL Server instance:

    EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE',
      N'Software\\Microsoft\\MSSQLServer\\MSSQLServer\\SuperSocketNetLib\\Np', 
      N'Enabled', 
      @NamedPipesEnabled OUTPUT

    SELECT @NamedPipesEnabled AS NamedPipesEnabled


### SQL Server Services Startup mode

    SELECT * FROM sys.dm_server_services

### Linked Servers and Linked Server Logins

This will provide a list of linked server and the logins used for linked servers.

    \-- list of remote/linked servers
    SELECT * FROM sys.servers
    -- linked server logins
    EXEC master.sys.sp_helplinkedsrvlogin 

### Find logins without permissions

This will find a list of logins that no permissions granted.  These logins if are not used could then be removed.

    SET NOCOUNT ON
    CREATE TABLE #all_users (db VARCHAR(70), sid VARBINARY(85), stat VARCHAR(50))
    EXEC master.sys.sp_msforeachdb
    'INSERT INTO #all_users  
     SELECT ''?'', CONVERT(varbinary(85), sid) , 
      CASE WHEN  r.role_principal_id IS NULL AND p.major_id IS NULL 
      THEN ''no_db_permissions''  ELSE ''db_user'' END
     FROM [?].sys.database_principals u LEFT JOIN [?].sys.database_permissions p 
       ON u.principal_id = p.grantee_principal_id  
       AND p.permission_name <> ''CONNECT''
      LEFT JOIN [?].sys.database_role_members r 
       ON u.principal_id = r.member_principal_id
      WHERE u.SID IS NOT NULL AND u.type_desc <> ''DATABASE_ROLE'''
    IF EXISTS 
    (SELECT l.name FROM sys.server_principals l LEFT JOIN sys.server_permissions p 
      ON l.principal_id = p.grantee_principal_id  
      AND p.permission_name <> 'CONNECT SQL'
     LEFT JOIN sys.server_role_members r 
      ON l.principal_id = r.member_principal_id
     LEFT JOIN #all_users u 
      ON l.sid= u.sid
     WHERE r.role_principal_id IS NULL  AND l.type_desc <> 'SERVER_ROLE' 
      AND p.major_id IS NULL
     )
    BEGIN
     SELECT DISTINCT l.name LoginName, l.type_desc, l.is_disabled, 
      ISNULL(u.stat + ', but is user in ' + u.db  +' DB', 'no_db_users') db_perms, 
      CASE WHEN p.major_id IS NULL AND r.role_principal_id IS NULL  
      THEN 'no_srv_permissions' ELSE 'na' END srv_perms 
     FROM sys.server_principals l LEFT JOIN sys.server_permissions p 
       ON l.principal_id = p.grantee_principal_id  
       AND p.permission_name <> 'CONNECT SQL'
      LEFT JOIN sys.server_role_members r 
       ON l.principal_id = r.member_principal_id
       LEFT JOIN #all_users u 
       ON l.sid= u.sid
      WHERE  l.type_desc <> 'SERVER_ROLE' 
       AND ((u.db  IS NULL  AND p.major_id IS NULL 
         AND r.role_principal_id IS NULL )
       OR (u.stat = 'no_db_permissions' AND p.major_id IS NULL 
         AND r.role_principal_id IS NULL)) 
     ORDER BY 1, 4
    END
    DROP TABLE #all_users 

The list returned by this query contains logins that should be reviewed and most likely have to be disabled or deleted:

The last login in the list above still has user account in master database, but this user does not have any permissions on the database. This login could be deleted as well (after user's account deleted from the master database).

### Find broken database users on all databases (SQL logins mapping is broken)

These users are known as orphaned users because the associated link between the login and user is broken. 

    EXEC master.sys.sp_msforeachdb '
    print ''?''
    EXEC [?].dbo.sp_change_users_login ''report'''

### Find orphaned users in all of the databases (no logins exist for the database users)

Make sure you ran the previous check and fixed SQL Server logins before running this check.

    SET NOCOUNT ON
    CREATE TABLE #orph_users (db SYSNAME, username SYSNAME, 
        type_desc VARCHAR(30),type VARCHAR(30))
    EXEC master.sys.sp_msforeachdb  
    'INSERT INTO #orph_users
     SELECT ''?'', u.name , u.type_desc, u.type
     FROM  [?].sys.database_principals u 
      LEFT JOIN  [?].sys.server_principals l ON u.sid = l.sid 
     WHERE l.sid IS NULL 
      AND u.type NOT IN (''A'', ''R'', ''C'') -- not a db./app. role or certificate
      AND u.principal_id > 4 -- not dbo, guest or INFORMATION_SCHEMA
      AND u.name NOT LIKE ''%DataCollector%'' 
      AND u.name NOT LIKE ''mdw%'' -- not internal users in msdb or MDW databases'
        
     SELECT * FROM #orph_users
     
     DROP TABLE #orph_users

### Validate logins (identify orphaned Windows logins)

This check will show Windows logins that have been deleted from the server or Active Directory. Read more 

    EXEC master.sys.sp_validatelogins

### Backups verification report

Check if a Full backup exists that is not older than 7 days, a Differential backup exists that is not older than 2 days or a Transaction Log backup exists that is not older than 1 day (you can change the number of days based on your requirements):

    SELECT m.name AS DatabaseName, DATABASEPROPERTYEX(m.name, 'Recovery') AS RecoveryMode,
     CASE WHEN ISNULL(MAX(b.backup_finish_date), GETDATE()-10000) < GETDATE()-7 
        AND b.[type] = 'D' THEN 'Problem!' 
       WHEN ISNULL(MAX(b.backup_finish_date), GETDATE()-10000) < GETDATE()-2 
         AND b.[type] = 'I' THEN 'Problem!' 
       WHEN ISNULL(MAX(b.backup_finish_date), GETDATE()-10000) < GETDATE()-1 
         AND b.[type] = 'L' THEN 'Problem!' 
       ELSE 'OK' END AS BackupStatus,
        CASE WHEN b.[type] = 'D'  THEN 'Full' 
       WHEN b.[type] = 'I'  THEN 'Differential'
       WHEN b.[type] = 'L'  THEN 'Transaction Log'  END AS BackupType, 
     MAX(b.backup_finish_date) AS backup_finish_date
      FROM master.sys.databases m LEFT JOIN msdb.dbo.backupset b
      ON m.name = b.database_name 
    WHERE m.database_id NOT IN (2,3) 
      AND DATABASEPROPERTYEX(m.name, 'Updateability') <> 'READ_ONLY'
    GROUP BY m.name, b.[type] 
    HAVING ISNULL(MAX(b.backup_finish_date), GETDATE()-11) > GETDATE() - 10 
      OR MAX(b.backup_finish_date) IS NULL
    ORDER BY m.name, backup_finish_date 

You can also use the SSMS built-in report to review a database's backup and restore events:
  
These scripts will be a good start for you to check your SQL Servers' security and settings. I provided scripts in SQL format for the most checks. This will allow you to put it all together and create your own report for all these checks.



  
  

