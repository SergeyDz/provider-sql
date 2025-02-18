WITH database_info AS (
    -- Get database and owner info
    SELECT 
        current_database() as database_name,
        pg_catalog.pg_get_userbyid(d.datdba) as database_owner
    FROM pg_catalog.pg_database d
    WHERE d.datname = current_database()
),
schema_list AS (
    SELECT nspname AS schema_name
    FROM pg_namespace
    WHERE nspname NOT LIKE 'pg_%' 
    AND nspname != 'information_schema'
),
user_privileges AS (
    -- Get user privileges with inheritance
    WITH RECURSIVE roles AS (
        SELECT 
            rm.roleid,
            rm.member,
            rm.admin_option,
            1 AS depth
        FROM pg_auth_members rm
        UNION ALL
        SELECT 
            r.roleid,
            m.member,
            r.admin_option,
            r.depth + 1
        FROM roles r
        JOIN pg_auth_members m ON m.roleid = r.member
        WHERE r.depth < 100
    ),
    -- Organize privileges by type
    privilege_details AS (
        -- Database privileges
        SELECT 
            dp.grantee,
            'DATABASE' as object_type,
            current_database() as object_name,
            array_agg(DISTINCT dp.privilege_type) as privileges
        FROM information_schema.usage_privileges dp
        WHERE dp.object_catalog = current_database()
        GROUP BY dp.grantee
        
        UNION ALL
        
        -- Schema privileges (enhanced version)
        SELECT 
            grantee,
            'SCHEMA' as object_type,
            table_schema as object_name,
            array_agg(DISTINCT 
                CASE 
                    WHEN privilege_type = 'INSERT' THEN 'USAGE'
                    WHEN privilege_type = 'USAGE' THEN 'USAGE'
                    WHEN privilege_type = 'SELECT' THEN 'USAGE'
                    ELSE privilege_type
                END
            ) as privileges
        FROM (
            SELECT DISTINCT grantee, table_schema, privilege_type
            FROM information_schema.role_table_grants
            WHERE table_catalog = current_database()
            UNION
            SELECT DISTINCT grantee, object_schema, privilege_type
            FROM information_schema.role_usage_grants
            WHERE object_catalog = current_database()
            AND object_type = 'SCHEMA'
        ) combined_schema_privs
        GROUP BY grantee, table_schema
        
        UNION ALL
        
        -- Table privileges
        SELECT 
            grantee,
            'TABLE' as object_type,
            table_schema || '.' || table_name as object_name,
            array_agg(DISTINCT privilege_type) as privileges
        FROM information_schema.role_table_grants
        WHERE table_catalog = current_database()
        GROUP BY grantee, table_schema, table_name
        
        UNION ALL
        
        -- Sequence privileges
        SELECT 
            grantee,
            'SEQUENCE' as object_type,
            object_schema || '.' || object_name as object_name,
            array_agg(DISTINCT privilege_type) as privileges
        FROM information_schema.role_usage_grants
        WHERE object_catalog = current_database()
        AND object_type = 'SEQUENCE'
        GROUP BY grantee, object_schema, object_name
        
        UNION ALL
        
        -- Function privileges
        SELECT 
            grantee,
            'FUNCTION' as object_type,
            specific_schema || '.' || routine_name as object_name,
            array_agg(DISTINCT privilege_type) as privileges
        FROM information_schema.routine_privileges
        WHERE specific_catalog = current_database()
        GROUP BY grantee, specific_schema, routine_name
    )
    SELECT DISTINCT
        r.rolname AS username,
        CASE 
            WHEN r.rolsuper THEN 'SUPERUSER'
            ELSE 'REGULAR USER'
        END AS user_type,
        r.rolcanlogin AS can_login,
        pd.object_type,
        string_agg(
            DISTINCT pd.object_name || ' (' || array_to_string(pd.privileges, ', ') || ')',
            E'\n          '
        ) AS privilege_details
    FROM pg_roles r
    LEFT JOIN roles rm ON rm.member = r.oid
    LEFT JOIN pg_roles pr ON pr.oid = rm.roleid
    LEFT JOIN privilege_details pd ON pd.grantee = r.rolname
    WHERE 
        r.rolname NOT LIKE 'pg_%'
        AND pd.object_type IS NOT NULL
    GROUP BY r.rolname, r.rolsuper, r.rolcanlogin, pd.object_type
)
SELECT 
    '=== DATABASE SECURITY REPORT ===' AS "Report Section",
    NULL::text AS "Details"
UNION ALL
SELECT 
    '1. Database Information',
    NULL
UNION ALL
SELECT 
    '   Database Name:',
    database_name
FROM database_info
UNION ALL
SELECT 
    '   Database Owner:',
    database_owner
FROM database_info
UNION ALL
SELECT 
    '2. Available Schemas',
    string_agg(schema_name, ', ')
FROM schema_list
UNION ALL
SELECT 
    '3. User Privileges',
    NULL
UNION ALL
SELECT 
    '   ' || username || ' (' || user_type || 
    CASE WHEN can_login THEN ' - Can login)' ELSE ' - Cannot login)' END,
    object_type || ' Privileges:' || E'\n          ' || privilege_details
FROM user_privileges
ORDER BY "Report Section", "Details";