DO $$
DECLARE
    role_name text;
    current_user text;
BEGIN
    -- Get current user
    SELECT session_user INTO current_user;
    
    -- First grant ourselves membership in these roles
    FOR role_name IN 
        SELECT rolname 
        FROM pg_roles 
        WHERE rolname LIKE '%event_service%'
    LOOP
        EXECUTE format('GRANT %I TO %I', role_name, current_user);
    END LOOP;

    -- Remove default privileges specifically for event_service_user
    ALTER DEFAULT PRIVILEGES FOR ROLE event_service_user IN SCHEMA public 
    REVOKE ALL ON TABLES FROM event_service_app_user;
    
    ALTER DEFAULT PRIVILEGES FOR ROLE event_service_user IN SCHEMA public 
    REVOKE ALL ON SEQUENCES FROM event_service_app_user;

    -- Now drop the roles
    EXECUTE 'DROP ROLE IF EXISTS event_service_app_user';
    EXECUTE 'DROP ROLE IF EXISTS event_service_user';
    
    RAISE NOTICE 'Roles dropped successfully';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Error: %', SQLERRM;
END;
$$;