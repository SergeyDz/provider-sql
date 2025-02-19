-- First, let's create a test large object
DO $$
DECLARE
    loid OID;
    lfd INTEGER;
    test_data TEXT := 'This is test data for our large object 2';
BEGIN
    -- Create a new large object
    loid := lo_create(-1);  -- -1 lets the system choose the OID
    
    -- Open the large object for writing (INV_WRITE = 131072)
    lfd := lo_open(loid, 131072);
    
    -- Write some data
    PERFORM lowrite(lfd, test_data::bytea);
    
    -- Close the large object
    PERFORM lo_close(lfd);
    
    -- Change the owner to event_service_user
    --EXECUTE format('ALTER LARGE OBJECT %s OWNER TO event_service_user', loid);
    
    RAISE NOTICE 'Created large object with OID: %', loid;
END;
$$;

-- Verify the large object exists (using pg_largeobject_metadata directly)
SELECT oid, lomowner::regrole as owner
FROM pg_largeobject_metadata
WHERE lomowner::regrole::text = 'event_service_user';