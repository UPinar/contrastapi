CREATE FUNCTION api.fn_connection_role_state()
  RETURNS TABLE (is_superuser    boolean,
                 is_owner_member boolean)
  LANGUAGE sql STABLE SECURITY DEFINER
  SET search_path = pg_catalog
BEGIN ATOMIC
  SELECT r.rolsuper,
         pg_has_role(session_user, 'contrastapi-owner', 'MEMBER')
    FROM pg_roles AS r
   WHERE r.rolname = session_user;
END;
