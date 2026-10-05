DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM sandbox_remote_terminal_routes) THEN
  RAISE EXCEPTION 'remote terminal records retained; reconcile explicitly before rollback';
 END IF;
END $$;
DROP TABLE sandbox_remote_terminal_routes;
DROP FUNCTION sandbox_remote_terminal_route_immutable();
