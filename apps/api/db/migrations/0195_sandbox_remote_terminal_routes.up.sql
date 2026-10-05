-- Operator-bound sandbox-only transport; no organization-wide routing toggle.
CREATE TABLE sandbox_remote_terminal_routes (
 sandbox_id uuid PRIMARY KEY,
 org_id uuid NOT NULL,
 terminal_device_id uuid NOT NULL,
 terminal_gateway_id uuid NOT NULL,
 runtime_gateway_id uuid NOT NULL,
 terminal_gateway_endpoint text NOT NULL CHECK(length(terminal_gateway_endpoint) BETWEEN 1 AND 128),
 runtime_gateway_endpoint text NOT NULL CHECK(length(runtime_gateway_endpoint) BETWEEN 1 AND 128),
 CHECK(terminal_gateway_id<>runtime_gateway_id),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id) ON DELETE CASCADE,
 FOREIGN KEY(org_id,terminal_device_id) REFERENCES devices(org_id,id),
 FOREIGN KEY(terminal_gateway_id) REFERENCES nodes(id),
 FOREIGN KEY(runtime_gateway_id) REFERENCES nodes(id)
);

CREATE FUNCTION sandbox_remote_terminal_route_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'sandbox remote terminal route is immutable';
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER sandbox_remote_terminal_route_immutable BEFORE UPDATE ON sandbox_remote_terminal_routes
 FOR EACH ROW EXECUTE FUNCTION sandbox_remote_terminal_route_immutable();
