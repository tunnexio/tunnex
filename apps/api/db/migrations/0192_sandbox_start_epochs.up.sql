-- Resume has its own fresh evidence epoch without changing enrollment identity.
CREATE TABLE sandbox_start_epochs (
 id uuid NOT NULL UNIQUE DEFAULT uuid_generate_v7(),
 sandbox_id uuid NOT NULL,
 org_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>1),
 operation_id uuid NOT NULL REFERENCES sandbox_launch_operations(id),
 created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(sandbox_id,generation),
 FOREIGN KEY(org_id,sandbox_id) REFERENCES sandboxes(org_id,id)
);
CREATE FUNCTION sandbox_start_epoch_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'sandbox start epoch is immutable';
END $$;
CREATE TRIGGER sandbox_start_epoch_immutable BEFORE UPDATE ON sandbox_start_epochs
 FOR EACH ROW EXECUTE FUNCTION sandbox_start_epoch_immutable();

ALTER TABLE sandbox_network_withdrawals ADD COLUMN network_epoch_id uuid REFERENCES sandbox_start_epochs(id);
