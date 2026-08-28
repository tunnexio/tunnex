-- S21 D1/D6: FQDNResource.label is an operator-authored note, like the static
-- Resource label. It is not a resolver or compiler input and therefore must not
-- affect a generation identity or policy hash.
ALTER TABLE fqdn_resources
    ADD COLUMN label text NULL CHECK (length(label) <= 60);
