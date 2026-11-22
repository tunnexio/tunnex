-- Restores the opt-in default for organizations created afterwards. Existing organizations keep their
-- current value: which were off before 0237 is not recorded, and turning connectivity off behind an
-- administrator's back would be worse than leaving it on.
ALTER TABLE organizations ALTER COLUMN cross_gateway_clients_enabled SET DEFAULT false;
