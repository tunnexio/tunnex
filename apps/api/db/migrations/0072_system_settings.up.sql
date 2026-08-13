-- ⛔ THE DEPLOYMENT-WIDE SETTINGS STORE, AND ITS FIRST TENANT IS THE LICENCE KEY.
--
-- S12.1 built a LicenseManager that held its claims IN MEMORY ONLY. `POST /license` verified a key,
-- cached it, and stored nothing — so a customer installed a valid licence, watched it work, and lost it
-- on the next restart or deploy. The first symptom was a gateway refusing to enrol.
--
-- ⚠ SEPARATE FROM `platform_secrets` ON PURPOSE. That table is for SEALED material (the agent CA, the
-- OpenVPN CA) and its rows are unreadable if the master key changes. A licence key is NOT a secret — it is
-- signed and self-verifying, and anyone holding it can already read every claim in it. Sealing it would
-- buy nothing cryptographically and would couple licence recovery to the sealer: a master-key rotation
-- would silently downgrade a paying deployment to Community, which is exactly the failure this migration
-- exists to prevent.
--
-- ⚠ WHAT IT DOES IDENTIFY, recorded so a data-handling review meets the fact rather than discovering it:
-- the stored key contains the customer's eTLD+1 DOMAIN, a licence ID, a tier and an expiry. It is
-- customer-identifying. It is not authenticating — possession grants nothing that reading it does not.
CREATE TABLE system_settings (
  key        text PRIMARY KEY,
  value      text NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON system_settings
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
