-- A rollback may remove unused scaffolding only.  Once a resolver-owned FQDN
-- spec, answer generation, or answer provenance exists, dropping it would lose
-- enforcement history and make a prior binary misstate why access changed.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM fqdn_resources)
       OR EXISTS (SELECT 1 FROM fqdn_resource_answer_generations)
       OR EXISTS (SELECT 1 FROM fqdn_resource_generation_answers) THEN
        RAISE EXCEPTION 'cannot roll back 0110: FQDN resource lifecycle data exists';
    END IF;
END $$;

DROP TRIGGER fqdn_generation_answer_before_delete ON fqdn_resource_generation_answers;
DROP TRIGGER fqdn_generation_answer_before_update ON fqdn_resource_generation_answers;
DROP FUNCTION fqdn_generation_answer_immutable();
DROP TRIGGER fqdn_generation_answer_before_insert ON fqdn_resource_generation_answers;
DROP FUNCTION fqdn_generation_answer_require_mutable();
DROP TRIGGER fqdn_generation_before_publish ON fqdn_resource_answer_generations;
DROP FUNCTION fqdn_generation_require_nonempty_active();
DROP TABLE fqdn_resource_generation_answers;
DROP TABLE fqdn_resource_answer_generations;
DROP TABLE fqdn_resources;
