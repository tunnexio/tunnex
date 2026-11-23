-- K8N-4: "expose every Service in this namespace". A rule names ONE cluster and ONE namespace; the
-- control plane applies it each time the cluster's gateway reports its Service inventory. A rule only
-- creates exposures (an address and a name); it never creates an access rule.
--
-- System namespaces and Tunnex's own are never eligible. The check is repeated here so a row written
-- past the API still cannot name one.

CREATE TABLE k8s_namespace_exposure_rules (
    id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id             uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    cluster_id         uuid        NOT NULL REFERENCES k8s_clusters (id) ON DELETE CASCADE,
    namespace          text        NOT NULL,
    created_by_user_id uuid        REFERENCES users (id) ON DELETE SET NULL,
    -- The outcome of the last pass. 'pending' until the first pass ran.
    status             text        NOT NULL DEFAULT 'pending',
    status_message     text        NOT NULL DEFAULT '',
    -- Services of the namespace the last pass could not expose (0 when status is 'applied').
    waiting_services   integer     NOT NULL DEFAULT 0 CHECK (waiting_services >= 0),
    last_reconciled_at timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (cluster_id, namespace),
    CONSTRAINT k8s_namespace_exposure_rules_namespace_label CHECK (
        namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$' AND octet_length(namespace) BETWEEN 1 AND 63
    ),
    CONSTRAINT k8s_namespace_exposure_rules_namespace_eligible CHECK (
        namespace NOT IN ('kube-system', 'kube-public', 'kube-node-lease', 'tunnex', 'tunnex-system')
        AND namespace NOT LIKE 'tunnex-%'
    ),
    CONSTRAINT k8s_namespace_exposure_rules_status CHECK (status IN (
        'pending', 'applied', 'inventory_stale', 'inventory_unavailable',
        'vip_range_exhausted', 'scope_review_limit', 'withdrawal_blocked', 'error'
    ))
);

CREATE INDEX k8s_namespace_exposure_rules_org_idx ON k8s_namespace_exposure_rules (org_id);

CREATE TRIGGER set_updated_at BEFORE UPDATE ON k8s_namespace_exposure_rules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Which exposures a rule created. A row here is the ONLY thing that makes an exposure the rule's: a
-- dashboard or operator exposure has none, and a rule never adopts one. Kept beside k8s_services, not as
-- a column on it, so the exposure row and everything that reads it are unchanged. Removing a rule
-- cascades these rows away, which is "remove the rule, keep its exposures": they become ordinary
-- dashboard exposures. missing_since is when a fresh report first lacked the Service port; the exposure
-- is withdrawn only after it has stayed missing for the wait.
CREATE TABLE k8s_namespace_rule_exposures (
    service_id    uuid PRIMARY KEY REFERENCES k8s_services (id) ON DELETE CASCADE,
    org_id        uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    rule_id       uuid        NOT NULL REFERENCES k8s_namespace_exposure_rules (id) ON DELETE CASCADE,
    missing_since timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX k8s_namespace_rule_exposures_rule_idx ON k8s_namespace_rule_exposures (rule_id);
