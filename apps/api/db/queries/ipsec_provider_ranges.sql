-- name: ListIPsecProviderReservations :many
SELECT 'ipsec_remote'::text AS class, r.cidr::text AS cidr
FROM ipsec_aws_remote_prefixes r WHERE r.org_id = $1
UNION ALL
SELECT 'ipsec_inside'::text, t.inside_cidr::text
FROM ipsec_aws_tunnel_configs t WHERE t.org_id = $1
UNION ALL
SELECT 'ipsec_underlay'::text, (t.aws_outside_ipv4::cidr)::text
FROM ipsec_aws_tunnel_configs t WHERE t.org_id = $1
UNION ALL
SELECT 'ipsec_underlay'::text, (s.customer_outside_ipv4::cidr)::text
FROM ipsec_aws_static_configs s WHERE s.org_id = $1;

-- name: LockProviderRangeOrganization :one
SELECT id FROM organizations WHERE id = $1 AND deleted_at IS NULL FOR UPDATE;

-- name: VersionProviderRangeOrganization :exec
UPDATE organizations SET updated_at = updated_at WHERE id = $1 AND deleted_at IS NULL;
