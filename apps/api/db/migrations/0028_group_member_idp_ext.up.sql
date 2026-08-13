-- S7.5.2 (review fold, D3 delete-sweep): record the directory external id on a synced membership so
-- that when a member is REMOVED from a group the reconciler can resolve whether they were deleted /
-- disabled upstream (→ full sweep) or merely moved out of this group (→ keep the account). Legacy
-- rows stay NULL and get a group-removal only.
ALTER TABLE group_members ADD COLUMN idp_external_id text NULL;
