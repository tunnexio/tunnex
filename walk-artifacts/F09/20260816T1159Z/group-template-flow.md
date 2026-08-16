# F09 group/template live flow

Two disposable active agents were added to one disposable group. Template v1
contained one resource destination.

```text
resources=created
group_members=2
template_version=1
preview_v1=agents:2,created:1,gateways:1,added:2
preview_no_write=pass
stale_preview=refused_409
apply_v1=pass|idempotent_replay=true
membership_change=rule_id_stable
replace_v2=created:1,removed:1,agents:2
destructive_impact=resource_1_and_group_refused
template_archive=assignment_preserved
assignment_removed=pass|group_archived=pass|opt_in_restored=false
combined_api_walk=pass
```

Preview performed no assignment, policy-rule or audit write. Apply used the
preview digest and created one ordinary assignment-owned rule. Removing and
restoring a member retained its rule ID. A stale digest refused before
mutation. Version replacement retained immutable v1/v2 history and converged
to one active assignment. Assignment removal deleted its generated binding;
archiving preserved history without retaining active access.
