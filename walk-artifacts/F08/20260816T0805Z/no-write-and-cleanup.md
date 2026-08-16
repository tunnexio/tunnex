# F08 no-write and cleanup evidence

Before two repeated allowed diagnostics, the disposable rows recorded:

- device `updated_at`: `2026-08-16 08:57:51.253753+00`;
- runtime desired/applied: `1/1`;
- rule row MD5: `38aba8033b61400303f399a04e03d354`;
- applied policy hash: `95b678aca708`.

After two repeated GETs the device timestamp, rule MD5, revisions and policy hash were byte-equivalent. Runtime and node observation timestamps advanced through their existing independent reporters, as expected by F08 D1; the evaluator itself did not create a row, revision, wake, push, poll or event. The exact-current PostgreSQL contract also proves full canonical-row equivalence with reporters absent.

Cleanup used released UI destructive copy to delete the one rule/resource and revoke/remove the one active F08 agent. The Ubuntu service, `runtime` interface and the five fixed managed paths were removed. Device Approval was restored to On.

The first cleanup-check correctly exposed that its device count included intentional soft-deleted history. The verifier was narrowed to live rows (`deleted_at IS NULL`) without deleting history. The corrected result was:

```text
devices=0
nodes=0
resources=0
cp_scratch=absent
runtime_interface=absent
vm_scratch=absent
```

Final CP services remained healthy, F08 API/web revision labels stayed exact, schema remained `96|false`, and the existing F07 node/reporter was untouched.
