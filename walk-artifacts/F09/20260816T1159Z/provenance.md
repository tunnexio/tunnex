# F09 AWS DEV provenance

- Walk date: 2026-08-16 UTC.
- Story branch content: `4e09c9378e193cd6f8b2db901d012b5533396241`.
- API image: `tunnex-api:f09-4e09c93-amd64`; revision label exactly the story
  SHA; healthy; restart count zero.
- Web image: `tunnex-web:f09-4e09c93-amd64-fixed`; revision label exactly the
  story SHA; healthy; restart count zero.
- Existing nginx and F07 node images remained unchanged and healthy.
- PostgreSQL ledger: version 97, dirty false.
- Rollback bundle:
  `/home/ubuntu/f09-rollback-4e09c93-20260816T1712IST`, mode 0700; contained
  mode-0600 database/config/image inventory and verified SHA256SUMS.
- Final API/web/nginx post-start severe-log scan: zero panic, fatal, migration
  dirty/failure, permission-denied or segmentation-fault matches.

Three deployment-harness defects were corrected before acceptance traffic: the
historical AI compose override was restored after an initial omission; archive
source permissions were normalized before the fixed web image build; unchanged
nginx was recreated once to resolve the new API container address. Database
content was preserved and schema remained clean throughout recovery. None is
counted as product acceptance evidence.

No cookie, bootstrap credential, private key, raw configuration, token hash or
password appears in this artifact.
