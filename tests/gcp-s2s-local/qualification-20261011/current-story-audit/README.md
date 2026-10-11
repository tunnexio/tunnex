# Current eleven-story acceptance audit — draft

Audit base: ROOT8b790e8a558cc0205f47b844a5148735f023c96d. This is a documentation-only criterion audit, not a new test run or final signoff. Running source372 is the diagnostic baseline; source fbf3 / image523 is built, not accepted as a running replacement here. CI and production publication are separate.

`Implemented` identifies an existing source slice. `Local` and `Live` identify demonstrated acceptance slices, not an assertion that every criterion in the original row is complete. A full-story numerical percentage is deliberately not inferred from packet successes. The eleven original story rows are the denominator; final per-story signoff has not been recorded.

| Story | Implemented | Local acceptance evidence | Owned live acceptance evidence | Remaining criterion / audit limit |
|---|---|---|---|---|
| GCP-0 | HA/Classic profile/topology and ownership contract | Decision/profile contract documented | Owned cloud resources and exact topology/configuration readbacks | No single formal all-assumptions acceptance receipt; contract remains the supported lab scope |
| GCP-1 | Common BGP/static/DNS foundations imported | Provenance and focused shared-path tests recorded in EPIC qualification checkpoints | Both provider paths exercised through normal API and owned gateway | Source preservation qualifies the import; this is not CI or publication acceptance |
| GCP-2 | Explicit profiles, disabled save, encrypted rotation, admission/RBAC | API/schema/role regressions and disposable PostgreSQL qualification | Disabled saves/normal Enable; isolated never-applied CAS fixture; actual old-key refusal/new-key recovery | Both API editions are locally tested; no broader customer-deployment coverage inferred |
| GCP-3 | Existing form/review/setup and GCP fields | Actual isolated owner/admin/member desktop/mobile browser acceptance | Browser proofs use the owned local control plane and real configured lab views | Role/UI acceptance passed within recorded routes; human-owned CAS tabs stayed untouched |
| GCP-4 | Profile-aware IKEv2/strongSwan/VICI/XFRM | Classic cardinality, ownership/refusal and Linux readback regressions | Actual Classic1/HA2, strict policy/native inventory, old-key authentication refusal and coexistence | Wrong-proposal/old-node refusal are local regressions; do not invent additional live fault tests |
| GCP-5 | BGP exact-prefix and Classic static routing | Import/export/leak/limit/withdrawal regression qualification | HA established/owned routes, Classic static return path, alternate path and restored routes | Deliberate route-leak/max-prefix live injection not established by successful route/traffic checkpoints |
| GCP-6 | Directional grants and finite lease authority | Lease/spoof/revocation and preservation tests | Real TCP/UDP allow/deny and temporary90s expiry denial; normal baseline restoration | Live expiry is bounded; no continuous availability guarantee, or unrecorded live spoof case |
| GCP-7 | Health, individual/both tunnel loss and recovery | One/both-path model and strict guard/native regressions | ONEv5 retained tuple/same-socket checkpoints plus fresh traffic; BOTH loss HA deny/Classic allow and recovery, exact cleanup | Continuous fresh/existing-flow downtime, asymmetric exhaustive scenarios and SLA are not proven. This entire story remains partial despite accepted checkpoints |
| GCP-8 | PSK/Disable/Delete/Enable, CAS, restart and rekey | Lifecycle/revision/cleanup regressions | Old key rejected/new key recovered; finalized CAS; same-enrollment restart; controlled CHILD rekey/later recovery; ONE/BOTH cleanup | Accepted named lifecycle slices; partial retry guarantees beyond recorded attempts are not generalized |
| GCP-9 | Authenticated private resolver context and normal generations | Strict resolver/profile/consensus/clock and wire parser tests | HA A/CNAME/NX; genuine explicit EDNS TC→TCP100A; historical Classic normal generations; matched current diagnostic mailbox | Current automatic Classic samples mixed; final successor DNS qualification pending. No FQDN-only IPsec app authorization, no hidden ordinary-grant conversion |
| GCP-10 | Integrated source-bound qualification, MTU, role/mobile | Local tests and immutable source/build receipts | Controlled MTUv7 normal/lowered fragmented round trips and1MiB both directions; roles/CAS; native/payload checkpoints | Final current-source DNS acceptance still pending. CI, main merge, production publication and general production availability remain separate |

Exact evidence anchors:
- [Role/browser](../../qualification-20261010/isolated-role-browser-20261011/README.md), [CAS](../../qualification-20261010/isolated-cas-accepted-20261011/README.md), [PSK recovery](../../qualification-20261010/classic-psk-recovery-checkpoint-20261011/README.md).
- [ONE/BOTH controlled faults](../0249-ha-one-both-faults/README.md), [CHILD rekey](../../qualification/child-rekey-20261011/README.md).
- [MTU](../../qualification-20261010/controlled-mtu-20261011/README.md), [EDNS/mailbox boundary](../0249-edns-mailbox-checkpoint/README.md), [372 bounded diagnostics](../372-diagnostic-baseline/README.md).
- API/transport/import local qualifications and historical failures remain in the EPIC's chronological checkpoints; this audit does not relabel them as current live evidence.

No defensible fully accepted-story percentage is asserted. An eventual count must resolve each remaining criterion or explicitly amend its acceptance scope through review, rather than silently treating a slice as the entire story.

## Owned forwarding incident and recovery

The local API remained healthy while the owned first reverse SSH hop was absent; bastion loopback48083/48446 therefore had no listeners. ROOT restored that hop using the existing transport. Subsequent source372 native, all four full production guards before/after, and fresh HA/Classic TCP/UDP packets passed in10.384seconds. This was external forwarding recovery without a product code repair. Earlier DNS after-proof ACTIVE refusals remain separate and are not explained by this incident.

The fbf successor is built and source-qualified, but STOP was rejected before execution by automatic approval review and explicit outage approval remains pending. The current source372 gateway was not stopped or replaced. Successor CID/interface measurements remain blocked; no successor readiness, publication, continuous availability, or overall completion percentage is claimed.

Public scalar results and exact original artifact hashes (raw native tables, logs, environment and credentials omitted):

```json
{
  "scope": "bounded forwarding recovery; no DNS refusal causality or successor deployment claim",
  "receipts": [
    {
      "artifact": "001-native-before.json",
      "sha256": "95276618a5f1efb453a8dede234ad16fa6c8b72e5e3018aed139bf1c92a164f0",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      "artifact": "003-guard-before-ha-tcp.json",
      "sha256": "04509f3a7486ba43d4bb30a0177738f15d9ea1728c0041ae4cd24eeff6c1e6aa",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "81504d2577c84127abed717ea81d40be8a3588d6579feda6ada2284482d7968c"
      }
    },
    {
      "artifact": "004-guard-before-ha-udp.json",
      "sha256": "e76a0a615cca135c0f74d780825dfb4b702577b5b68d2196621b48afd4777f7b",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "5993cc246e69168dc4142a9900759da14c36e0d330c423e1261c6acd25b2905e"
      }
    },
    {
      "artifact": "005-guard-before-classic-tcp.json",
      "sha256": "2cfe182d5fc9c63485e6a0fdf6506d7b13a0f7d34a8916b33688da8c3d4af91e",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "f66d3eb3e843755b7ec39f26b622fc42bc119d072a07086bb877003803f84533"
      }
    },
    {
      "artifact": "006-guard-before-classic-udp.json",
      "sha256": "b20434cb8b8e8aece2657ec569d275234f1b4427ce0ad776ca1d61a5e0863672",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "8dbd45180eb6342e7ac2715438d8faa1e6fc9cd064e29f544896923c79e00f06"
      }
    },
    {
      "artifact": "007-packet-ha.json",
      "sha256": "95276618a5f1efb453a8dede234ad16fa6c8b72e5e3018aed139bf1c92a164f0",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      "artifact": "008-packet-classic.json",
      "sha256": "95276618a5f1efb453a8dede234ad16fa6c8b72e5e3018aed139bf1c92a164f0",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      "artifact": "009-native-after.json",
      "sha256": "95276618a5f1efb453a8dede234ad16fa6c8b72e5e3018aed139bf1c92a164f0",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
      }
    },
    {
      "artifact": "011-guard-after-ha-tcp.json",
      "sha256": "2f98805bf60a3003a32a86e391276f649acd5556fee559e196efe70df0b3d74e",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "834a3992e2d10ef9140c64e732fbe7216bce452e0ecfae576362052b5b903199"
      }
    },
    {
      "artifact": "012-guard-after-ha-udp.json",
      "sha256": "c96c1c86931b7f85f152c77669fea3817a772bd1facfbadd4163dbaaeec29a9a",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "80cd4a7a241453e246b1f96e75be15e573e797d0db6e2949baca42082bb2ef81"
      }
    },
    {
      "artifact": "013-guard-after-classic-tcp.json",
      "sha256": "357dc6b8edc385f57bf687e193262125edd2797983e9c980af185d8547aecca8",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "1c982d29fc8f7df9c5e60d4c64ae3dc77fbeb9758e4ec90a75c960a3ccf3652f"
      }
    },
    {
      "artifact": "014-guard-after-classic-udp.json",
      "sha256": "46b121b928575dc6ea7c817701fc58aaaccffc769384bfea7be3fedb7c9347c8",
      "result": {
        "completed": true,
        "returncode": 0,
        "error_type": null,
        "stdout_sha256": "e97d9cdad84604bcc3e164dba8826bd4f99d282a52e2e24d734ddcac7c1deaec"
      }
    },
    {
      "artifact": "packet-classic.json",
      "sha256": "f4edd304d09022cbe00f5136c5af9221221eb0e4409a9d4d3ac33170e30cc721",
      "result": {
        "completed": true,
        "accepted": true
      }
    },
    {
      "artifact": "packet-ha.json",
      "sha256": "3819dec907e9039bf2ea1db86024af415de859ffc7796b1277718e43e01fd008",
      "result": {
        "completed": true,
        "accepted": true
      }
    },
    {
      "artifact": "result.json",
      "sha256": "e191d0424d4dcde107689cfbce6f3e97427d0285b24e772aab5d36b2815eb2a8",
      "result": {
        "completed": true,
        "elapsed_seconds": 10.383656708000018,
        "source": "372e43ac935591f287aae02b023bba8de1b43a66",
        "container": "2a5ef7b1ffe6c3c4822aa37f3fb673606019fbc9724f3d2a160e2b56157b6a01",
        "api_checkpoint_sha256": "cfb8f49050da9c98c5979f608b46ab2cfc34f4445540bfa338b2ff0ec8e4cf7a"
      }
    }
  ]
}
```

The independent normal API read also accepted all three generations and preserved the configured baseline, with zero mutations. Local fbf build qualification and native overlay construction are separate from its unexecuted STOP. Staged qualifier delivery is bound below to the local completed-tool-result binder; the qualifier was staged, not executed, and the binder is not a fresh remote reobservation.

```json
[
  {
    "artifact": "actual-api-restored-forward-v3.jsonl",
    "sha256": "b0d3e9c5e2ca501ba7bbcd8f80adc6c6bcffbdb34df3716587a86f090d9fed37",
    "public_result": {
      "completed": true,
      "generation_accepted": true,
      "accepted_by_resource": {
        "01a127b1-ba33-7941-9bdf-58dbaca5ab12": true,
        "01a127b1-ba4c-74bf-bbb5-38339ea6c516": true,
        "01a127b1-ba5d-7b7d-a885-4230f29ee67b": true
      },
      "configured_count": 7,
      "baseline_preserved": true,
      "mutations": 0
    }
  },
  {
    "artifact": "BUILD-RECEIPT.json",
    "sha256": "a95c48c73764dedf5964b2f930039fb7917550883804fcfb0720432c046bbfba",
    "public_result": {
      "source_commit": "fbf3b87b1babc60ee21bb463f93ab0a121bc9f03",
      "source_tree": "97753e0e49da8bda601209b549820bcab74217f2",
      "apps_node_tree": "758281af7c9bbf12f32e3bc1e1b4de676488c661",
      "source_clean": true,
      "target": "linux/amd64",
      "CGO_ENABLED": "0",
      "GOAMD64": "v1",
      "qualification": {
        "local_crosscompile": "PASS",
        "focused_combined_race": {
          "ipsec_seconds": 3.358,
          "fqdnrpc_seconds": 1.976,
          "result": "PASS"
        },
        "live_execution": false
      }
    }
  },
  {
    "artifact": "receipt.json",
    "sha256": "5dc2af884ccf0485866241de55e0567be36824321a840a7bb2ceb0d4be7fd823",
    "public_result": {
      "image": "sha256:523c28ba5ab005c40b3af4b75ff3c642f549c9e12ed12922cc263b808da1c14a",
      "base": "sha256:15df7baa80287f2f4ffa614886c854929063c9187090084c7b3fc085448eb5d6",
      "node_sha256": "b1b0fc5053c79f57e0a1a2be0ecc82e86a58f44084c62c2d5ad0815bed16bfa1",
      "recipe_sha256": "ee4e4840c0ae5ea77811d94ba2f0cec55444f909c355a78f398d1565b872405a",
      "source": "fbf3b87b1babc60ee21bb463f93ab0a121bc9f03",
      "status": "node-only-native-overlay-content-pass"
    }
  }
]
```

Read-only successor preflight binds original SHA `f49b9c04f4d0d87380d84522ce48a98f5a2424c7825b5b0e6a244ae2fe18eede` and the following public source/image/policy evidence fields; native topology and private launch configuration are omitted:

```json
{
  "accepted_policy_evidence_sha256": "e191d0424d4dcde107689cfbce6f3e97427d0285b24e772aab5d36b2815eb2a8",
  "new_image": "sha256:523c28ba5ab005c40b3af4b75ff3c642f549c9e12ed12922cc263b808da1c14a",
  "source": "fbf3b87b1babc60ee21bb463f93ab0a121bc9f03"
}
```

Local ownership/tool-result binders (exact SSH command omitted; no fresh remote read implied):

```json
[
  {
    "artifact": "actual-fbf-staging-and-rejection-local-v1.json",
    "sha256": "199a8fbf8d38a88486cf1e63700c8fd6dd7b6c4aafb4454f8a63e99970ef7228",
    "public_result": {
      "source": "fbf3b87b1babc60ee21bb463f93ab0a121bc9f03",
      "image": "sha256:523c28ba5ab005c40b3af4b75ff3c642f549c9e12ed12922cc263b808da1c14a",
      "retained_gateway_source": "372e43ac935591f287aae02b023bba8de1b43a66",
      "scope": "local record of actual completed tool results; no fresh remote reobservation or authority",
      "staging": {
        "both_hop_sha256": "67d84c8f1ce90a2501a9e4f399f6768ee1abc2787dee72244abdd2e007473ab7",
        "exec_session_id": 6932,
        "executed": false,
        "exit_code": 0,
        "gateway_preflight_sha256": "f49b9c04f4d0d87380d84522ce48a98f5a2424c7825b5b0e6a244ae2fe18eede",
        "staged": true,
        "stager_source_sha256": "211801a75834d7b93f295c46c10b32f861e50f97bc8ebb7e5c88ac06b2e272ff"
      },
      "stop": {
        "action": "normal stop of owned GCP gateway for final DNS source cutover",
        "attempted": false,
        "reason": "Exact gateway stop and traffic interruption lacked explicit human approval according to reviewer",
        "tool_result": "CreateProcess rejected by automatic approval review before execution",
        "user_approval_question_pending": true
      }
    }
  },
  {
    "artifact": "actual-restored-forward-ownership-v1.json",
    "sha256": "e533648b45796dd63fb417db0addcfcd7774a473ed4e0fb68a065d1e83afb093",
    "public_result": {
      "completed": true,
      "session_id": 14444,
      "restored_missing_bastion_loopback_ports": [
        48083,
        48446
      ],
      "local_target_ports": [
        38083,
        38446
      ],
      "scope": "owned GCP test CP reverse forward only; no public listeners or cross-chat processes changed",
      "owned_process_ids": [
        95848
      ]
    }
  }
]
```

## Current fbf checkpoint

The explicitly approved normal replacement now runs fbf source/image523/CID3ee. [The source-bound checkpoint](../fbf-approved-cutover-checkpoint/README.md) records fresh strict native/app+DNS guards and HA/Classic payload, plus individual Classic and HA app/alias/NX wire cases and Classic EDNS1232 TC→TCP. The earlier372/rejection records remain historical. Fresh normal API automatic generation did not accept alias; it is not upgraded by successful manual wire cases. The eleven implemented components are not eleven fully accepted stories. Remaining routing-negative, directional and complete current-generation criteria, CI and publication remain distinct.
