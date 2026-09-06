# B: AWS account-level NLB refusal

2026-09-05, source `61ecc5fec4e5a971faaf9b1c65ccdc7b3b4cd8c1`.
The separate planned gateway B uses worker 10.240.10.121, release
`tunnex-s205-b`, the same digest-pinned candidate and private charts.
Native read-only plan completed 15:34:31.330Z, exit 0.

At 15:35:37Z, the ordinary load-balancer controller CreateLoadBalancer call
returned HTTP 400, `OperationNotPermitted`:

> This AWS account currently does not support creating load balancers.
> For more information, please contact AWS Support.

AWS request ID `acfdf0b1-e9cc-4d0b-a323-63f9c36f8abe`; repeated identical
refusals observed through 15:35:55Z. This is distinct from the A2 IAM resource
name 403. B's Pod was Running with zero restarts, but not Ready; its Service
had no external endpoint. The bounded native install was still active at this
observation; do not infer a terminal result from this snapshot.

No Service mutation, permission wildcard expansion, controller restart, or
provider substitution was used. NLB qualification is blocked on the AWS
restriction. A NodePort walk is a separate endpoint-design disposition, not
evidence satisfying the NLB path. No leg is advanced by this failure.

Read-only account limits at 15:37:17Z returned NLB maximum 50 and target-group
maximum 3000; describe-load-balancers returned no load balancers. Therefore the
observed refusal is not explained by exhausting the displayed NLB count limit.
