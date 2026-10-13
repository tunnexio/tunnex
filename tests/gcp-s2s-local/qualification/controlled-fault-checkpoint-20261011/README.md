# Controlled fault checkpoint

The initial source-0249 one-peer run remained false. Its later native observation showed the secondary CHILD and Classic CHILD with SAD 4 while the owned HA route was absent. The strict driver refused before accepting failover traffic. Cleanup was independently verified: all owned filters were withdrawn and the temporary clsact was removed.

A separate post-fault fresh preparation and all four full production guard checks passed. HA and Classic TCP/UDP restoration packets also passed. These are later restoration checkpoints, not a successful original fault run or a continuous downtime measurement.

The six-rule helper installed and cleaned up successfully in a transient isolated network namespace, with zero packet sends, zero host mutations, and unchanged host topology. That result qualifies installation/cleanup grammar only; it is not actual two-peer packet-loss acceptance. The separate child-rekey archive preserves its original immediate false result and later recovery proof.

Only public allowlisted projections, full successful verifier results, and minimal packet observations are retained here. Raw NFT, journals, logs, credentials, and keys are excluded.
