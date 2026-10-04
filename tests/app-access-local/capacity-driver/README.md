# Owned session capacity qualification

Run only after the serial withdrawal/day-two matrix and rollback are stable,
with a fresh real native app session. This helper never mutates authority. It
connects only to the fixed owned app at 127.0.0.1:443 using TLS1.3, registered SNI
and the owned CA. It has no environment proxy or certificate bypass.

It requires sixteen positive SSE streams, continuously drains them, checks the
seventeenth is 403, closes one and requires positive replacement within ten
seconds, then closes all clients and requires root 200. Maximum simultaneous
clients is seventeen and the whole run has a thirty-second cancellation bound.
Connection/header/initial-content reads have a three-second deadline. Evidence
must be an exclusive new file in the owned runtime directory and is mode0600;
it contains aggregate outcomes/times only. Session files must be private and
stay inside the same owned directory, without symlinks.

Use `APP_ACCESS_OWNED_PROJECT=tunnex-app-access-aa0-1003` and
`APP_ACCESS_OWNED_CHECKOUT=/Users/pawangupta/tunnex/tests/app-access-local`, then
run `/private/tmp/aa8-capacity-driver --session-file ABS --evidence-file ABS`.
Never put the token on the command line or print its source file.

This proves the session16 admission/release behavior on this application only.
It does not qualify app32/gateway128/global256/callback128, memory, throughput,
fairness or HA. An unchanged authority snapshot and positive replacement are
necessary corroboration: a generic 403 alone does not identify its internal cause.
