-- AI-SEC-1: HTTP inside the WireGuard VPN (the gateway relay route) gets its
-- own switch, so allowing it no longer requires allowing public plaintext.
-- allow_http keeps its meaning (public HTTP) and its saved value. Every
-- installation starts with VPN HTTP on: one that had allow_http on keeps both
-- on, one that had it off gets VPN HTTP on and public HTTP still off.
ALTER TABLE server_ai_transport_settings
    ADD COLUMN allow_vpn_http boolean NOT NULL DEFAULT true;
