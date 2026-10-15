# Import an AWS Generic VPN download

In **Site-to-site → IPsec → New connection**, choose AWS and upload the **Generic `.txt`** configuration downloaded for the existing AWS VPN connection. The upload fills both tunnel endpoints, inside addresses and PSKs, detects static or BGP routing, and fills the BGP ASNs when present. You can still enter or correct settings manually.

The importer accepts a nonempty text file up to 64 KiB with two complete IPv4 tunnel sections. AWS XML and device-specific scripts are not supported. Malformed, incomplete or ambiguous files are rejected without displaying their contents. Only the current in-memory form receives the parsed settings; the raw file is not uploaded or persisted. Credentials stay masked and leave the form through the existing configuration check and encrypted credential storage path when saving. Cancelling or changing the signed-in organization/user discards the draft.

Choose the local Site and gateway, select approved local ranges, and enter the exact permitted remote VPC/TGW CIDRs. The download does not grant access or supply these scopes; sample routes and `0.0.0.0/0` selectors are never imported as application ranges. For BGP, an empty Router ID defaults to the customer public IPv4 address and remains editable. Keep it stable and unique; an existing Router ID is preserved. The existing maximum-prefix limit defaults to 64 per peer.

AWS attachment and routing are separate choices:

| Existing AWS attachment | Routing represented by the import |
| --- | --- |
| Virtual Private Gateway (VGW) | IPv4 static or BGP |
| Transit Gateway (TGW) | IPv4 static or BGP |

The Tunnex profile is attachment-neutral. A Generic file can use “Virtual Private Gateway” labels for a TGW connection, so the importer does not infer or provision the attachment. Tunnex retains its existing two-public-IPv4-endpoint, two-APIPA-/30 contract. BGP requires distinct ASNs: customer and AWS private ASNs (64512–65534 or 4200000000–4294967294), or AWS legacy ASN 7224. Other public ASNs, IPv6, certificate authentication and IKEv1 are outside this importer/runtime contract. Parser coverage of VGW/TGW formats is not live qualification of every AWS topology.

Review the imported fields before saving. Tunnex uses **IKEv2 with PSK; IKE and ESP AES256-CBC, SHA256 and DH/PFS group 14 (MODP2048)**. AWS Generic downloads may describe minimum examples such as AES128/SHA1/DH2. The review calls out that difference; it does not import those algorithms or establish what the live AWS tunnel permits. Even a matching template does not prove negotiated compatibility.

**Save disabled connection** is available without a crypto acknowledgment. To choose **Create and connect…**, first verify both AWS tunnels permit the required Tunnex profile and check the acknowledgment. This saves the disabled connection, clears the secret draft and opens the existing final **Enable connection** confirmation. That confirmation rechecks gateway/provider readiness and uses the saved revision. A BGP gateway must report fresh BGP support. Failed or uncertain activation leaves the saved connection available; close and refresh before retrying enable, rather than creating another connection.

Saving, acknowledging compatibility or requesting enable does not mean Connected. Check reported tunnel health, BGP status/routes where applicable, and permitted application traffic. Existing access policies still determine which traffic can pass. The import does not change AWS routes, security groups, tunnel options, DNS or attachment configuration.
