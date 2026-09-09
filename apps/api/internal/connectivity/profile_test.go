package connectivity

import "testing"

func TestRelayURLValidation(t *testing.T) {
	for _, url := range []string{"turns:relay.example.com:5349?transport=tcp", "turns:10.20.0.1:443?transport=tcp", "turns:[2001:db8::1]:5349?transport=tcp"} {
		if !validRelayURL(url) {
			t.Fatal("rejected relay URL", url)
		}
	}
	for _, url := range []string{"turn:relay.example.com:3478?transport=tcp", "https://relay.example.com", "turns:localhost:5349?transport=tcp", "turns:127.0.0.1:5349?transport=tcp", "turns:169.254.169.254:80?transport=tcp", "turns:relay.example.com:0?transport=tcp", "turns:relay.example.com:5349?transport=udp", "turns:user:secret@relay.example.com:5349?transport=tcp", "turns:relay.example.com:5349?transport=tcp#ignored"} {
		if validRelayURL(url) {
			t.Fatal("accepted unsafe relay URL", url)
		}
	}
}
