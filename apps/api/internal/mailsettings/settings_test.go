package mailsettings

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

func TestCandidateKeepsSecretAndRefusesDestinationChange(t *testing.T) {
	current := mail.Config{Host: "smtp.example.test", Port: "587", From: "sender@example.test", Username: "sender", Password: "private-marker"}
	in := Update{Revision: 0, Enabled: true, Host: current.Host, Port: 587, From: current.From, Username: current.Username, PasswordAction: "keep"}
	next, err := prepare(current, in)
	if err != nil || next.Password != current.Password {
		t.Fatal("unchanged destination did not preserve password", err)
	}
	in.Host = "different.example.test"
	if _, err = prepare(current, in); err == nil {
		t.Fatal("existing password followed changed destination")
	}
	in.PasswordAction = "replace"
	in.Password = "new-marker"
	if next, err = prepare(current, in); err != nil || next.Password != in.Password {
		t.Fatal("explicit replacement failed", err)
	}
}

func TestViewNeverReturnsSecrets(t *testing.T) {
	view := viewOf(mail.Config{Host: "smtp.example.test", Password: "private-marker"}, 3)
	raw, err := json.Marshal(view)
	if err != nil || strings.Contains(string(raw), "private-marker") || strings.Contains(string(raw), `"password":`) {
		t.Fatal("secret leaked")
	}
	if !view.PasswordConfigured || view.Source != "server" || view.Revision != 3 {
		t.Fatal("missing safe metadata")
	}
}

func TestInvalidSMTPDoesNotBecomeSavedConfiguration(t *testing.T) {
	valid := Update{Enabled: true, Host: "smtp.example.test", Port: 587, From: "sender@example.test", PasswordAction: "clear"}
	for _, modify := range []func(*Update){
		func(v *Update) { v.Host = "smtp.example.test/path" },
		func(v *Update) { v.From = "bad\r\nBCC: other@example.test" },
		func(v *Update) { v.Port = 0 },
		func(v *Update) { v.Port = 465 },
		func(v *Update) { v.PasswordAction = "unknown" },
		func(v *Update) { v.Username = "user\nname" },
	} {
		in := valid
		modify(&in)
		if _, err := prepare(mail.Config{}, in); err == nil {
			t.Fatal("invalid candidate accepted")
		}
	}
}
