package sandboxes

import (
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestDelegationBounds(t *testing.T) {
	now := time.Now()
	d := Delegation{OrgID: uuid.New(), OwnerID: uuid.New(), MachineID: uuid.New(), TemplateID: uuid.New(), MaxTTLSeconds: 900, MaxActive: 1, MaximumScope: []Scope{{CIDR: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}}, ExpiresAt: now.Add(time.Hour)}
	if err := d.validate(now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Delegation){func(v *Delegation) { v.MaxTTLSeconds = 901 }, func(v *Delegation) { v.MaxActive = 3 }, func(v *Delegation) { v.OwnerID = uuid.Nil }, func(v *Delegation) { v.ExpiresAt = now }, func(v *Delegation) { v.MaximumScope[0].CIDR = "0.0.0.0/33" }} {
		v := d
		v.MaximumScope = append([]Scope{}, d.MaximumScope...)
		change(&v)
		if v.validate(now) == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	in := CreateInput{TemplateID: d.TemplateID, TTLSeconds: 900, Requested: d.MaximumScope}
	if err := d.admit(in); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CreateInput){func(v *CreateInput) { v.TTLSeconds = 901 }, func(v *CreateInput) { v.TemplateID = uuid.New() }, func(v *CreateInput) { v.Requested = []Scope{{CIDR: "0.0.0.0/0", Protocol: "any"}} }, func(v *CreateInput) { v.SelectedSkills = []SkillSelection{{RevisionID: uuid.New()}} }} {
		v := in
		change(&v)
		if d.admit(v) == nil {
			t.Fatal("escalation accepted")
		}
	}
}
