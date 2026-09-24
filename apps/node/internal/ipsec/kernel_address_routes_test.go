package ipsec

import (
	"strings"
	"testing"
)

const kernelAddressRoutes = `[{"type":"2","dst":"169.254.10.1","dev":"ipsec-a","table":"255","protocol":"2","scope":"254","prefsrc":"169.254.10.1","flags":[]},{"type":"3","dst":"169.254.10.3","dev":"ipsec-a","table":"255","protocol":"2","scope":"253","prefsrc":"169.254.10.1","flags":[]}]`

func TestKernelInventoryAddressRoutesRemainTyped(t *testing.T) {
	got, e := ParseKernelInventory("net:[1]", []byte(kernelLinksFixture), []byte(kernelAddressRoutes))
	if e != nil {
		t.Fatal(e)
	}
	if len(got.Routes) != 2 || got.Routes[0].Kind != 2 || got.Routes[1].Kind != 3 {
		t.Fatal("kernel address routes hidden")
	}
}
func TestKernelInventoryAddressRoutesRefuseWidening(t *testing.T) {
	for name, raw := range map[string]string{
		"foreign range":   strings.ReplaceAll(kernelAddressRoutes, "169.254.10.", "10.20.0."),
		"wrong table":     strings.Replace(kernelAddressRoutes, `"table":"255"`, `"table":"254"`, 1),
		"wrong protocol":  strings.Replace(kernelAddressRoutes, `"protocol":"2"`, `"protocol":"242"`, 1),
		"wrong source":    strings.Replace(kernelAddressRoutes, `"prefsrc":"169.254.10.1"`, `"prefsrc":"169.254.10.2"`, 1),
		"wrong broadcast": strings.Replace(kernelAddressRoutes, `"dst":"169.254.10.3"`, `"dst":"169.254.10.2"`, 1),
		"wrong scope":     strings.Replace(kernelAddressRoutes, `"scope":"254"`, `"scope":"0"`, 1),
		"gateway":         strings.Replace(kernelAddressRoutes, `"flags":[]`, `"gateway":"169.254.10.2","flags":[]`, 1),
		"metric":          strings.Replace(kernelAddressRoutes, `"flags":[]`, `"metric":0,"flags":[]`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseKernelInventory("net:[1]", []byte(kernelLinksFixture), []byte(raw)); e == nil {
				t.Fatal("unqualified address route accepted")
			}
		})
	}
}
