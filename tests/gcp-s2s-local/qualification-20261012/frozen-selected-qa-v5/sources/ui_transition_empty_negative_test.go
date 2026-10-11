package main

import (
 "encoding/json"
 "os"
 "strings"
 "testing"
)

func uiTransitionBase(t *testing.T) capture {
 t.Helper()
 b, err := os.ReadFile("/private/tmp/provider-gcp-cloud-expiry-observer-5121dc33-actual-measured-callbacks-v1/poststart-8cdf4b98b51a437fb7cb7626b0ac3696-guard-before-1.json")
 if err != nil { t.Fatal(err) }
 var c capture
 if json.Unmarshal(b, &c) != nil { t.Fatal("capture decode") }
 if err := verifyTransitionEmpty(c); err != nil { t.Fatal("actual baseline must qualify", err) }
 return c
}
func uiChangeNFT(t *testing.T, c *capture, expected bool, change func([]any) []any) {
 t.Helper()
 raw := []byte(c.Actual)
 if expected { raw = []byte(c.Expected.ExpectedJSON) }
 d, err := decode(raw); if err != nil { t.Fatal(err) }
 rows, ok := d["nftables"].([]any); if !ok { t.Fatal("rows") }
 d["nftables"] = change(rows)
 b, err := json.Marshal(d); if err != nil { t.Fatal(err) }
 if expected { c.Expected.ExpectedJSON = string(b) } else { c.Actual = b }
}
func uiNonemptySet(t *testing.T, rows []any) []any {
 t.Helper()
 for _, r := range rows {
  set := object(object(r)["set"])
  if set != nil && set["name"] == lease { set["elem"] = []any{map[string]any{"elem": map[string]any{"val": "10.70.0.10", "expires": 0}}}; return rows }
 }
 t.Fatal("canonical lease set not found"); return nil
}
func TestUITransitionEmptyRejectsForeignAndUnknown(t *testing.T) {
 cases := []struct{name string; mutate func(*capture)}{
  {"foreign-source", func(c *capture){c.Source = strings.Repeat("0",40)}},
  {"foreign-cid", func(c *capture){c.Container = strings.Repeat("0",64)}},
  {"foreign-namespace", func(c *capture){c.After = "net:[1]"}},
  {"foreign-interface", func(c *capture){for _,l := range c.Links {var n string; _=json.Unmarshal(l["ifname"],&n); if n=="txe936e4aecebb" {l["ifindex"]=json.RawMessage("21");return}};t.Fatal("interface")}},
  {"revision", func(c *capture){c.Expected.Revision++}},
  {"owner-digest", func(c *capture){c.Expected.Digest=strings.Repeat("0",64)}},
  {"actual-nonempty-zero-expiry",func(c *capture){uiChangeNFT(t,c,false,func(r []any)[]any{return uiNonemptySet(t,r)})}},
  {"expected-nonempty-zero-expiry",func(c *capture){uiChangeNFT(t,c,true,func(r []any)[]any{return uiNonemptySet(t,r)})}},
  {"separate-live-element",func(c *capture){uiChangeNFT(t,c,false,func(r []any)[]any{return append(r,map[string]any{"element":map[string]any{"family":"inet","table":"tunnex_ipsec","name":lease,"elem":[]any{"10.70.0.10"}}})})}},
  {"missing-permanent-drop",func(c *capture){uiChangeNFT(t,c,false,func(r []any)[]any{for i,x:=range r {rule:=object(object(x)["rule"]); if rule!=nil {b,_:=json.Marshal(rule["expr"]);if strings.Contains(string(b),"\"drop\""){return append(r[:i],r[i+1:]...)}}};t.Fatal("drop");return nil})}},
  {"extra-unknown-authority",func(c *capture){uiChangeNFT(t,c,false,func(r []any)[]any{return append(r,map[string]any{"rule":map[string]any{"family":"inet","table":"tunnex_ipsec","chain":"forward","expr":[]any{map[string]any{"accept":nil}}}})})}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){c:=uiTransitionBase(t);tc.mutate(&c);if verifyTransitionEmpty(c)==nil {t.Fatal("invalid capture admitted")}})}
}
