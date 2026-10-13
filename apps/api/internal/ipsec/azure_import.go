package ipsec

import (
	"bytes"
	"encoding/json"
	"io"
)

// ImportAzureConfiguration accepts the documented Tunnex JSON interchange,
// not Azure ARM exports or vendor scripts. Secret-bearing input is never logged.
func ImportAzureConfiguration(raw []byte) (StaticConfig, error) {
	if len(raw) == 0 || len(raw) > 65536 || !azureUniqueJSON(raw) {
		return StaticConfig{}, configError("import_invalid", "configuration", 0)
	}
	var wire struct {
		ProfileID              string         `json:"profile_id"`
		Azure                  *AzureContract `json:"azure"`
		BGP                    *BGPConfig     `json:"bgp"`
		Mode                   string         `json:"mode"`
		CustomerOutsideAddress string         `json:"customer_outside_address"`
		LocalPrefixes          []string       `json:"local_prefixes"`
		RemotePrefixes         []string       `json:"remote_prefixes"`
		Tunnels                []struct {
			OutsideAddress        string `json:"outside_address"`
			InsideCIDR            string `json:"inside_cidr"`
			CustomerInsideAddress string `json:"customer_inside_address"`
			CloudInsideAddress    string `json:"cloud_inside_address"`
			PSK                   string `json:"psk"`
		} `json:"tunnels"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&wire) != nil {
		return StaticConfig{}, configError("import_invalid", "configuration", 0)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return StaticConfig{}, configError("import_invalid", "configuration", 0)
	}
	c := StaticConfig{ProfileID: wire.ProfileID, Azure: wire.Azure, BGP: wire.BGP, Mode: wire.Mode, CustomerOutsideAddress: wire.CustomerOutsideAddress, LocalPrefixes: wire.LocalPrefixes, RemotePrefixes: wire.RemotePrefixes}
	for _, t := range wire.Tunnels {
		c.Tunnels = append(c.Tunnels, StaticTunnel{OutsideAddress: t.OutsideAddress, InsideCIDR: t.InsideCIDR, CustomerInsideAddress: t.CustomerInsideAddress, CloudInsideAddress: t.CloudInsideAddress, PSK: t.PSK})
	}
	if err := ValidateAzureConfig(c); err != nil {
		return StaticConfig{}, err
	}
	return c, nil
}

// AzurePeerSettings is a key-free review projection. It contains no command,
// credential, automatic provisioning or attestation of actual Azure state.
type AzurePeerSettings struct {
	Slot            int    `json:"slot"`
	OutsideAddress  string `json:"outside_address"`
	LocalBGPAddress string `json:"local_bgp_address,omitempty"`
	AzureBGPAddress string `json:"azure_bgp_address,omitempty"`
	IKEEncryption   string `json:"ike_encryption"`
	IKEIntegrity    string `json:"ike_integrity"`
	DHGroup         string `json:"dh_group"`
	IPsecEncryption string `json:"ipsec_encryption"`
	IPsecIntegrity  string `json:"ipsec_integrity"`
	PFSGroup        string `json:"pfs_group"`
}

func GenerateAzurePeerSettings(c StaticConfig) ([]AzurePeerSettings, error) {
	if err := ValidateAzureConfig(c); err != nil {
		return nil, err
	}
	out := make([]AzurePeerSettings, len(c.Tunnels))
	for i, t := range c.Tunnels {
		out[i] = AzurePeerSettings{Slot: i + 1, OutsideAddress: t.OutsideAddress, IKEEncryption: "AES256", IKEIntegrity: "SHA256", DHGroup: "DHGroup14", IPsecEncryption: "AES256", IPsecIntegrity: "SHA256", PFSGroup: "PFS2048"}
		if azureBGP(c.ProfileID) {
			out[i].LocalBGPAddress = t.CustomerInsideAddress
			out[i].AzureBGPAddress = t.CloudInsideAddress
		}
	}
	return out, nil
}

func azureUniqueJSON(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) bool
	value = func(depth int) bool {
		if depth > 16 {
			return false
		}
		token, err := d.Token()
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return true
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return false
				}
				seen[name] = true
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim('}')
		case '[':
			for d.More() {
				if !value(depth + 1) {
					return false
				}
			}
			end, err := d.Token()
			return err == nil && end == json.Delim(']')
		default:
			return false
		}
	}
	if !value(0) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
