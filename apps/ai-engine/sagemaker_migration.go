// Compiled into Bifrost's private configuration package. This is a single,
// installation-bound migration from the retired Tunnex OpenAI bridge to its
// native SageMaker provider. Other immutable provider fields stay immutable.
package lib

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/framework/configstore"
	"os"
	"reflect"
	"strings"
)

func tunnexSageMakerMigration(next, old configstore.ProviderConfig, provider schemas.ModelProvider) bool {
	id, err := uuid.Parse(strings.TrimPrefix(string(provider), "custom-"))
	if err != nil || id == uuid.Nil || string(provider) != "custom-"+id.String() {
		return false
	}
	a, b := next.CustomProviderConfig, old.CustomProviderConfig
	if a == nil || b == nil || a.BaseProviderType != "tnx-sagemaker" || b.BaseProviderType != "openai" || a.IsKeyLess || b.IsKeyLess || len(a.RequestPathOverrides) > 0 || len(b.RequestPathOverrides) > 0 {
		return false
	}
	if next.NetworkConfig == nil || old.NetworkConfig == nil || !reflect.DeepEqual(next.NetworkConfig, old.NetworkConfig) {
		return false
	}
	if next.ProxyConfig == nil || old.ProxyConfig == nil || next.ProxyConfig.Type != "http" || old.ProxyConfig.Type != "http" || next.ProxyConfig.URL == nil || old.ProxyConfig.URL == nil || next.ProxyConfig.URL.GetRawRef() != "env.TUNNEX_AI_CUSTOM_PROXY_URL" || old.ProxyConfig.URL.GetRawRef() != "env.TUNNEX_AI_CUSTOM_PROXY_URL" {
		return false
	}
	if next.ProxyConfig.Username != nil || next.ProxyConfig.Password != nil || next.ProxyConfig.CACertPEM != nil || old.ProxyConfig.Username != nil || old.ProxyConfig.Password != nil || old.ProxyConfig.CACertPEM != nil {
		return false
	}
	if next.SendBackRawRequest || next.SendBackRawResponse || next.StoreRawRequestResponse || old.SendBackRawRequest || old.SendBackRawResponse || old.StoreRawRequestResponse {
		return false
	}
	// Only the old, CP-owned connection namespace can be migrated; no unrelated
	// native keys can be relabelled or inherited by this operation.
	for _, k := range old.Keys {
		keyID, e := uuid.Parse(strings.TrimPrefix(k.ID, "tnx-managed-"))
		if e != nil || keyID == uuid.Nil || k.ID != "tnx-managed-"+keyID.String() || !strings.HasPrefix(k.Name, k.ID+"-r") {
			return false
		}
	}
	if a.AllowedRequests == nil || !a.AllowedRequests.ListModels || !a.AllowedRequests.ChatCompletion || !a.AllowedRequests.ChatCompletionStream {
		return false
	}
	// Compare against exactly the restricted set, including false fields.
	expected := &schemas.AllowedRequests{ListModels: true, ChatCompletion: true, ChatCompletionStream: true}
	if !reflect.DeepEqual(a.AllowedRequests, expected) {
		return false
	}
	raw, e := os.ReadFile(os.Getenv("TUNNEX_AI_CUSTOM_ENDPOINTS_FILE"))
	if e != nil || len(raw) > 65536 {
		return false
	}
	var policy struct {
		Endpoints []struct {
			Provider string `json:"provider"`
			URL      string `json:"url"`
		} `json:"endpoints"`
	}
	if json.Unmarshal(raw, &policy) != nil {
		return false
	}
	for _, ep := range policy.Endpoints {
		if ep.Provider == "sagemaker" && ep.URL == next.NetworkConfig.BaseURL {
			return true
		}
	}
	return false
}
