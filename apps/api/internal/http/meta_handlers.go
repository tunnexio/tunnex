package http

import (
	"context"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"time"

	"github.com/go-chi/chi/v5/middleware"

	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/enterprise"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/policyspec"
)

// editionName is what `/meta` reports, and it is READ FROM THE LICENCE.
//
// ⛔ IT WAS A CONSTANT, AND THE CONSTANT SAID "open". S12.1 collapsed the build-tag split: `34004a72`
// deleted `edition_enterprise.go` (`//go:build enterprise`, `Name = "enterprise"`) and left ONE definition
// — `const Name = "open"`. From that commit until this one, **every deployment reported itself as open, on
// any licence**, because no code path could return anything else.
//
// ⚠ THAT WAS NOT A COSMETIC DEFECT. Eleven web files gate on `meta.edition` (`policyview`, `usersview`,
// `domainview`, `idpsyncview`, `sitesview`, `lib/edition.ts`…) and render an upsell or an absence when it
// is not "enterprise". So a customer could install a valid Growth key, have the API correctly grant
// multi_org, SSO and IdP sync — and see upsell cards on every screen that reaches them.
//
// > ## ⛔ **THE LICENCE UNLOCKED IT, THE API SERVED IT, AND THE UI WOULD NOT SHOW IT.**
//
// ⭐ AND THE GRACE LADDER FALLS OUT CORRECTLY RATHER THAN NEEDING A CASE. `Evaluate` keeps the licensed
// tier through the whole 90-day grace and only drops to Community once lapsed — so during grace the UI
// keeps working, and after it the surfaces close on their own. No expiry logic lives here.
func (s apiServer) editionName() string {
	if s.licence.Evaluate(time.Now()).Tier == licence.TierCommunity {
		return enterprise.Name // "open" — the unlicensed tier's name, now used ONLY for that
	}
	return "enterprise"
}

// GetMeta returns public deployment metadata so the SPA can gate edition-only UI
// (hide SSO without a licence) from one bundle — no build-time web fork. SSO
// providers are advertised only when the SSO port is wired.
func (s apiServer) GetMeta(ctx context.Context, _ api.GetMetaRequestObject) (api.GetMetaResponseObject, error) {
	// ⚠ UNAUTHENTICATED, like everything else here, and that is safe: "this deployment cannot send mail"
	// is not a secret — it is a fact any visitor discovers the moment a reset email does not arrive.
	smtp := s.smtpConfigured
	providers := []api.MetaSsoProviders{}
	connections := []struct {
		Id       uuid.UUID                      `json:"id"`
		Name     string                         `json:"name"`
		Provider api.MetaSsoConnectionsProvider `json:"provider"`
	}{}
	if adapter, ok := s.sso.(*ssoAdapter); ok && adapter.pool != nil {
		q := sqlc.New(adapter.pool)
		for _, provider := range []string{"google", "microsoft"} {
			orgs, err := q.ListEnabledSSOOrgsByProvider(ctx, provider)
			if err != nil {
				return nil, err
			}
			if len(orgs) == 1 {
				providers = append(providers, api.MetaSsoProviders(provider))
			}
		}
		rows, err := q.ListPublicLoginConnections(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			connections = append(connections, struct {
				Id       uuid.UUID                      `json:"id"`
				Name     string                         `json:"name"`
				Provider api.MetaSsoConnectionsProvider `json:"provider"`
			}{row.ID, row.Name, api.MetaSsoConnectionsProvider(row.Provider)})
		}
	}
	// ⛔ THE DEPLOYMENT QUESTION. Unauthenticated, because the login page must answer it before anyone has
	// signed in — and it is a HINT, never the boundary: auth.Signup refuses on the server regardless.
	// ⚠ Fail-open to "set up" on a read error: showing a signup form to a stranger because a query blipped
	// is the wrong direction to fail.
	setup := true
	if s.orgs != nil {
		if done, e := s.orgs.SetupComplete(ctx); e == nil {
			setup = done
		}
	}
	base := s.appBaseURL // S8.2c: the CP's authoritative public URL for the gateway-enroll command
	gatewayURL := s.gatewayControlURL
	if s.system != nil {
		if configured, err := s.system.GetSystemSetting(ctx, gatewayControlSettingKey); err == nil && configured != "" {
			gatewayURL = configured
		}
	}
	img := s.nodeAgentImage // WF-2: the (digest-pinnable) agent image the emitted command uses
	var upgrade *api.UpgradeStatus
	status := s.releaseStatus
	if s.releaseStatusProvider != nil {
		status = s.releaseStatusProvider()
	}
	if st := status; st != nil {
		upgrade = &api.UpgradeStatus{Available: st.Available, Verified: st.Verified, CurrentVersion: st.CurrentVersion, CurrentSourceSha: st.CurrentSourceSHA, Reason: st.Reason}
		state := api.UpgradeStatusState(st.State)
		preflight := api.UpgradeStatusPreflightState(st.PreflightState)
		backup := api.UpgradeStatusBackupState(st.BackupState)
		rollback := api.UpgradeStatusRollbackState(st.RollbackState)
		approval := api.UpgradeStatusApprovalMode(st.ApprovalMode)
		upgrade.State = &state
		upgrade.PreflightState = &preflight
		upgrade.BackupState = &backup
		upgrade.RollbackState = &rollback
		upgrade.ApprovalMode = &approval
		if st.Version != "" {
			upgrade.Version = &st.Version
		}
		if st.SourceSHA != "" {
			upgrade.SourceSha = &st.SourceSHA
		}
		if st.Sequence != 0 {
			upgrade.Sequence = &st.Sequence
		}
		if st.Compatibility != "" {
			upgrade.Compatibility = &st.Compatibility
		}
		if st.Downtime != "" {
			upgrade.Downtime = &st.Downtime
		}
		if st.ReleaseNotesURL != "" {
			upgrade.ReleaseNotesUrl = &st.ReleaseNotesURL
		}
	}
	return api.GetMeta200JSONResponse{
		Body:    api.Meta{Edition: api.MetaEdition(s.editionName()), SsoProviders: providers, SsoConnections: &connections, ProtocolVersion: policyspec.ProtocolVersion, PublicBaseUrl: &base, GatewayControlUrl: &gatewayURL, SetupComplete: &setup, NodeAgentImage: &img, SmtpConfigured: &smtp, Upgrade: upgrade},
		Headers: api.GetMeta200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)},
	}, nil
}
