// Command tunnex-sandbox-fixture-setup seeds only a fresh, isolated qualification
// database. Configuration and generated credentials are private fixture files;
// stdout contains public identifiers only. It never connects to a product DB.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxproduct"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	appcrypto "github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/nodes"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxes"
)

type configuration struct {
	DatabaseURL     string `json:"database_url"`
	MasterKey       string `json:"master_key"`
	LoginPassword   string `json:"login_password"`
	ImageDigest     string `json:"image_digest"`
	OutputDirectory string `json:"output_directory"`
}
type publicFixture struct {
	OrganizationID      uuid.UUID   `json:"organization_id"`
	OtherOrganizationID uuid.UUID   `json:"other_organization_id"`
	CreatorID           uuid.UUID   `json:"creator_id"`
	OtherCreatorID      uuid.UUID   `json:"other_creator_id"`
	TemplateID          uuid.UUID   `json:"template_id"`
	GatewayID           string      `json:"gateway_id"`
	SkillRevisionIDs    []uuid.UUID `json:"skill_revision_ids"`
}

func privateWrite(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
func run() error {
	if len(os.Args) != 1 {
		return errors.New("stdin configuration required")
	}
	var c configuration
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 32769))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&c) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid configuration")
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil || u.Scheme != "postgres" || !strings.HasPrefix(u.Path, "/tunnex_sandbox_qual_") || len(strings.TrimPrefix(u.Path, "/tunnex_sandbox_qual_")) < 8 {
		return errors.New("isolated database required")
	}
	if !strings.HasPrefix(c.ImageDigest, "sha256:") || len(c.ImageDigest) != 71 {
		return errors.New("immutable image required")
	}
	if _, err = hex.DecodeString(strings.TrimPrefix(c.ImageDigest, "sha256:")); err != nil {
		return errors.New("invalid image")
	}
	if !filepath.IsAbs(c.OutputDirectory) || filepath.Clean(c.OutputDirectory) != c.OutputDirectory {
		return errors.New("absolute output required")
	}
	info, err := os.Lstat(c.OutputDirectory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private output required")
	}
	master, err := base64.StdEncoding.DecodeString(c.MasterKey)
	if err != nil {
		return errors.New("invalid fixture master")
	}
	sealer, err := appcrypto.NewSealer(master)
	if err != nil {
		return errors.New("invalid fixture master")
	}
	hash, err := password.Hash(c.LoginPassword)
	if err != nil || len(c.LoginPassword) < password.MinPasswordLen {
		return errors.New("invalid fixture password")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, c.DatabaseURL)
	if err != nil {
		return errors.New("fixture connection failed")
	}
	defer pool.Close()
	// Refuse any existing application schema before migration. A rerun must use
	// explicit recovery, never silently reseed principals or credentials.
	var existing bool
	if err = pool.QueryRow(ctx, `SELECT to_regclass('public.organizations') IS NOT NULL`).Scan(&existing); err != nil || existing {
		return errors.New("fresh database required")
	}
	if err = db.Up(c.DatabaseURL); err != nil {
		return errors.New("fixture migration failed")
	}
	p := publicFixture{OrganizationID: uuid.New(), OtherOrganizationID: uuid.New(), CreatorID: uuid.New(), OtherCreatorID: uuid.New(), TemplateID: uuid.New()}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for i, org := range []uuid.UUID{p.OrganizationID, p.OtherOrganizationID} {
		_, err = tx.Exec(ctx, `INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,sandboxes_enabled,max_sandboxes,max_sandboxes_per_user) VALUES($1,$2,$3,$4,'enforcing',true,1,1)`, org, fmt.Sprintf("Sandbox qualification %d", i), org.String(), fmt.Sprintf("10.254.%d.0/24", 242+i))
		if err != nil {
			return err
		}
		creator := p.CreatorID
		if i == 1 {
			creator = p.OtherCreatorID
		}
		_, err = tx.Exec(ctx, `INSERT INTO users(id,email,name,password_hash,email_verified_at) VALUES($1,$2,'Qualification creator',$3,now())`, creator, creator.String()+"@sandbox.example.test", hash)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'owner')`, org, creator)
		if err != nil {
			return err
		}
	}
	// The second fixture creator can exercise non-owner access in this org;
	// no rule grants that member the first creator's terminal permission.
	if _, err = tx.Exec(ctx, `INSERT INTO memberships(org_id,user_id,role) VALUES($1,$2,'member')`, p.OrganizationID, p.OtherCreatorID); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO sandbox_templates(id,org_id,name,image_digest,maximum_scope,memory_mib,max_ttl_seconds,enabled) VALUES($1,$2,'Minimal private terminal',$3,'[{"cidr":"10.254.242.0/24","protocol":"tcp","port_low":22,"port_high":22}]',128,3600,true)`, p.TemplateID, p.OrganizationID, c.ImageDigest)
	if err != nil {
		return err
	}
	resource := uuid.New()
	_, err = tx.Exec(ctx, `INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high) VALUES($1,$2,'Qualification private terminal','10.254.242.0/24','tcp',22,22)`, resource, p.OrganizationID)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO policy_rules(org_id,src_kind,src_user_id,dst_kind,dst_resource_id) VALUES($1,'user',$2,'resource',$3)`, p.OrganizationID, p.CreatorID, resource)
	if err != nil {
		return err
	}
	for i := 1; i <= 2; i++ {
		text := fmt.Sprintf("# Qualification workspace guide v%d\nUse existing terminal tools. No commands run during installation.\n", i)
		digest := sha256.Sum256([]byte(text))
		revision := sandboxes.SkillRevision{ID: uuid.New(), Name: "Workspace guide", Version: fmt.Sprint(i), Description: "Inert fixture instructions", Instructions: text, Digest: hex.EncodeToString(digest[:]), RequiredScope: []sandboxes.Scope{}, Fields: []sandboxes.SkillField{{Key: "format", Label: "Format", Choices: []string{"short", "long"}, Required: true}}}
		raw, _ := json.Marshal(revision)
		_, err = tx.Exec(ctx, `INSERT INTO sandbox_skill_revisions(id,org_id,manifest,enabled) VALUES($1,$2,$3,true)`, revision.ID, p.OrganizationID, raw)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO sandbox_template_skills(org_id,template_id,revision_id) VALUES($1,$2,$3)`, p.OrganizationID, p.TemplateID, revision.ID)
		if err != nil {
			return err
		}
		p.SkillRevisionIDs = append(p.SkillRevisionIDs, revision.ID)
	}
	if err = tx.Commit(ctx); err != nil {
		return err
	}
	ca, _, err := agentca.LoadOrCreate(ctx, sqlc.New(pool), sealer)
	if err != nil {
		return errors.New("fixture CA failed")
	}
	service := nodes.NewService(pool, ca, sealer)
	token, err := service.IssueJoinToken(ctx, p.CreatorID, p.OrganizationID, "sandbox-qualification-gateway", "gateway")
	if err != nil {
		return errors.New("fixture gateway admission failed")
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "sandbox-qualification-gateway"}}, key)
	if err != nil {
		return err
	}
	result, err := service.Enroll(ctx, token, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), "sandbox-qualification-gateway", "sandbox-qualification")
	if err != nil {
		return errors.New("fixture gateway enrollment failed")
	}
	p.GatewayID = result.NodeID
	for name, data := range map[string][]byte{"key.pem": pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), "cert.pem": []byte(result.CertPEM), "ca.pem": []byte(result.CAPEM)} {
		if err = privateWrite(filepath.Join(c.OutputDirectory, name), data); err != nil {
			return errors.New("fixture credentials publication failed")
		}
	}
	raw, _ := json.MarshalIndent(p, "", "  ")
	if err = privateWrite(filepath.Join(c.OutputDirectory, "fixture-public.json"), raw); err != nil {
		return err
	}
	fmt.Println(string(raw))
	return nil
}
func main() {
	// TODO(sandbox-reentry): docs/S-sandbox-shelved-main-reentry.md.
	if sandboxproduct.Shelved {
		fmt.Fprintln(os.Stderr, sandboxproduct.Message)
		os.Exit(1)
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qualification setup failed")
		os.Exit(1)
	}
}
