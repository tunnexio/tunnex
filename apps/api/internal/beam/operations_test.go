package beam

import (
	"github.com/tunnexio/tunnex/apps/api/internal/agentca"
	"sync"
	"testing"
)

func TestBeamCleanupTraversesBeyondHealthyFirstBatch(t *testing.T) {
	f := newFixture(t)
	r := f.create()
	// Owned fixture rows model a fleet larger than the per-tick work bound.
	// The first batch is healthy, so repeatedly starting from row zero would
	// permanently hide a later failed startup from durable cleanup.
	f.exec(`INSERT INTO beam_shares(org_id,publisher_id,source_credential_id,name,hostname,target,digest,idempotency_key,request_digest,state,expires_at)
	 SELECT org_id,publisher_id,source_credential_id,'Healthy fixture','p-'||md5(i::text)||'.beam.other.net',target,digest,uuid_generate_v7(),request_digest,'paused',now()+interval '15 minutes'
	 FROM beam_shares CROSS JOIN generate_series(1,500) i WHERE id=$1`, r.ID)
	f.exec(`UPDATE beam_shares SET created_at=now()-interval '3 minutes' WHERE id=$1`, r.ID)
	if e := f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	var state string
	if e := f.pool.QueryRow(f.ctx, `SELECT state FROM beam_shares WHERE id=$1`, r.ID).Scan(&state); e != nil || state != "starting" {
		t.Fatal("fixture startup was not outside the first batch", state, e)
	}
	if e := f.s.Sweep(f.ctx); e != nil {
		t.Fatal(e)
	}
	if e := f.pool.QueryRow(f.ctx, `SELECT state FROM beam_shares WHERE id=$1`, r.ID).Scan(&state); e != nil || state != "stopped" {
		t.Fatal("healthy first batch starved later startup cleanup", state, e)
	}
}

func TestBeamConcurrentDeniedEvidenceIsDeduplicated(t *testing.T) {
	f := newFixture(t)
	r, _ := f.connect(f.create())
	token := f.browser(r, f.login(f.reviewer))
	var workers sync.WaitGroup
	for i := 0; i < 32; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			f.s.auditDenied(f.ctx, r.Binding(), token)
		}()
	}
	workers.Wait()
	var count int
	if e := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM audit_logs WHERE org_id=$1 AND action='beam.access.denied'`, f.org).Scan(&count); e != nil || count != 1 {
		t.Fatal("concurrent denials duplicated evidence", count, e)
	}
}

type paddedSerialSigner struct{ Signer }

func (p paddedSerialSigner) SignCSR(csr []byte, identity string) (agentca.Issued, error) {
	issued, e := p.Signer.SignCSR(csr, identity)
	issued.Serial = "000" + issued.Serial
	return issued, e
}

func TestBeamCertificateSerialCanonicalization(t *testing.T) {
	f := newFixture(t)
	f.s.signer = paddedSerialSigner{f.s.signer}
	r, connector := f.connect(f.create())
	serial := issuedSerial(tFromPEM(connector.CertificatePEM))
	if r.Serial == nil || *r.Serial != serial {
		t.Fatal("certificate identity and persisted serial have different encodings")
	}
	// Previously issued rows used even-length byte hex. Preserve their exact
	// generation while matching the actual certificate's numeric identity.
	f.exec(`UPDATE beam_shares SET certificate_serial=$2 WHERE id=$1`, r.ID, "00"+serial)
	if _, e := f.s.Channel(f.ctx, r.Binding(), serial); e != nil {
		t.Fatal("legacy padded serial lost its matching certificate", e)
	}
	if _, e := f.s.Channel(f.ctx, r.Binding(), serial+"1"); e == nil {
		t.Fatal("a different numeric certificate identity was admitted")
	}
}
