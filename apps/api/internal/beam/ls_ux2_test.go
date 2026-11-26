package beam

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// LS-UX-2 #3: a reviewer sees who shared the app as "Name (email)", on the
// detail and in Shared with me. The publisher identity is only on projections
// that already passed the publisher/manager/grantee check: an org member who
// was not invited gets the same refusal as for a share that does not exist.
func TestBeamReviewerSeesPublisherIdentityOnlyWhenPermitted(t *testing.T) {
	f := newFixture(t)
	f.exec(`UPDATE users SET name='Pat Publisher', email='pat@beam.test' WHERE id=$1`, f.owner)
	f.exec(`UPDATE users SET name='Rae Reviewer', email='rae@beam.test' WHERE id=$1`, f.reviewer)
	share := f.create()
	share, _ = f.connect(share)
	reviewer, outsider := f.login(f.reviewer), f.login(f.outsider)

	got, e := f.s.Get(f.ctx, f.org, share.ID, reviewer)
	if e != nil {
		t.Fatal(e)
	}
	if got.PublisherName != "Pat Publisher" || got.PublisherEmail != "pat@beam.test" || got.CanManage || got.Target != nil || got.Grants != nil {
		t.Fatalf("reviewer projection: %+v", got)
	}
	page, e := f.s.ListQueryScope(f.ctx, f.org, reviewer, true, 20, 0, "", "", "", "")
	if e != nil || len(page.Items) != 1 || page.Items[0].PublisherEmail != "pat@beam.test" || page.Items[0].PublisherName != "Pat Publisher" {
		t.Fatal("shared inventory lacks the publisher identity", page, e)
	}

	// Uniform refusal: not invited and does not exist read the same.
	_, notInvited := f.s.Get(f.ctx, f.org, share.ID, outsider)
	_, absent := f.s.Get(f.ctx, f.org, uuid.New(), outsider)
	var a, b *apierr.Error
	if !errors.As(notInvited, &a) || !errors.As(absent, &b) || a.Status != b.Status || a.Code != b.Code || a.Message != b.Message {
		t.Fatalf("refusals differ: %v vs %v", notInvited, absent)
	}
	outsiderPage, e := f.s.ListQueryScope(f.ctx, f.org, outsider, true, 20, 0, "", "", "", "")
	if e != nil || len(outsiderPage.Items) != 0 {
		t.Fatal("outsider listed a share it was not invited to", outsiderPage, e)
	}

	// Feedback names its author the same way, for the share's participants.
	if _, e = f.s.AddFeedback(f.ctx, f.org, share.ID, reviewer, FeedbackInput{Body: "Looks good", Status: "approved"}); e != nil {
		t.Fatal(e)
	}
	feedback, e := f.s.Feedback(f.ctx, f.org, share.ID, f.login(f.owner), 20, 0)
	if e != nil || len(feedback.Items) != 1 || feedback.Items[0].AuthorName != "Rae Reviewer" || feedback.Items[0].AuthorEmail != "rae@beam.test" {
		t.Fatal("feedback author identity", feedback, e)
	}
	if _, e = f.s.Feedback(f.ctx, f.org, share.ID, outsider, 20, 0); e == nil {
		t.Fatal("outsider read feedback")
	}

	// An invited reviewer of an ended share still reads its detail (so the
	// console can say it ended and who shared it), but its review room is closed.
	f.exec(`UPDATE beam_shares SET state='stopped' WHERE id=$1`, share.ID)
	ended, e := f.s.Get(f.ctx, f.org, share.ID, reviewer)
	if e != nil || ended.State != "stopped" || ended.CanOpen || ended.PublisherEmail != "pat@beam.test" {
		t.Fatal("ended share detail for reviewer", ended, e)
	}
	if _, e = f.s.Feedback(f.ctx, f.org, share.ID, reviewer, 20, 0); e == nil {
		t.Fatal("reviewer read feedback of an ended share")
	}
}
