package sandboxes

import (
	"os"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Hundreds of latest-schema lifecycle cases need independent databases, not
// hundreds of identical migration replays. Historical migration cases retain
// their explicit NewAtVersion fixtures.
var fixtureTemplate testpostgres.Template

func TestMain(m *testing.M) {
	os.Exit(fixtureTemplate.Run(m))
}
