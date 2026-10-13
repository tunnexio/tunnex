package main

import (
	"encoding/json"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"os"
)

func main() {
	r, err := io.ReadAll(io.LimitReader(os.Stdin, (18<<20)+1))
	if err != nil {
		panic("bounded input read refused")
	}
	v, err := ipsec.ReadOnlyGuardSemantic(r)
	if err != nil {
		panic(err)
	}
	if json.NewEncoder(os.Stdout).Encode(v) != nil {
		panic("projection refused")
	}
}
