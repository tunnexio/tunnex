package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"os"
)

func main() {
	dir := flag.String("dir", "", "exact existing private journal directory; read only")
	flag.Parse()
	org, owner, err := ipsec.ReadRuntimeJournalIdentity(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "whole journal validation refused")
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]string{"org": org.String(), "owner": owner.String()})
}
