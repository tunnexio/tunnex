package main

import (
	"strings"
	"testing"
)

func TestExactFreshDockerCgroupLayouts(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, path := range []string{"/docker/" + id, "/system.slice/docker-" + id + ".scope"} {
		got, err := exactDockerCgroupPath("0::"+path+"\n", id)
		if err != nil || got != path {
			t.Fatal("exact Docker layout refused", err)
		}
	}
	for _, raw := range []string{"0::/", "0::/docker/" + id + "/child", "0::/system.slice/docker-" + id + ".scope/child", "0::/system.slice/docker-" + strings.Repeat("b", 64) + ".scope", "1:cpu:/docker/" + id, "0::/docker/" + id + "\n0::/other"} {
		if _, err := exactDockerCgroupPath(raw, id); err == nil {
			t.Fatal("foreign layout accepted")
		}
	}
	if _, err := exactDockerCgroupPath("0::/docker/short", "short"); err == nil {
		t.Fatal("short ID accepted")
	}
}
