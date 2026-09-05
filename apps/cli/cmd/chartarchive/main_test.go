package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func archiveFixture(t *testing.T, files []chartFile, timestamp int64, kind byte) []byte {
	t.Helper()
	var result bytes.Buffer
	gz := gzip.NewWriter(&result)
	gz.ModTime = time.Unix(timestamp, 0)
	tw := tar.NewWriter(gz)
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: 0600, Size: int64(len(file.body)), ModTime: time.Unix(timestamp, 0), Typeflag: kind}
		if kind == tar.TypeSymlink {
			header.Linkname, header.Size = "outside", 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if header.Size != 0 {
			if _, err := tw.Write(file.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return result.Bytes()
}

func TestCanonicalArchivePreservesContentAndIgnoresClockAndOrder(t *testing.T) {
	files := []chartFile{{"chart/Chart.yaml", []byte("name: chart\nversion: 1.2.3\n")}, {"chart/values.yaml", []byte("answer: 42\n")}}
	a := archiveFixture(t, files, 100, tar.TypeReg)
	b := archiveFixture(t, []chartFile{files[1], files[0]}, 200, tar.TypeReg)
	var normalizedA, normalizedB bytes.Buffer
	if err := canonicalize(bytes.NewReader(a), &normalizedA); err != nil {
		t.Fatal(err)
	}
	if err := canonicalize(bytes.NewReader(b), &normalizedB); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalizedA.Bytes(), normalizedB.Bytes()) {
		t.Fatal("clock/order changed canonical archive bytes")
	}
	var repeated bytes.Buffer
	if err := canonicalize(bytes.NewReader(normalizedA.Bytes()), &repeated); err != nil || !bytes.Equal(repeated.Bytes(), normalizedA.Bytes()) {
		t.Fatalf("canonicalization is not idempotent: %v", err)
	}
	files[1].body = []byte("answer: 43\n")
	var changed bytes.Buffer
	if err := canonicalize(bytes.NewReader(archiveFixture(t, files, 100, tar.TypeReg)), &changed); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(normalizedA.Bytes(), changed.Bytes()) {
		t.Fatal("changed chart content did not change artifact bytes")
	}
}

func TestCanonicalArchiveRefusesUnsafeEntriesAndTrailingStreams(t *testing.T) {
	valid := chartFile{"chart/Chart.yaml", []byte("name: chart\n")}
	for name, files := range map[string][]chartFile{
		"duplicate": {valid, valid}, "traversal": {valid, {"chart/../outside", nil}},
		"absolute": {valid, {"/outside/file", nil}}, "multi-root": {valid, {"other/file", nil}},
		"missing-metadata": {{"chart/values.yaml", nil}}, "backslash": {valid, {"chart/a\\b", nil}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := canonicalize(bytes.NewReader(archiveFixture(t, files, 100, tar.TypeReg)), &bytes.Buffer{}); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
	for _, input := range [][]byte{
		archiveFixture(t, []chartFile{valid}, 100, tar.TypeSymlink),
		[]byte("not-gzip"), append(archiveFixture(t, []chartFile{valid}, 100, tar.TypeReg), []byte("trailing")...),
	} {
		if err := canonicalize(bytes.NewReader(input), &bytes.Buffer{}); err == nil {
			t.Fatal("malformed/non-regular archive accepted")
		}
	}
}

func TestRunNeverOverwritesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "input.tgz"), filepath.Join(dir, "output.tgz")
	if err := os.WriteFile(input, archiveFixture(t, []chartFile{{"chart/Chart.yaml", []byte("name: chart\n")}}, 100, tar.TypeReg), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing-user-artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(input, output); err == nil {
		t.Fatal("existing artifact overwritten")
	}
	data, err := os.ReadFile(output)
	if err != nil || string(data) != "existing-user-artifact" {
		t.Fatalf("existing output changed: %v", err)
	}
}
