// chartarchive is a build-only canonicalizer for real Helm chart archives.
// It never extracts archive paths or overwrites a pre-existing artifact.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"
)

const maxArchiveBytes int64 = 128 << 20
const maxArchiveFiles = 16384

type chartFile struct {
	name string
	body []byte
}

func canonicalize(input io.Reader, output io.Writer) error {
	compressed, err := io.ReadAll(io.LimitReader(input, maxArchiveBytes+1))
	if err != nil || int64(len(compressed)) > maxArchiveBytes {
		return errors.New("chart archive input is unreadable or oversized")
	}
	compressedReader := bytes.NewReader(compressed)
	zr, err := gzip.NewReader(compressedReader)
	if err != nil {
		return errors.New("chart archive is not gzip")
	}
	zr.Multistream(false)
	data, readErr := io.ReadAll(io.LimitReader(zr, maxArchiveBytes+1))
	closeErr := zr.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) > maxArchiveBytes || compressedReader.Len() != 0 {
		return errors.New("chart gzip stream is invalid, oversized, or has trailing content")
	}
	tr := tar.NewReader(bytes.NewReader(data))
	var files []chartFile
	seen := make(map[string]bool)
	root := ""
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("chart tar stream is invalid")
		}
		name := header.Name
		parts := strings.SplitN(name, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[0] == "." || parts[0] == ".." ||
			name != path.Clean(name) || path.IsAbs(name) || strings.ContainsAny(name, "\\\x00\r\n") ||
			len(name) > 4096 || seen[name] || len(files) >= maxArchiveFiles ||
			(header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA) || header.Linkname != "" ||
			header.Size < 0 || header.Size > maxArchiveBytes {
			return errors.New("chart archive entry is unsafe, duplicate, unsupported, or oversized")
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return errors.New("chart archive has multiple roots")
		}
		body, err := io.ReadAll(tr)
		if err != nil || int64(len(body)) != header.Size {
			return errors.New("chart archive entry is incomplete")
		}
		seen[name] = true
		files = append(files, chartFile{name: name, body: body})
	}
	if len(files) == 0 || !seen[root+"/Chart.yaml"] {
		return errors.New("chart archive metadata is absent")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })
	zw := gzip.NewWriter(output)
	tw := tar.NewWriter(zw)
	for _, file := range files {
		header := &tar.Header{Name: file.name, Mode: 0644, Size: int64(len(file.body)),
			ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tw.Write(file.body); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return zw.Close()
}

func run(inputPath, outputPath string) error {
	if inputPath == "" || outputPath == "" {
		return errors.New("input and output are required")
	}
	info, err := os.Lstat(inputPath)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("input must be a readable regular archive")
	}
	input, err := os.Open(inputPath)
	if err != nil {
		return errors.New("cannot open input archive")
	}
	defer input.Close()
	// Validate completely before creating the output pathname.
	var content bytes.Buffer
	if err := canonicalize(input, &content); err != nil {
		return err
	}
	output, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("output must be an absent writable pathname")
	}
	_, writeErr := content.WriteTo(output)
	syncErr := output.Sync()
	closeErr := output.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("output persistence failed; incomplete artifact retained")
	}
	return nil
}

func main() {
	input := flag.String("input", "", "real Helm .tgz archive")
	output := flag.String("output", "", "new canonical .tgz archive")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "chartarchive: unexpected positional argument")
		os.Exit(1)
	}
	if err := run(*input, *output); err != nil {
		fmt.Fprintln(os.Stderr, "chartarchive:", err)
		os.Exit(1)
	}
}
