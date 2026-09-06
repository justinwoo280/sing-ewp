package ewp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestV3SourceBoundaryHasNoEarlierHandshake(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	directory := filepath.Dir(sourceFile)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, forbidden := range []string{
			"WriteClientHello",
			"AcceptClientHello",
			"NewClientV21",
			"NewServiceV21",
			"NewClientV22",
			"NewServiceV22",
			"protocolVersion",
			"v22Suite",
			"ewp/v2",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s contains forbidden earlier-protocol symbol %q", name, forbidden)
			}
		}
	}
}
