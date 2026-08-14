package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRouteFor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		source      string
		destination string
		want        route
	}{
		{"README.md", "index.md", route{Source: "README.md", Output: "index.html", URL: "/"}},
		{"appsec/example.md", "appsec/example.md", route{Source: "appsec/example.md", Output: "appsec/example/index.html", URL: "/appsec/example/"}},
		{"docs/topic/README.md", "docs/topic/README.md", route{Source: "docs/topic/README.md", Output: "docs/topic/index.html", URL: "/docs/topic/"}},
		{"docs/topic/part.md", "docs/topic/part.md", route{Source: "docs/topic/part.md", Output: "docs/topic/part/index.html", URL: "/docs/topic/part/"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.destination, func(t *testing.T) {
			t.Parallel()
			if got := routeFor(test.source, test.destination); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("routeFor() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestResolveInsideRejectsEscape(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if _, err := resolveInside(root, "../outside", "test path"); err == nil {
		t.Fatal("resolveInside accepted a path outside the repository")
	}
}

func TestSafeArtifactPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	m := model{root: root, config: config{ArtifactDirectory: ".artifacts"}}
	want := filepath.Join(root, ".artifacts", "site")
	got, err := safeArtifactPath(m, ".artifacts/site")
	if err != nil {
		t.Fatalf("safeArtifactPath returned error: %v", err)
	}
	if got != want {
		t.Fatalf("safeArtifactPath = %q, want %q", got, want)
	}
	for _, unsafe := range []string{".", ".artifacts", "mkdocs-project/site"} {
		if _, err := safeArtifactPath(m, unsafe); err == nil {
			t.Fatalf("safeArtifactPath accepted %q", unsafe)
		}
	}
}

func TestSafeArtifactPathRejectsSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".artifacts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".artifacts", "site")); err != nil {
		t.Fatal(err)
	}
	m := model{root: root, config: config{ArtifactDirectory: ".artifacts"}}
	if _, err := safeArtifactPath(m, ".artifacts/site"); err == nil {
		t.Fatal("safeArtifactPath accepted a symlinked output")
	}
}

func TestVerifySiteReportsCanonicalSource(t *testing.T) {
	t.Parallel()
	site := t.TempDir()
	for _, name := range []string{"index.html", "404.html", "CNAME"} {
		if err := os.WriteFile(filepath.Join(site, name), []byte("test"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	m := model{routes: []route{{Source: "docs/example.md", Output: "docs/example/index.html", URL: "/docs/example/"}}}
	err := verifySite(m, site)
	if err == nil {
		t.Fatal("verifySite accepted a missing canonical route")
	}
	if !strings.Contains(err.Error(), "docs/example.md") {
		t.Fatalf("verifySite error %q does not identify the canonical source", err)
	}
}

func TestManifestExcludesItselfAndSortsArtifacts(t *testing.T) {
	t.Parallel()
	site := t.TempDir()
	files := map[string]string{
		"z/index.html": "z",
		"a.txt":        "a",
		manifestName:   "old manifest",
	}
	for name, value := range files {
		path := filepath.Join(site, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(value), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	manifest, err := makeManifest(model{config: config{CanonicalBranch: "main"}}, site)
	if err != nil {
		t.Fatalf("makeManifest returned error: %v", err)
	}
	if len(manifest.Artifacts) != 2 {
		t.Fatalf("got %d artifacts, want 2", len(manifest.Artifacts))
	}
	if manifest.Artifacts[0].Path != "a.txt" || manifest.Artifacts[1].Path != "z/index.html" {
		t.Fatalf("artifacts are not sorted: %#v", manifest.Artifacts)
	}
}

func TestClassifyGaps(t *testing.T) {
	t.Parallel()
	m := model{
		config: config{CanonicalBranch: "main", PublishedBranch: "gh-pages"},
		routes: []route{
			{Source: "covered.md", Output: "covered/index.html", URL: "/covered/"},
			{Source: "revived.md", Output: "revived/index.html", URL: "/revived/"},
			{Source: "new.md", Output: "new/index.html", URL: "/new/"},
		},
	}
	records := map[string]publishedRecord{
		"/covered/":   {Title: "Covered", Status: "reference", Indexable: true},
		"/live-only/": {Title: "Live only", Status: "tool", Indexable: true},
		"/revived/":   {Title: "Old", Status: "archived", Indexable: false},
	}
	audit := classifyGaps(m, records)
	if audit.CoveredIndexableCount != 1 {
		t.Fatalf("covered count = %d, want 1", audit.CoveredIndexableCount)
	}
	if len(audit.PublishedOnlyIndexable) != 1 || audit.PublishedOnlyIndexable[0].URL != "/live-only/" {
		t.Fatalf("unexpected published-only gaps: %#v", audit.PublishedOnlyIndexable)
	}
	if len(audit.CanonicalOnly) != 1 || audit.CanonicalOnly[0].URL != "/new/" {
		t.Fatalf("unexpected canonical-only gaps: %#v", audit.CanonicalOnly)
	}
	if len(audit.ArchivedSourceRoutes) != 1 || audit.ArchivedSourceRoutes[0].URL != "/revived/" {
		t.Fatalf("unexpected archived source routes: %#v", audit.ArchivedSourceRoutes)
	}
}
