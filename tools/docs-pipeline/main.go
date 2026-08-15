// Command docs-pipeline builds and verifies the documentation site from the
// canonical Markdown sources on main. It deliberately does not pull content
// back from generated HTML: published artifacts must never become a hidden
// source of truth.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const (
	configName   = "docs-pipeline.json"
	manifestName = "docs-build-manifest.json"
)

type config struct {
	SchemaVersion     int      `json:"schemaVersion"`
	CanonicalBranch   string   `json:"canonicalBranch"`
	PublishedBranch   string   `json:"publishedBranch"`
	MkDocsConfig      string   `json:"mkdocsConfig"`
	RequirementsFile  string   `json:"requirementsFile"`
	LifecycleRegistry string   `json:"lifecycleRegistry"`
	DocsDirectory     string   `json:"docsDirectory"`
	ArtifactDirectory string   `json:"artifactDirectory"`
	MigrationMode     bool     `json:"migrationMode"`
	BuildInputs       []string `json:"buildInputs"`
	Mounts            []mount  `json:"mounts"`
}

type mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Virtual     bool   `json:"virtual,omitempty"`
}

type sourceFile struct {
	Path        string `json:"path"`
	Destination string `json:"destination"`
	SHA256      string `json:"sha256"`
}

type route struct {
	Source    string `json:"source"`
	Output    string `json:"output"`
	URL       string `json:"url"`
	Status    string `json:"status,omitempty"`
	Indexable bool   `json:"indexable"`
	Generated bool   `json:"generated,omitempty"`
}

type artifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type buildManifest struct {
	SchemaVersion   int          `json:"schemaVersion"`
	CanonicalBranch string       `json:"canonicalBranch"`
	Inputs          []sourceFile `json:"inputs"`
	Routes          []route      `json:"routes"`
	Artifacts       []artifact   `json:"artifacts"`
}

type publishedRecord struct {
	Title     string `json:"title"`
	Status    string `json:"status"`
	Indexable bool   `json:"indexable"`
}

type migrationGap struct {
	URL    string `json:"url"`
	Source string `json:"source,omitempty"`
	Title  string `json:"title,omitempty"`
	Status string `json:"status,omitempty"`
}

type migrationAudit struct {
	SchemaVersion          int            `json:"schemaVersion"`
	CanonicalBranch        string         `json:"canonicalBranch"`
	PublishedBranch        string         `json:"publishedBranch"`
	CanonicalRouteCount    int            `json:"canonicalRouteCount"`
	PublishedRecordCount   int            `json:"publishedRecordCount"`
	CoveredIndexableCount  int            `json:"coveredIndexableCount"`
	PublishedOnlyIndexable []migrationGap `json:"publishedOnlyIndexable"`
	CanonicalOnly          []migrationGap `json:"canonicalOnly"`
	ArchivedSourceRoutes   []migrationGap `json:"archivedSourceRoutes"`
}

type model struct {
	root    string
	config  config
	inputs  []sourceFile
	routes  []route
	records map[string]publishedRecord
	docsDir string
}

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "build":
		err = runBuild(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "inventory":
		err = runInventory(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "help", "-h", "--help":
		usage(os.Stdout)
		return
	default:
		usage(os.Stderr)
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "docs-pipeline: %v\n", err)
		os.Exit(1)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: docs-pipeline <build|serve|verify|inventory|audit> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  build      run strict MkDocs build, verify routes, write manifest")
	fmt.Fprintln(w, "  serve      run the canonical MkDocs development server")
	fmt.Fprintln(w, "  verify     validate a previously built site")
	fmt.Fprintln(w, "  inventory  print canonical source-to-route inventory as JSON")
	fmt.Fprintln(w, "  audit      compare canonical routes with published lifecycle data")
}

func runServe(args []string) error {
	set, rootFlag, _ := commonFlags("serve", args)
	python := set.String("python", "python3", "Python interpreter with documentation dependencies installed")
	address := set.String("address", "127.0.0.1:8000", "development server listen address")
	if err := set.Parse(args); err != nil {
		return err
	}
	m, err := loadModel(*rootFlag)
	if err != nil {
		return err
	}
	command := exec.Command(*python, "-m", "mkdocs", "serve", "--strict", "-f", m.config.MkDocsConfig, "--dev-addr", *address)
	command.Dir = m.root
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("MkDocs development server failed: %w", err)
	}
	return nil
}

func commonFlags(name string, args []string) (*flag.FlagSet, *string, error) {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(io.Discard)
	root := set.String("root", ".", "repository root")
	return set, root, nil
}

func runBuild(args []string) error {
	set, rootFlag, _ := commonFlags("build", args)
	python := set.String("python", "python3", "Python interpreter with documentation dependencies installed")
	output := set.String("output", ".artifacts/site", "staged site directory inside artifactDirectory")
	if err := set.Parse(args); err != nil {
		return err
	}
	m, err := loadModel(*rootFlag)
	if err != nil {
		return err
	}
	outputPath, err := safeArtifactPath(m, *output)
	if err != nil {
		return err
	}

	command := exec.Command(*python, "-m", "mkdocs", "build", "--strict", "--clean", "-f", m.config.MkDocsConfig, "-d", outputPath)
	command.Dir = m.root
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("strict MkDocs build failed: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outputPath, ".nojekyll"), []byte{}, 0o644); err != nil {
		return fmt.Errorf("write .nojekyll marker: %w", err)
	}
	if err := verifySite(m, outputPath); err != nil {
		return err
	}
	manifest, err := makeManifest(m, outputPath)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode build manifest: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(outputPath, manifestName), encoded, 0o644); err != nil {
		return fmt.Errorf("write build manifest: %w", err)
	}
	fmt.Printf("Verified %d canonical routes and wrote %s.\n", len(m.routes), filepath.Join(outputPath, manifestName))
	return nil
}

func runVerify(args []string) error {
	set, rootFlag, _ := commonFlags("verify", args)
	site := set.String("site", ".artifacts/site", "built site directory")
	if err := set.Parse(args); err != nil {
		return err
	}
	m, err := loadModel(*rootFlag)
	if err != nil {
		return err
	}
	sitePath, err := resolveInside(m.root, *site, "site directory")
	if err != nil {
		return err
	}
	if err := verifySite(m, sitePath); err != nil {
		return err
	}
	fmt.Printf("Verified %d canonical routes in %s.\n", len(m.routes), sitePath)
	return nil
}

func runInventory(args []string) error {
	set, rootFlag, _ := commonFlags("inventory", args)
	if err := set.Parse(args); err != nil {
		return err
	}
	m, err := loadModel(*rootFlag)
	if err != nil {
		return err
	}
	payload := struct {
		SchemaVersion   int          `json:"schemaVersion"`
		CanonicalBranch string       `json:"canonicalBranch"`
		Inputs          []sourceFile `json:"inputs"`
		Routes          []route      `json:"routes"`
	}{1, m.config.CanonicalBranch, m.inputs, m.routes}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(payload)
}

func runAudit(args []string) error {
	set, rootFlag, _ := commonFlags("audit", args)
	publishedRef := set.String("published-ref", "origin/gh-pages", "Git ref containing the published lifecycle registry")
	statusPath := set.String("status-path", "content-status.json", "lifecycle registry path at published-ref")
	output := set.String("output", ".artifacts/live-content-gap.json", "audit report path below artifactDirectory")
	failOnGap := set.Bool("fail-on-gap", false, "return an error when migration gaps remain")
	if err := set.Parse(args); err != nil {
		return err
	}
	m, err := loadModel(*rootFlag)
	if err != nil {
		return err
	}
	records, err := readPublishedRecords(m.root, *publishedRef, *statusPath)
	if err != nil {
		return err
	}
	audit := classifyGaps(m, records)
	encoded, err := json.MarshalIndent(audit, "", "  ")
	if err != nil {
		return fmt.Errorf("encode migration audit: %w", err)
	}
	encoded = append(encoded, '\n')
	outputPath, err := safeArtifactFile(m, *output)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("create audit output directory: %w", err)
	}
	if err := os.WriteFile(outputPath, encoded, 0o644); err != nil {
		return fmt.Errorf("write migration audit: %w", err)
	}
	fmt.Printf(
		"Migration audit: %d covered indexable, %d published-only indexable, %d canonical-only, %d archived source routes. Report: %s\n",
		audit.CoveredIndexableCount,
		len(audit.PublishedOnlyIndexable),
		len(audit.CanonicalOnly),
		len(audit.ArchivedSourceRoutes),
		outputPath,
	)
	if *failOnGap && (len(audit.PublishedOnlyIndexable) != 0 || len(audit.CanonicalOnly) != 0) {
		return errors.New("published content migration gaps remain")
	}
	return nil
}

func readPublishedRecords(root, ref, statusPath string) (map[string]publishedRecord, error) {
	if strings.TrimSpace(ref) == "" || strings.ContainsAny(ref, ":\r\n\x00") {
		return nil, errors.New("published-ref must be a nonempty Git ref without a colon")
	}
	cleanStatus := filepath.ToSlash(filepath.Clean(statusPath))
	if cleanStatus == "." || strings.HasPrefix(cleanStatus, "../") || filepath.IsAbs(statusPath) || strings.ContainsAny(cleanStatus, ":\r\n\x00") {
		return nil, errors.New("status-path must be a repository-relative path")
	}
	command := exec.Command("git", "show", ref+":"+cleanStatus)
	command.Dir = root
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("read %s from %s: %w", cleanStatus, ref, err)
	}
	var records map[string]publishedRecord
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("parse published lifecycle registry: %w", err)
	}
	return records, nil
}

func classifyGaps(m model, records map[string]publishedRecord) migrationAudit {
	canonical := make(map[string]route, len(m.routes))
	for _, item := range m.routes {
		if item.Generated {
			continue
		}
		canonical[item.URL] = item
	}
	audit := migrationAudit{
		SchemaVersion:        1,
		CanonicalBranch:      m.config.CanonicalBranch,
		PublishedBranch:      m.config.PublishedBranch,
		CanonicalRouteCount:  len(m.routes),
		PublishedRecordCount: len(records),
	}
	for url, record := range records {
		item, exists := canonical[url]
		if record.Indexable {
			if exists {
				audit.CoveredIndexableCount++
			} else {
				audit.PublishedOnlyIndexable = append(audit.PublishedOnlyIndexable, migrationGap{URL: url, Title: record.Title, Status: record.Status})
			}
		} else if exists && record.Status == "archived" {
			audit.ArchivedSourceRoutes = append(audit.ArchivedSourceRoutes, migrationGap{URL: url, Source: item.Source, Title: record.Title, Status: record.Status})
		}
	}
	for url, item := range canonical {
		if _, exists := records[url]; !exists {
			audit.CanonicalOnly = append(audit.CanonicalOnly, migrationGap{URL: url, Source: item.Source})
		}
	}
	sortGaps := func(items []migrationGap) {
		sort.Slice(items, func(i, j int) bool { return items[i].URL < items[j].URL })
	}
	sortGaps(audit.PublishedOnlyIndexable)
	sortGaps(audit.CanonicalOnly)
	sortGaps(audit.ArchivedSourceRoutes)
	return audit
}

func loadModel(root string) (model, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return model{}, fmt.Errorf("resolve repository root: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return model{}, fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(realRoot, configName))
	if err != nil {
		return model{}, fmt.Errorf("read %s: %w", configName, err)
	}
	var cfg config
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return model{}, fmt.Errorf("parse %s: %w", configName, err)
	}
	if cfg.SchemaVersion != 1 {
		return model{}, fmt.Errorf("unsupported schemaVersion %d", cfg.SchemaVersion)
	}
	if cfg.CanonicalBranch != "main" || cfg.PublishedBranch != "gh-pages" {
		return model{}, errors.New("canonicalBranch must be main and publishedBranch must be gh-pages")
	}
	if len(cfg.Mounts) == 0 {
		return model{}, errors.New("at least one source mount is required")
	}

	docsDir, err := existingDirectory(realRoot, cfg.DocsDirectory, "docsDirectory")
	if err != nil {
		return model{}, err
	}
	for _, required := range []struct {
		value string
		label string
	}{{cfg.MkDocsConfig, "mkdocsConfig"}, {cfg.RequirementsFile, "requirementsFile"}, {cfg.LifecycleRegistry, "lifecycleRegistry"}} {
		if _, err := existingFile(realRoot, required.value, required.label); err != nil {
			return model{}, err
		}
	}
	if _, err := resolveInside(realRoot, cfg.ArtifactDirectory, "artifactDirectory"); err != nil {
		return model{}, err
	}

	inputs := make([]sourceFile, 0)
	routes := make([]route, 0)
	destinations := map[string]string{}
	outputs := map[string]string{}
	for _, item := range cfg.Mounts {
		files, err := validateMount(realRoot, docsDir, item)
		if err != nil {
			return model{}, err
		}
		for _, file := range files {
			if previous, ok := destinations[file.Destination]; ok {
				return model{}, fmt.Errorf("duplicate destination %q from %q and %q", file.Destination, previous, file.Path)
			}
			destinations[file.Destination] = file.Path
			inputs = append(inputs, file)
			if strings.EqualFold(filepath.Ext(file.Destination), ".md") {
				r := routeFor(file.Path, file.Destination)
				if previous, ok := outputs[r.Output]; ok {
					return model{}, fmt.Errorf("duplicate route %q from %q and %q", r.Output, previous, file.Path)
				}
				outputs[r.Output] = file.Path
				routes = append(routes, r)
			}
		}
	}
	for _, input := range []string{configName, cfg.MkDocsConfig, cfg.RequirementsFile, cfg.LifecycleRegistry} {
		files, err := collectInput(realRoot, input, input)
		if err != nil {
			return model{}, err
		}
		inputs = append(inputs, files...)
	}
	for _, input := range cfg.BuildInputs {
		files, err := collectInput(realRoot, input, "buildInput")
		if err != nil {
			return model{}, err
		}
		inputs = append(inputs, files...)
	}
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Path == inputs[j].Path {
			return inputs[i].Destination < inputs[j].Destination
		}
		return inputs[i].Path < inputs[j].Path
	})
	records, err := readLifecycleFile(realRoot, cfg.LifecycleRegistry)
	if err != nil {
		return model{}, err
	}
	for index := range routes {
		record, exists := records[routes[index].URL]
		if !exists {
			return model{}, fmt.Errorf("canonical route %q has no lifecycle record", routes[index].URL)
		}
		routes[index].Status = record.Status
		routes[index].Indexable = record.Indexable
	}
	routeURLs := make(map[string]struct{}, len(routes))
	for _, item := range routes {
		routeURLs[item.URL] = struct{}{}
	}
	for url, record := range records {
		if _, exists := routeURLs[url]; exists || record.Status != "archived" {
			continue
		}
		routes = append(routes, route{
			Source:    cfg.LifecycleRegistry + "#" + url,
			Output:    strings.TrimPrefix(url, "/") + "index.html",
			URL:       url,
			Status:    record.Status,
			Indexable: false,
			Generated: true,
		})
		routeURLs[url] = struct{}{}
	}
	if !cfg.MigrationMode {
		for url, record := range records {
			if !record.Indexable {
				continue
			}
			found := false
			for _, item := range routes {
				if item.URL == url {
					found = true
					break
				}
			}
			if !found {
				return model{}, fmt.Errorf("indexable lifecycle route %q has no canonical Markdown; enable migrationMode only while resolving known gaps", url)
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Output < routes[j].Output })
	return model{root: realRoot, config: cfg, inputs: inputs, routes: routes, records: records, docsDir: docsDir}, nil
}

func readLifecycleFile(root, value string) (map[string]publishedRecord, error) {
	path, err := existingFile(root, value, "lifecycleRegistry")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read lifecycle registry: %w", err)
	}
	var records map[string]publishedRecord
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("parse lifecycle registry: %w", err)
	}
	for url, record := range records {
		if !strings.HasPrefix(url, "/") || (url != "/404.html" && !strings.HasSuffix(url, "/")) {
			return nil, fmt.Errorf("invalid lifecycle URL %q", url)
		}
		if strings.TrimSpace(record.Title) == "" || strings.TrimSpace(record.Status) == "" {
			return nil, fmt.Errorf("lifecycle record %q requires title and status", url)
		}
	}
	return records, nil
}

func validateMount(root, docsDir string, item mount) ([]sourceFile, error) {
	if item.Source == "" || item.Destination == "" {
		return nil, errors.New("mount source and destination must be nonempty")
	}
	source, err := resolveInside(root, item.Source, "mount source")
	if err != nil {
		return nil, err
	}
	source, err = realExistingPath(root, source, "mount source")
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(source)
	if err != nil {
		return nil, fmt.Errorf("stat mount source %q: %w", item.Source, err)
	}
	if !item.Virtual {
		mounted, err := resolveInside(docsDir, item.Destination, "mount destination")
		if err != nil {
			return nil, err
		}
		realMounted, err := filepath.EvalSymlinks(mounted)
		if err != nil {
			return nil, fmt.Errorf("resolve mount destination %q: %w", item.Destination, err)
		}
		if !samePath(source, realMounted) {
			return nil, fmt.Errorf("mount %q resolves to %q, expected %q", item.Destination, realMounted, source)
		}
	}

	if !info.IsDir() {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("mount source %q is not a regular file", item.Source)
		}
		hash, err := fileHash(source)
		if err != nil {
			return nil, err
		}
		return []sourceFile{{Path: slash(item.Source), Destination: slash(item.Destination), SHA256: hash}}, nil
	}

	files := make([]sourceFile, 0)
	err = filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if current != source && (entry.Name() == ".git" || entry.Name() == "node_modules" || entry.Name() == ".terraform") {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source %q contains non-regular file %q", item.Source, current)
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		hash, err := fileHash(current)
		if err != nil {
			return err
		}
		files = append(files, sourceFile{
			Path:        slash(filepath.Join(item.Source, relative)),
			Destination: slash(filepath.Join(item.Destination, relative)),
			SHA256:      hash,
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk mount source %q: %w", item.Source, err)
	}
	return files, nil
}

func routeFor(source, destination string) route {
	destination = slash(destination)
	directory, name := filepath.Split(destination)
	base := strings.TrimSuffix(name, filepath.Ext(name))
	var output string
	if strings.EqualFold(base, "index") || strings.EqualFold(base, "readme") {
		output = slash(filepath.Join(directory, "index.html"))
	} else {
		output = slash(filepath.Join(directory, base, "index.html"))
	}
	url := "/" + strings.TrimSuffix(output, "index.html")
	if output == "index.html" {
		url = "/"
	}
	return route{Source: slash(source), Output: output, URL: url}
}

func verifySite(m model, site string) error {
	info, err := os.Stat(site)
	if err != nil {
		return fmt.Errorf("stat built site: %w", err)
	}
	if !info.IsDir() {
		return errors.New("built site is not a directory")
	}
	missing := make([]string, 0)
	for _, item := range m.routes {
		target := filepath.Join(site, filepath.FromSlash(item.Output))
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() {
			missing = append(missing, fmt.Sprintf("%s (%s)", item.Output, item.Source))
			continue
		}
		html, err := os.ReadFile(target)
		if err != nil {
			return fmt.Errorf("read built route %q: %w", item.Output, err)
		}
		body := string(html)
		if item.Status == "archived" {
			if !strings.Contains(body, `content="noindex, nofollow"`) || !strings.Contains(body, "Archived reference") {
				return fmt.Errorf("archived route %q is missing noindex archive treatment", item.URL)
			}
		} else if item.Indexable && strings.Contains(body, `content="noindex, nofollow"`) {
			return fmt.Errorf("indexable route %q unexpectedly contains archive noindex treatment", item.URL)
		}
	}
	for _, required := range []string{"index.html", "404.html", "CNAME"} {
		target := filepath.Join(site, required)
		if info, err := os.Stat(target); err != nil || !info.Mode().IsRegular() {
			missing = append(missing, required+" (required site file)")
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return fmt.Errorf("built site is missing %d outputs:\n  %s", len(missing), strings.Join(missing, "\n  "))
	}
	return nil
}

func makeManifest(m model, site string) (buildManifest, error) {
	artifacts := make([]artifact, 0)
	err := filepath.WalkDir(site, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("built site contains symlink %q", current)
		}
		if entry.Name() == manifestName {
			return nil
		}
		relative, err := filepath.Rel(site, current)
		if err != nil {
			return err
		}
		hash, err := fileHash(current)
		if err != nil {
			return err
		}
		artifacts = append(artifacts, artifact{Path: slash(relative), SHA256: hash})
		return nil
	})
	if err != nil {
		return buildManifest{}, fmt.Errorf("inventory built site: %w", err)
	}
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	return buildManifest{
		SchemaVersion:   1,
		CanonicalBranch: m.config.CanonicalBranch,
		Inputs:          m.inputs,
		Routes:          m.routes,
		Artifacts:       artifacts,
	}, nil
}

func safeArtifactPath(m model, value string) (string, error) {
	artifactRoot, err := resolveInside(m.root, m.config.ArtifactDirectory, "artifactDirectory")
	if err != nil {
		return "", err
	}
	output, err := resolveInside(m.root, value, "output directory")
	if err != nil {
		return "", err
	}
	if output == artifactRoot || !isInside(artifactRoot, output) {
		return "", fmt.Errorf("output directory must be below %s", m.config.ArtifactDirectory)
	}
	if err := rejectSymlinkComponents(m.root, output); err != nil {
		return "", err
	}
	return output, nil
}

func safeArtifactFile(m model, value string) (string, error) {
	artifactRoot, err := resolveInside(m.root, m.config.ArtifactDirectory, "artifactDirectory")
	if err != nil {
		return "", err
	}
	output, err := resolveInside(m.root, value, "artifact file")
	if err != nil {
		return "", err
	}
	if !isInside(artifactRoot, output) {
		return "", fmt.Errorf("artifact file must be below %s", m.config.ArtifactDirectory)
	}
	if err := rejectSymlinkComponents(m.root, output); err != nil {
		return "", err
	}
	return output, nil
}

func existingDirectory(root, value, label string) (string, error) {
	path, err := resolveInside(root, value, label)
	if err != nil {
		return "", err
	}
	path, err = realExistingPath(root, path, label)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s %q: %w", label, value, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("%s %q is not a directory", label, value)
	}
	return path, nil
}

func existingFile(root, value, label string) (string, error) {
	path, err := resolveInside(root, value, label)
	if err != nil {
		return "", err
	}
	path, err = realExistingPath(root, path, label)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat %s %q: %w", label, value, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s %q is not a regular file", label, value)
	}
	return path, nil
}

func collectInput(root, value, label string) ([]sourceFile, error) {
	path, err := resolveInside(root, value, label)
	if err != nil {
		return nil, err
	}
	path, err = realExistingPath(root, path, label)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s %q: %w", label, value, err)
	}
	if info.Mode().IsRegular() {
		hash, err := fileHash(path)
		if err != nil {
			return nil, err
		}
		return []sourceFile{{Path: slash(value), Destination: slash(value), SHA256: hash}}, nil
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s %q is neither a regular file nor a directory", label, value)
	}
	result := make([]sourceFile, 0)
	err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if !entryInfo.Mode().IsRegular() {
			return fmt.Errorf("%s %q contains non-regular file %q", label, value, current)
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		hash, err := fileHash(current)
		if err != nil {
			return err
		}
		result = append(result, sourceFile{Path: slash(relative), Destination: slash(relative), SHA256: hash})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s %q: %w", label, value, err)
	}
	return result, nil
}

func realExistingPath(root, path, label string) (string, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s symlinks: %w", label, err)
	}
	if real != root && !isInside(root, real) {
		return "", fmt.Errorf("%s resolves outside repository root: %q", label, real)
	}
	return real, nil
}

func rejectSymlinkComponents(root, target string) error {
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect output path %q: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("output path contains symlink %q", current)
		}
	}
	return nil
}

func resolveInside(root, value, label string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s must be nonempty", label)
	}
	path := value
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	path = filepath.Clean(path)
	if path != root && !isInside(root, path) {
		return "", fmt.Errorf("%s %q escapes repository root", label, value)
	}
	return path, nil
}

func isInside(parent, child string) bool {
	relative, err := filepath.Rel(parent, child)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func samePath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}

func fileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %q: %w", path, err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("hash %q: %w", path, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func slash(value string) string {
	return filepath.ToSlash(filepath.Clean(value))
}
