package gitdiff

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Depth-N diff scoping: grow the changed-file set to include files that IMPORT a
// changed file (its callers), so a change to a shared util also re-scans the
// handlers that depend on it — the gap a literal depth-0 diff scan misses.
//
// Resolution is precise (not basename matching, so it doesn't over-pull on
// common names like `index`): relative specifiers for JS/TS + Ruby
// (require_relative), relative + absolute-from-root for Python, and
// module-path → package-dir for Go (via go.mod). A language whose import can't
// be resolved (e.g. Go without a go.mod, Ruby bare `require`) simply doesn't
// expand — those files still enter the set via depth-0.

var sourceExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".svelte": true,
	".py": true,
	".go": true,
	".rb": true,
}

var expandSkipDirs = map[string]bool{
	"node_modules": true, ".git": true, "vendor": true, "dist": true, "build": true,
	".next": true, "__pycache__": true, ".venv": true, "venv": true, ".turbo": true,
}

var (
	jsSpecRes = []*regexp.Regexp{
		regexp.MustCompile(`from\s+['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s+['"]([^'"]+)['"]`),
		regexp.MustCompile(`import\s*\(\s*['"]([^'"]+)['"]\s*\)`), // dynamic import()
		regexp.MustCompile(`require\(\s*['"]([^'"]+)['"]\s*\)`),
	}
	pyFromRe   = regexp.MustCompile(`(?m)^\s*from\s+(\.*[\w.]*)\s+import\b`)
	pyImportRe = regexp.MustCompile(`(?m)^\s*import\s+([\w.]+)`)
	// Go: quoted import paths, both `import "x"` and within `import ( … )`.
	goImportRe      = regexp.MustCompile(`"([^"\n]+)"`)
	goImportBlockRe = regexp.MustCompile(`(?s)import\s*\((.*?)\)`)
	goImportLineRe  = regexp.MustCompile(`(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"\n]+)"`)
	// Ruby: require_relative is resolvable (relative to the file's dir); bare
	// `require` uses the load path and is too ambiguous to map to a file.
	rbRequireRelRe = regexp.MustCompile(`require_relative\s+['"]([^'"]+)['"]`)
	goModuleRe     = regexp.MustCompile(`(?m)^\s*module\s+(\S+)`)
)

// ExpandByImporters grows `changed` to include files that import any file in the
// set, up to `depth` hops. Returns the expanded set and how many files were
// added. depth <= 0 (or an empty set) returns the set unchanged.
func ExpandByImporters(workdir string, changed map[string]bool, depth int) (map[string]bool, int) {
	out := make(map[string]bool, len(changed))
	for f := range changed {
		out[f] = true
	}
	if depth <= 0 || len(changed) == 0 {
		return out, 0
	}

	// Go imports name a package PATH (module + dir), so we need the module path
	// from go.mod to map an import back to a repo-relative directory. Absent =>
	// Go files are indexed but their imports won't resolve (depth-0 for Go).
	goModule := readGoModule(workdir)

	// Index every source file once: file → the workdir-relative, extension-less
	// stems it imports from within the repo.
	imports := map[string][]string{}
	_ = filepath.WalkDir(workdir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if expandSkipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rel, relErr := filepath.Rel(workdir, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if stems := importStemsFor(rel, string(body), goModule); len(stems) > 0 {
			imports[rel] = stems
		}
		return nil
	})

	added := 0
	frontier := changed
	for hop := 0; hop < depth; hop++ {
		targets := changedStems(frontier)
		next := map[string]bool{}
		for file, stems := range imports {
			if out[file] {
				continue
			}
			for _, s := range stems {
				if targets[s] {
					next[file] = true
					break
				}
			}
		}
		if len(next) == 0 {
			break
		}
		for f := range next {
			out[f] = true
			added++
		}
		frontier = next
	}
	return out, added
}

// changedStems maps a set of changed files to the import-target stems that would
// resolve to them: the extension-less path, plus the directory for index files
// (so `import './utils'` matches a changed `utils/index.ts`).
func changedStems(files map[string]bool) map[string]bool {
	out := map[string]bool{}
	for f := range files {
		// Go imports a package (directory), not a file — target the dir so any
		// importer of the package is pulled in for a change to any file in it.
		if strings.ToLower(filepath.Ext(f)) == ".go" {
			out[filepath.ToSlash(filepath.Dir(f))] = true
			continue
		}
		stem := stripExt(f)
		out[stem] = true
		base := f[strings.LastIndex(f, "/")+1:]
		if name := stripExt(base); name == "index" || name == "__init__" {
			out[filepath.ToSlash(filepath.Dir(f))] = true
		}
	}
	return out
}

// importStemsFor returns the workdir-relative, extension-less stems that the
// file at relPath imports from within the repo (relative specs for JS/TS;
// relative + absolute-from-root for Python). Package/3rd-party imports are
// dropped — they're not files we scan.
func importStemsFor(relPath, content, goModule string) []string {
	ext := strings.ToLower(filepath.Ext(relPath))
	dir := filepath.ToSlash(filepath.Dir(relPath))
	var stems []string
	switch {
	case ext == ".py":
		for _, m := range pyFromRe.FindAllStringSubmatch(content, -1) {
			if s := pyResolve(dir, m[1]); s != "" {
				stems = append(stems, s)
			}
		}
		for _, m := range pyImportRe.FindAllStringSubmatch(content, -1) {
			if s := pyResolve(dir, m[1]); s != "" {
				stems = append(stems, s)
			}
		}
	case ext == ".go":
		if goModule == "" {
			break // can't map package paths to dirs without the module path
		}
		prefix := goModule + "/"
		add := func(path string) {
			if strings.HasPrefix(path, prefix) {
				// Import path → repo-relative package DIR (matches changedStems).
				stems = append(stems, strings.TrimPrefix(path, prefix))
			}
		}
		for _, blk := range goImportBlockRe.FindAllStringSubmatch(content, -1) {
			for _, m := range goImportRe.FindAllStringSubmatch(blk[1], -1) {
				add(m[1])
			}
		}
		for _, m := range goImportLineRe.FindAllStringSubmatch(content, -1) {
			add(m[1])
		}
	case ext == ".rb":
		for _, m := range rbRequireRelRe.FindAllStringSubmatch(content, -1) {
			stems = append(stems, normStem(filepath.Join(dir, m[1])))
		}
	default: // JS/TS family
		for _, re := range jsSpecRes {
			for _, m := range re.FindAllStringSubmatch(content, -1) {
				spec := m[1]
				if !strings.HasPrefix(spec, ".") {
					continue // bare specifier = package, not a local file
				}
				stems = append(stems, normStem(filepath.Join(dir, spec)))
			}
		}
	}
	return stems
}

// readGoModule returns the module path from workdir/go.mod, or "" if absent.
// Go import paths are module-rooted, so without this Go imports can't be mapped
// back to repo files (those files then only enter the set via depth-0).
func readGoModule(workdir string) string {
	body, err := os.ReadFile(filepath.Join(workdir, "go.mod"))
	if err != nil {
		return ""
	}
	if m := goModuleRe.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1]))
	}
	return ""
}

// pyResolve maps a Python import target to a workdir-relative stem. Relative
// (dotted) imports resolve against the importer's directory; absolute imports
// resolve from the workdir root (the common intra-repo package layout).
func pyResolve(dir, spec string) string {
	if spec == "" {
		return ""
	}
	if strings.HasPrefix(spec, ".") {
		dots := len(spec) - len(strings.TrimLeft(spec, "."))
		rest := strings.ReplaceAll(spec[dots:], ".", "/")
		base := dir
		for i := 1; i < dots; i++ {
			base = filepath.Dir(base)
		}
		if rest == "" {
			return "" // `from . import x` — the package itself, too ambiguous
		}
		return normStem(filepath.Join(base, rest))
	}
	return normStem(strings.ReplaceAll(spec, ".", "/"))
}

func normStem(p string) string {
	p = filepath.ToSlash(filepath.Clean(p))
	if p == "." {
		return ""
	}
	return stripExt(p)
}

func stripExt(p string) string {
	if ext := filepath.Ext(p); ext != "" {
		return p[:len(p)-len(ext)]
	}
	return p
}
