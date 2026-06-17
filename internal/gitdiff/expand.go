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
// Resolution is precise (relative-path, not basename) for JS/TS and Python — the
// AI-app languages — so it doesn't over-pull on common names like `index`. Go
// (package-path imports) and Ruby aren't resolved; their files only enter the
// set via depth-0. This is the honest tradeoff, logged by the caller.

var sourceExts = map[string]bool{
	".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true, ".svelte": true,
	".py": true,
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
		if stems := importStemsFor(rel, string(body)); len(stems) > 0 {
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
func importStemsFor(relPath, content string) []string {
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
