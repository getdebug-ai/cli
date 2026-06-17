package gitdiff

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestExpandByImporters_JSRelative(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"src/utils/auth.ts":  "export const check = () => true\n",
		"src/api/handler.ts": "import { check } from '../utils/auth'\nexport default check\n",
		"src/unrelated.ts":   "import { x } from './other'\n",
		"src/other.ts":       "export const x = 1\n",
	})
	changed := map[string]bool{"src/utils/auth.ts": true}

	out, added := ExpandByImporters(dir, changed, 1)
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if !out["src/api/handler.ts"] {
		t.Fatalf("want importer src/api/handler.ts in set, got %v", out)
	}
	if out["src/unrelated.ts"] {
		t.Fatalf("did not expect unrelated file, got %v", out)
	}
}

func TestExpandByImporters_PythonRelativeAndIndex(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"pkg/auth.py":    "def check():\n    return True\n",
		"pkg/handler.py": "from .auth import check\n",
		"lib/index.ts":   "export const v = 1\n",
		"app.ts":         "import { v } from './lib'\n", // resolves to lib (index alias)
	})

	out, _ := ExpandByImporters(dir, map[string]bool{"pkg/auth.py": true}, 1)
	if !out["pkg/handler.py"] {
		t.Fatalf("want pkg/handler.py (python relative import), got %v", out)
	}

	out2, _ := ExpandByImporters(dir, map[string]bool{"lib/index.ts": true}, 1)
	if !out2["app.ts"] {
		t.Fatalf("want app.ts (index alias import), got %v", out2)
	}
}

func TestExpandByImporters_GoPackagePath(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"go.mod":             "module example.com/m\n\ngo 1.21\n",
		"pkg/util/auth.go":   "package util\n\nfunc Check() bool { return true }\n",
		"pkg/api/handler.go": "package api\n\nimport \"example.com/m/pkg/util\"\n\nvar _ = util.Check\n",
		"pkg/other/x.go":     "package other\n\nimport \"fmt\"\n\nvar _ = fmt.Println\n",
	})
	out, added := ExpandByImporters(dir, map[string]bool{"pkg/util/auth.go": true}, 1)
	if added != 1 || !out["pkg/api/handler.go"] {
		t.Fatalf("want pkg/api/handler.go (imports the changed package), got %v (added=%d)", out, added)
	}
	if out["pkg/other/x.go"] {
		t.Fatalf("did not expect pkg/other/x.go (imports only fmt), got %v", out)
	}
}

func TestExpandByImporters_RubyRequireRelative(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"lib/auth.rb":      "def check; true; end\n",
		"app/handler.rb":   "require_relative '../lib/auth'\n",
		"app/unrelated.rb": "require 'json'\n",
	})
	out, _ := ExpandByImporters(dir, map[string]bool{"lib/auth.rb": true}, 1)
	if !out["app/handler.rb"] {
		t.Fatalf("want app/handler.rb (require_relative), got %v", out)
	}
	if out["app/unrelated.rb"] {
		t.Fatalf("did not expect app/unrelated.rb (bare require), got %v", out)
	}
}

func TestExpandByImporters_DepthZeroAndChaining(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a.ts": "export const a = 1\n",
		"b.ts": "import { a } from './a'\nexport const b = a\n", // imports a
		"c.ts": "import { b } from './b'\nexport const c = b\n", // imports b
	})
	changed := map[string]bool{"a.ts": true}

	// depth 0 — no expansion.
	if _, added := ExpandByImporters(dir, changed, 0); added != 0 {
		t.Fatalf("depth 0 added = %d, want 0", added)
	}
	// depth 1 — only direct importer b.
	out1, _ := ExpandByImporters(dir, changed, 1)
	if !out1["b.ts"] || out1["c.ts"] {
		t.Fatalf("depth 1 = %v, want b.ts only", out1)
	}
	// depth 2 — b then c (transitive caller).
	out2, _ := ExpandByImporters(dir, changed, 2)
	if !out2["b.ts"] || !out2["c.ts"] {
		t.Fatalf("depth 2 = %v, want b.ts and c.ts", out2)
	}
}
