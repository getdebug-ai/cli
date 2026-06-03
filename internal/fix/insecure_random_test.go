package fix

import (
	"strings"
	"testing"
)

func TestInsecureRandomBareCall(t *testing.T) {
	src := `const r = Math.random();`
	got := InsecureRandomPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: "Math.random()"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "crypto.getRandomValues") {
		t.Errorf("expected crypto.getRandomValues substitution; got:\n%s", got.Patched)
	}
	if strings.Contains(got.Patched, "Math.random()") {
		t.Errorf("Math.random() still present after patch:\n%s", got.Patched)
	}
}

// The replacement is parenthesised so arithmetic context composes — a
// regression here would change semantics (`x * Math.random()` →
// `x * crypto.getRandomValues(...)... / 4294967296` without parens
// would group wrong).
func TestInsecureRandomComposesInArithmeticContext(t *testing.T) {
	src := `const x = base * Math.random();`
	got := InsecureRandomPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: "Math.random()"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "base * (crypto.getRandomValues") {
		t.Errorf("expected parenthesised replacement preserving precedence; got:\n%s", got.Patched)
	}
}

// Drift safety: the line no longer has Math.random() — could be a stale
// finding, could be an alias. Either way, decline cleanly.
func TestInsecureRandomDriftDeclines(t *testing.T) {
	src := `const r = secureDraw();`
	got := InsecureRandomPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on drift, got OK with patched:\n%s", got.Patched)
	}
	if !strings.Contains(got.Reason, "drift") && !strings.Contains(got.Reason, "non-literal") {
		t.Errorf("decline reason should mention drift or non-literal; got %q", got.Reason)
	}
}

// Ambiguity safety: two Math.random() on one line — defer to manual.
func TestInsecureRandomMultipleHitsDeclines(t *testing.T) {
	src := `const r = Math.random() * Math.random();`
	got := InsecureRandomPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on multiple hits, got OK")
	}
	if !strings.Contains(got.Reason, "multiple") {
		t.Errorf("decline reason should mention multiple; got %q", got.Reason)
	}
}

// Out-of-range lineStart never panics.
func TestInsecureRandomLineOutOfRangeDeclines(t *testing.T) {
	src := `const x = 1;`
	got := InsecureRandomPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 99, LineEnd: 99},
	})
	if got.OK {
		t.Fatalf("expected decline on out-of-range line, got OK")
	}
}

func TestRegistryHasInsecureRandom(t *testing.T) {
	if Lookup("insecure-random") == nil {
		t.Fatal("insecure-random missing from Registry")
	}
}

// Unknown categories MUST return nil — the engine relies on this to skip
// instead of panicking.
func TestRegistryUnknownReturnsNil(t *testing.T) {
	if Lookup("sql-injection") != nil {
		t.Fatal("sql-injection should not have a local patcher (LLM-driven only)")
	}
	if Lookup("") != nil {
		t.Fatal("empty category should not have a patcher")
	}
}
