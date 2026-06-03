package fix

import (
	"strings"
	"testing"
)

func TestWeakCryptoJsCreateHashMd5(t *testing.T) {
	src := `import crypto from "crypto";
const h = crypto.createHash("md5").update(s).digest("hex");
`
	got := WeakCryptoPatcher(PatcherInput{
		Source:   src,
		FilePath: "src/h.ts",
		Match:    MatchSite{LineStart: 2, LineEnd: 2, MatchedSpan: `createHash("md5")`},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, `createHash("sha256")`) {
		t.Errorf("expected sha256 substitution; got:\n%s", got.Patched)
	}
	if strings.Contains(got.Patched, `"md5"`) {
		t.Errorf("MD5 still present after patch:\n%s", got.Patched)
	}
	if !strings.Contains(got.Description, "SHA-256") {
		t.Errorf("description should explain the change; got %q", got.Description)
	}
}

func TestWeakCryptoJsCreateHmacSha1SingleQuotes(t *testing.T) {
	src := `const h = crypto.createHmac('sha1', secret).update(s).digest('hex');`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: `createHmac('sha1', secret)`},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, `createHmac('sha256', secret)`) {
		t.Errorf("expected sha256 with single quotes preserved; got:\n%s", got.Patched)
	}
}

func TestWeakCryptoPythonHashlibMd5(t *testing.T) {
	src := `import hashlib
h = hashlib.md5(data).hexdigest()
`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.py",
		Match: MatchSite{LineStart: 2, LineEnd: 2, MatchedSpan: "hashlib.md5(data)"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "hashlib.sha256(data)") {
		t.Errorf("expected hashlib.sha256; got:\n%s", got.Patched)
	}
}

func TestWeakCryptoPythonHashlibNewSha1(t *testing.T) {
	src := `h = hashlib.new("sha1", data)`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.py",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: `hashlib.new("sha1", data)`},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, `hashlib.new("sha256"`) {
		t.Errorf("expected hashlib.new(\"sha256\"); got:\n%s", got.Patched)
	}
}

// Drift safety: the matched line no longer contains an md5/sha1 call.
// We must decline, never invent a fix.
func TestWeakCryptoDriftDeclines(t *testing.T) {
	src := `const h = crypto.createHash("sha256").update(s);`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: ""},
	})
	if got.OK {
		t.Fatalf("expected decline on drift, got OK with patched:\n%s", got.Patched)
	}
	if !strings.Contains(got.Reason, "drift") {
		t.Errorf("decline reason should mention drift; got %q", got.Reason)
	}
}

// Ambiguity safety: two weak-hash calls on one line — defer to manual.
// Rewriting blindly might touch the wrong one.
func TestWeakCryptoMultipleHitsDeclines(t *testing.T) {
	src := `const a = crypto.createHash("md5"); const b = crypto.createHash("sha1");`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: ""},
	})
	if got.OK {
		t.Fatalf("expected decline on multiple hits, got OK")
	}
	if !strings.Contains(got.Reason, "multiple") {
		t.Errorf("decline reason should mention multiple; got %q", got.Reason)
	}
}

// Out-of-range lineStart: never panic, never invent a fix.
func TestWeakCryptoLineOutOfRangeDeclines(t *testing.T) {
	src := `const h = "ok";`
	got := WeakCryptoPatcher(PatcherInput{
		Source: src, FilePath: "h.ts",
		Match: MatchSite{LineStart: 99, LineEnd: 99},
	})
	if got.OK {
		t.Fatalf("expected decline on out-of-range line, got OK")
	}
}

// The Registry entry must exist and resolve to the right function — the
// fix command picks the patcher off the registry, so a missing entry
// silently makes the category unfixable.
func TestRegistryHasWeakCrypto(t *testing.T) {
	if Lookup("weak-crypto") == nil {
		t.Fatal("weak-crypto missing from Registry")
	}
}
