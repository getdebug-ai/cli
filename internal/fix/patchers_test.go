package fix

import (
	"strings"
	"testing"
)

// ── xss ──────────────────────────────────────────────────────────

func TestXssBasicSubstitution(t *testing.T) {
	src := `el.innerHTML = userInput;`
	got := XssPatcher(PatcherInput{
		Source: src, FilePath: "x.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: ".innerHTML = userInput"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "el.textContent = userInput;") {
		t.Errorf("expected textContent substitution; got:\n%s", got.Patched)
	}
}

// `==` (and `===`) must not match — they're equality checks, not
// assignments. Regression guard for a regex that doesn't filter them.
func TestXssDoesNotMatchEqualityCompare(t *testing.T) {
	src := `if (el.innerHTML == "x") {}`
	got := XssPatcher(PatcherInput{
		Source: src, FilePath: "x.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on equality compare, got OK:\n%s", got.Patched)
	}
}

func TestXssCompoundAssignDoesNotMatch(t *testing.T) {
	src := `el.innerHTML += chunk;`
	got := XssPatcher(PatcherInput{
		Source: src, FilePath: "x.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on compound assign, got OK:\n%s", got.Patched)
	}
}

// ── insecure-cors ────────────────────────────────────────────────

func TestInsecureCorsObjectLiteral(t *testing.T) {
	src := `const headers = { "Access-Control-Allow-Origin": "*" };`
	got := InsecureCorsPatcher(PatcherInput{
		Source: src, FilePath: "cors.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if strings.Contains(got.Patched, `"*"`) {
		t.Errorf("wildcard value should be gone; got:\n%s", got.Patched)
	}
	if !strings.Contains(got.Patched, "CORS_ALLOWED_ORIGIN") {
		t.Errorf("expected env-lookup replacement; got:\n%s", got.Patched)
	}
}

func TestInsecureCorsSetHeaderArgPair(t *testing.T) {
	src := `res.setHeader("Access-Control-Allow-Origin", "*");`
	got := InsecureCorsPatcher(PatcherInput{
		Source: src, FilePath: "cors.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "CORS_ALLOWED_ORIGIN") {
		t.Errorf("expected env-lookup replacement; got:\n%s", got.Patched)
	}
}

// A non-wildcard value should not be rewritten — only literal "*".
func TestInsecureCorsNonWildcardDeclines(t *testing.T) {
	src := `res.setHeader("Access-Control-Allow-Origin", "https://app.example.com");`
	got := InsecureCorsPatcher(PatcherInput{
		Source: src, FilePath: "cors.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on non-wildcard value, got OK:\n%s", got.Patched)
	}
}

// ── open-redirect ────────────────────────────────────────────────

func TestOpenRedirectBareIdentifier(t *testing.T) {
	src := `res.redirect(url);`
	got := OpenRedirectPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	for _, frag := range []string{`typeof url === "string"`, `url.startsWith("/")`, `!url.startsWith("//")`} {
		if !strings.Contains(got.Patched, frag) {
			t.Errorf("patched missing guard fragment %q; got:\n%s", frag, got.Patched)
		}
	}
}

// Function-call arg is the most common decline shape: the regex
// deliberately excludes parens in the arg so we don't truncate
// `req.query.next()` mid-expression.
func TestOpenRedirectFunctionCallArgDeclines(t *testing.T) {
	src := `res.redirect(searchParams.get("next"));`
	got := OpenRedirectPatcher(PatcherInput{
		Source: src, FilePath: "r.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline on function-call arg, got OK:\n%s", got.Patched)
	}
}

// ── client-side-llm-key ──────────────────────────────────────────

func TestClientSideLlmKeyStripsNextPublic(t *testing.T) {
	src := `const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;`
	got := ClientSideLlmKeyPatcher(PatcherInput{
		Source: src, FilePath: "key.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: "NEXT_PUBLIC_OPENAI_API_KEY"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if strings.Contains(got.Patched, "NEXT_PUBLIC_OPENAI_API_KEY") {
		t.Errorf("prefix should be stripped from the env var; got:\n%s", got.Patched)
	}
	if !strings.Contains(got.Patched, "process.env.OPENAI_API_KEY") {
		t.Errorf("expected stripped env var; got:\n%s", got.Patched)
	}
	if !strings.Contains(got.Patched, "removed NEXT_PUBLIC_ prefix") {
		t.Errorf("expected explainer comment; got:\n%s", got.Patched)
	}
}

func TestClientSideLlmKeyPreservesIndent(t *testing.T) {
	src := "function load() {\n    const k = process.env.VITE_ANTHROPIC_KEY;\n}\n"
	got := ClientSideLlmKeyPatcher(PatcherInput{
		Source: src, FilePath: "key.ts",
		Match: MatchSite{LineStart: 2, LineEnd: 2, MatchedSpan: "VITE_ANTHROPIC_KEY"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "    // getdebug: removed VITE_ prefix") {
		t.Errorf("comment should match source indentation; got:\n%s", got.Patched)
	}
}

func TestClientSideLlmKeyUnknownPrefixDeclines(t *testing.T) {
	src := `const k = process.env.MY_OWN_PUBLIC_API_KEY;`
	got := ClientSideLlmKeyPatcher(PatcherInput{
		Source: src, FilePath: "key.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1, MatchedSpan: "MY_OWN_PUBLIC_API_KEY"},
	})
	if got.OK {
		t.Fatalf("expected decline on unknown prefix, got OK")
	}
}

// ── unbounded-stream ─────────────────────────────────────────────

func TestUnboundedStreamInsertsAbortController(t *testing.T) {
	src := "const r = await openai.chat.completions.create({\n  model: \"gpt-4\",\n  stream: true,\n});"
	got := UnboundedStreamPatcher(PatcherInput{
		Source: src, FilePath: "stream.ts",
		Match: MatchSite{LineStart: 3, LineEnd: 3},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "const controller = new AbortController();") {
		t.Errorf("expected AbortController declaration; got:\n%s", got.Patched)
	}
	if !strings.Contains(got.Patched, "signal: controller.signal,") {
		t.Errorf("expected signal option; got:\n%s", got.Patched)
	}
}

// decoder.decode({ stream: true }) is the Web Streams API — must decline
// hard. Regression guard for the false positive recorded in the TS doc.
func TestUnboundedStreamRefusesWebStreamsAPI(t *testing.T) {
	src := `const out = decoder.decode(chunk, { stream: true });`
	got := UnboundedStreamPatcher(PatcherInput{
		Source: src, FilePath: "stream.ts",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected hard decline on TextDecoder, got OK:\n%s", got.Patched)
	}
	if !strings.Contains(got.Reason, "Web Streams API") {
		t.Errorf("decline reason should call out the false positive; got %q", got.Reason)
	}
}

func TestUnboundedStreamDeclinesWhenNoLlmCallNearby(t *testing.T) {
	src := "const opts = {\n  stream: true,\n};"
	got := UnboundedStreamPatcher(PatcherInput{
		Source: src, FilePath: "stream.ts",
		Match: MatchSite{LineStart: 2, LineEnd: 2},
	})
	if got.OK {
		t.Fatalf("expected decline when no LLM call sits above, got OK:\n%s", got.Patched)
	}
}

// ── dependency-cve ───────────────────────────────────────────────

func TestDependencyCveRequirementsTxtBump(t *testing.T) {
	src := "flask==1.0\nrequests==2.25.0\n"
	got := DependencyCvePatcher(PatcherInput{
		Source: src, FilePath: "requirements.txt",
		Match:   MatchSite{LineStart: 2, LineEnd: 2},
		Context: map[string]string{"packageName": "requests", "fixedVersion": "2.32.0"},
	})
	if !got.OK {
		t.Fatalf("expected OK, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "requests==2.32.0") {
		t.Errorf("expected requests bumped to 2.32.0; got:\n%s", got.Patched)
	}
	if !strings.Contains(got.Patched, "flask==1.0") {
		t.Errorf("untouched line should be preserved; got:\n%s", got.Patched)
	}
}

// Range operators get stripped from the fixedVersion field.
func TestDependencyCveStripsRangeFromFixedVersion(t *testing.T) {
	src := "flask==1.0\n"
	got := DependencyCvePatcher(PatcherInput{
		Source: src, FilePath: "requirements.txt",
		Match:   MatchSite{LineStart: 1, LineEnd: 1},
		Context: map[string]string{"packageName": "flask", "fixedVersion": ">=2.3.2,<3"},
	})
	if !got.OK {
		t.Fatalf("expected OK after stripping range operator, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "flask==2.3.2") {
		t.Errorf("expected flask==2.3.2 after range strip; got:\n%s", got.Patched)
	}
}

// PEP 503 normalisation lets the patcher match Flask-Login when the
// manifest pins flask_login.
func TestDependencyCveNormalisedNameMatch(t *testing.T) {
	src := "flask_login==0.6.0\n"
	got := DependencyCvePatcher(PatcherInput{
		Source: src, FilePath: "requirements.txt",
		Match:   MatchSite{LineStart: 1, LineEnd: 1},
		Context: map[string]string{"packageName": "Flask-Login", "fixedVersion": "0.6.3"},
	})
	if !got.OK {
		t.Fatalf("expected OK with normalised name match, got reason=%q", got.Reason)
	}
	if !strings.Contains(got.Patched, "flask_login==0.6.3") {
		t.Errorf("expected flask_login bumped; got:\n%s", got.Patched)
	}
}

// JS lockfile hit → manual-command result, NOT a patch.
func TestDependencyCveJsLockfileReturnsManualCommand(t *testing.T) {
	got := DependencyCvePatcher(PatcherInput{
		Source: "{}\n", FilePath: "pnpm-lock.yaml",
		Match:   MatchSite{LineStart: 1, LineEnd: 1},
		Context: map[string]string{"packageName": "lodash", "fixedVersion": "4.17.21"},
	})
	if got.OK {
		t.Fatalf("expected decline on lockfile, got OK")
	}
	if !strings.Contains(got.ManualCommand, "pnpm update lodash@4.17.21") {
		t.Errorf("expected pnpm command in ManualCommand, got %q", got.ManualCommand)
	}
}

func TestDependencyCveGoModReturnsManualCommand(t *testing.T) {
	got := DependencyCvePatcher(PatcherInput{
		Source: "module x\n", FilePath: "go.mod",
		Match:   MatchSite{LineStart: 1, LineEnd: 1},
		Context: map[string]string{"packageName": "golang.org/x/net", "fixedVersion": "0.23.0"},
	})
	if got.OK {
		t.Fatalf("expected decline on go.mod, got OK")
	}
	if !strings.Contains(got.ManualCommand, "go get golang.org/x/net@v0.23.0") {
		t.Errorf("expected go get command in ManualCommand, got %q", got.ManualCommand)
	}
	if !strings.Contains(got.ManualCommand, "go mod tidy") {
		t.Errorf("manual command should chain `go mod tidy`; got %q", got.ManualCommand)
	}
}

func TestDependencyCveNoContextDeclines(t *testing.T) {
	got := DependencyCvePatcher(PatcherInput{
		Source: "flask==1.0\n", FilePath: "requirements.txt",
		Match: MatchSite{LineStart: 1, LineEnd: 1},
	})
	if got.OK {
		t.Fatalf("expected decline when context is missing, got OK")
	}
}

// ── Registry coverage ────────────────────────────────────────────

// Locks in the full set of categories the local engine claims to fix.
// A future drop has to update this list explicitly, which is the point.
func TestRegistryContainsAllExpectedCategories(t *testing.T) {
	want := []string{
		"client-side-llm-key",
		"dependency-cve",
		"insecure-cors",
		"insecure-random",
		"open-redirect",
		"unbounded-stream",
		"weak-crypto",
		"xss",
	}
	for _, cat := range want {
		if Lookup(cat) == nil {
			t.Errorf("Registry missing %q", cat)
		}
	}
	if len(Registry) != len(want) {
		t.Errorf("Registry size = %d, want %d (drift in either direction is suspicious)", len(Registry), len(want))
	}
}
