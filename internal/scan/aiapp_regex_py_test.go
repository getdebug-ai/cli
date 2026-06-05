package scan

import "testing"

// ── pii-in-prompt (Python) ──────────────────────────────────────

func TestPyPiiInPromptDetectsJsonDumpsUserInMessages(t *testing.T) {
	src := `
import openai
def f(user):
    openai.OpenAI().chat.completions.create(
        messages=[{"role": "user", "content": json.dumps(user)}],
    )`
	hits := scanPiiInPromptPython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "pii-in-prompt" {
		t.Errorf("category=%q want pii-in-prompt", hits[0].Category)
	}
}

func TestPyPiiInPromptIgnoresReductionVar(t *testing.T) {
	src := `
import openai
def f(user):
    safe_ctx = {"name": user.name}
    openai.OpenAI().chat.completions.create(
        messages=[{"role": "user", "content": json.dumps(safe_ctx)}],
    )`
	hits := scanPiiInPromptPython("app.py", src)
	if len(hits) != 0 {
		t.Errorf("safe_ctx is not in user-shape allowlist, should not fire (got %d)", len(hits))
	}
}

func TestPyPiiInPromptIgnoresLogContext(t *testing.T) {
	src := `def log(user): print(json.dumps(user))`
	hits := scanPiiInPromptPython("logger.py", src)
	if len(hits) != 0 {
		t.Errorf("no LLM-call marker nearby, should not fire (got %d)", len(hits))
	}
}

// ── unsafe-role-merge (Python) ─────────────────────────────────

func TestPyUnsafeRoleMergeDetectsFStringInSystem(t *testing.T) {
	src := `messages=[
  {"role": "system", "content": f"You are an assistant for a {persona}."},
  {"role": "user", "content": q},
]`
	hits := scanUnsafeRoleMergePython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1, got %d: %+v", len(hits), hits)
	}
}

func TestPyUnsafeRoleMergeIgnoresInterpolationInOtherRole(t *testing.T) {
	src := `messages=[
  {"role": "system", "content": SYSTEM_PROMPT},
  {"role": "user", "content": f"I am a {persona}."},
]`
	hits := scanUnsafeRoleMergePython("app.py", src)
	if len(hits) != 0 {
		t.Errorf("interpolation in user-role, should not fire (got %d)", len(hits))
	}
}

// ── prompt-injection (Python) ──────────────────────────────────

func TestPyPromptInjectionDetectsConcat(t *testing.T) {
	src := `prompt = "You are a translator. " + user_question`
	hits := scanPromptInjectionPython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1, got %d", len(hits))
	}
}

func TestPyPromptInjectionDetectsFString(t *testing.T) {
	src := `prompt = f"You are a translator. {user_question}"`
	hits := scanPromptInjectionPython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1, got %d", len(hits))
	}
}

func TestPyPromptInjectionIgnoresConstantSystem(t *testing.T) {
	src := `SYSTEM_PROMPT = "You are a translator."`
	hits := scanPromptInjectionPython("app.py", src)
	if len(hits) != 0 {
		t.Errorf("constant literal, should not fire (got %d)", len(hits))
	}
}

// ── unbounded-stream (Python) ──────────────────────────────────

func TestPyUnboundedStreamDetectsStreamTrueNoBound(t *testing.T) {
	src := `def f():
    chunks = client.chat.completions.create(stream=True, model="x", messages=[])
    for c in chunks: yield c`
	hits := scanUnboundedStreamPython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1, got %d", len(hits))
	}
}

func TestPyUnboundedStreamIgnoresWithBlock(t *testing.T) {
	src := `def f():
    with client.chat.completions.create(stream=True, timeout=30, model="x", messages=[]) as chunks:
        for c in chunks: yield c`
	hits := scanUnboundedStreamPython("app.py", src)
	if len(hits) != 0 {
		t.Errorf("with-block bounds the stream, should not fire (got %d)", len(hits))
	}
}

// Regression: a comment containing 'with' / 'timeout' / 'abort' must
// NOT satisfy the bound-stream check (caught during py-calib testing).
func TestPyUnboundedStreamIgnoresBoundMarkerInComment(t *testing.T) {
	src := `def f():
    # VULN: stream=True with no abort/timeout/with-block
    chunks = client.chat.completions.create(stream=True, model="x", messages=[])
    for c in chunks: yield c`
	hits := scanUnboundedStreamPython("app.py", src)
	if len(hits) != 1 {
		t.Errorf("comment mentions should not satisfy bound-check (got %d)", len(hits))
	}
}

// ── unsafe-tool-output (Python) ────────────────────────────────

func TestPyUnsafeToolOutputDetectsSubprocessRunToolCall(t *testing.T) {
	src := `import subprocess
def h(tool_call):
    return subprocess.run(tool_call.input.command, shell=True)`
	hits := scanUnsafeToolOutputPython("app.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1, got %d", len(hits))
	}
}

func TestPyUnsafeToolOutputIgnoresAllowlistedRun(t *testing.T) {
	src := `import subprocess
ALLOWED = {"x": "uptime"}
def h(tool_call):
    cmd = ALLOWED.get(tool_call.input.tag)
    return subprocess.run(cmd, shell=True)`
	hits := scanUnsafeToolOutputPython("app.py", src)
	if len(hits) != 0 {
		t.Errorf("allowlist-then-run is safe, should not fire (got %d)", len(hits))
	}
}
