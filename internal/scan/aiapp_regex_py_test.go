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

// FIX 3 (crewAI dogfood 2026-06-06): `message` and `query` were in the
// identifier allowlist, so the detector lit up on every exception
// subclass `__init__` and every SQL builder. 14 of 22 HIGH false
// positives on crewAI came from this. These tests pin the non-firings.

func TestPyPromptInjectionIgnoresExceptionMessageFString(t *testing.T) {
	// Idiomatic Python exception construction — every codebase has
	// dozens of these. Was a HIGH false positive in v0.5.0.
	src := `class BadConfigError(Exception):
    def __init__(self, cause):
        self.message = f"could not load config: {cause}"`
	hits := scanPromptInjectionPython("errors.py", src)
	if len(hits) != 0 {
		t.Errorf("self.message = f\"...\" in an Exception subclass is not prompt construction (got %d)", len(hits))
	}
}

func TestPyPromptInjectionIgnoresSQLQueryConcat(t *testing.T) {
	// SQL builder — string concat into a `query` variable. Real SQL
	// injection lives in a different detector (sql-injection); this
	// regex was emitting prompt-injection findings on it, which sent
	// users chasing the wrong root cause.
	src := `def list_users(role):
    query = "SELECT * FROM users WHERE role = '" + role + "'"
    return db.execute(query)`
	hits := scanPromptInjectionPython("db.py", src)
	if len(hits) != 0 {
		t.Errorf("query = \"SELECT ...\" + var is SQL building, not prompt construction (got %d)", len(hits))
	}
}

// FIX 4 (crewAI dogfood 2026-06-06): streamTruePyRe must require kwarg
// context (`(` or `,` before `stream=True`). Bare attribute assignments
// and variable bindings are not LLM calls. These tests pin the FPs that
// generated 9 of the medium FPs on crewAI.

func TestPyUnboundedStreamIgnoresSelfStreamAttributeAssignment(t *testing.T) {
	src := `class Worker:
    def __init__(self):
        self.stream = True
`
	hits := scanUnboundedStreamPython("worker.py", src)
	if len(hits) != 0 {
		t.Errorf("self.stream = True is attribute assignment, not an SDK kwarg (got %d)", len(hits))
	}
}

func TestPyUnboundedStreamIgnoresBareVariableAssignment(t *testing.T) {
	src := `def cfg():
    stream = True
    return stream
`
	hits := scanUnboundedStreamPython("cfg.py", src)
	if len(hits) != 0 {
		t.Errorf("bare `stream = True` is a variable binding, not an SDK kwarg (got %d)", len(hits))
	}
}

func TestPyPromptInjectionIgnoresSQLQueryFString(t *testing.T) {
	// F-string variant of the same SQL builder shape.
	src := `def lookup(table):
    query = f"SELECT * FROM {table}"
    return db.execute(query)`
	hits := scanPromptInjectionPython("db.py", src)
	if len(hits) != 0 {
		t.Errorf("query = f\"SELECT {table}\" is SQL building, not prompt construction (got %d)", len(hits))
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

// ── 0.5.5 FastAPI / async detector wave ─────────────────────────

func TestPyStreamNoGuardFiresOnUnguardedGenerator(t *testing.T) {
	src := `
async def token_stream(prompt):
    stream = await client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}],
        stream=True,
    )
    async for chunk in stream:
        yield chunk.choices[0].delta.content or ""`
	hits := scanPyStreamNoGuard("app/api/chat.py", src)
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].Category != "unbounded-stream" {
		t.Errorf("category=%q want unbounded-stream", hits[0].Category)
	}
}

func TestPyStreamNoGuardIgnoresDisconnectAndFinally(t *testing.T) {
	src := `
async def token_stream(prompt, request):
    stream = await client.chat.completions.create(messages=[], stream=True)
    try:
        async for chunk in stream:
            if await request.is_disconnected():
                break
            yield chunk
    finally:
        await stream.close()`
	if hits := scanPyStreamNoGuard("app/api/chat.py", src); len(hits) != 0 {
		t.Errorf("is_disconnected + finally is bounded, should not fire (got %d)", len(hits))
	}
}

func TestPyStreamNoGuardIgnoresGuardNamedOnlyInComment(t *testing.T) {
	// The fixture comment NAMES the missing guard; stripping must prevent
	// a false-suppress.
	src := `
async def token_stream(prompt):
    # no is_disconnected() check and no finally: here — that is the bug
    stream = await client.chat.completions.create(messages=[], stream=True)
    async for chunk in stream:
        yield chunk`
	if hits := scanPyStreamNoGuard("app/api/chat.py", src); len(hits) != 1 {
		t.Errorf("guard named only in a comment must not suppress (got %d)", len(hits))
	}
}

func TestPyStreamNoGuardFiresOnWebsocketLoop(t *testing.T) {
	src := `
async def agent_socket(websocket):
    await websocket.accept()
    while True:
        msg = await websocket.receive_text()
        await websocket.send_text(msg)`
	if hits := scanPyStreamNoGuard("app/ws.py", src); len(hits) != 1 {
		t.Errorf("websocket loop with no disconnect branch should fire (got %d)", len(hits))
	}
}

func TestPyHttpxStreamNoTimeoutFires(t *testing.T) {
	src := `
async def proxy(prompt):
    client = httpx.AsyncClient()
    async with client.stream("POST", URL, json=payload) as resp:
        async for line in resp.aiter_lines():
            yield line`
	if hits := scanPyHttpxStreamNoTimeout("app/proxy.py", src); len(hits) != 1 {
		t.Fatalf("AsyncClient() with no timeout + .stream should fire (got %d)", len(hits))
	}
}

func TestPyHttpxStreamNoTimeoutIgnoresTimeoutKwarg(t *testing.T) {
	src := `
async def proxy(prompt):
    client = httpx.AsyncClient(timeout=httpx.Timeout(30.0))
    async with client.stream("POST", URL) as resp:
        async for line in resp.aiter_lines():
            yield line`
	if hits := scanPyHttpxStreamNoTimeout("app/proxy.py", src); len(hits) != 0 {
		t.Errorf("timeout= present, should not fire (got %d)", len(hits))
	}
}

func TestPyShellToolArgFiresOnShellTrue(t *testing.T) {
	src := `
def run_shell(args):
    return subprocess.run(args.command, shell=True, capture_output=True)`
	if hits := scanPyShellToolArg("app/tools/shell.py", src); len(hits) != 1 {
		t.Fatalf("subprocess shell=True should fire (got %d)", len(hits))
	}
}

func TestPyShellToolArgIgnoresArgvList(t *testing.T) {
	src := `def run_ls(): return subprocess.run(["ls", "-la"], capture_output=True)`
	if hits := scanPyShellToolArg("app/tools/shell.py", src); len(hits) != 0 {
		t.Errorf("argv list without shell=True should not fire (got %d)", len(hits))
	}
}

func TestPySqlFStringFires(t *testing.T) {
	src := `def lookup(args): cursor.execute(f"SELECT * FROM users WHERE id = {args.user_id}")`
	if hits := scanPySqlFString("app/tools/db.py", src); len(hits) != 1 {
		t.Fatalf("f-string SQL should fire (got %d)", len(hits))
	}
}

func TestPySqlFStringIgnoresParameterized(t *testing.T) {
	src := `def lookup(args): cursor.execute("SELECT * FROM users WHERE id = ?", (args.user_id,))`
	if hits := scanPySqlFString("app/tools/db.py", src); len(hits) != 0 {
		t.Errorf("parameterized query should not fire (got %d)", len(hits))
	}
}

func TestPyDynamicRoleFiresOnBareIdentifier(t *testing.T) {
	src := `
def dispatch(req):
    role_input = req.role
    messages = [{"role": role_input, "content": req.content}]`
	if hits := scanPyDynamicRole("app/router.py", src); len(hits) != 1 {
		t.Fatalf("variable role should fire (got %d)", len(hits))
	}
}

func TestPyDynamicRoleIgnoresAllowlistedFile(t *testing.T) {
	src := `
ALLOWED_ROLES = {"user", "assistant", "system"}
def dispatch(req):
    if req.role not in ALLOWED_ROLES:
        raise ValueError("bad role")
    messages = [{"role": req.role, "content": req.content}]`
	if hits := scanPyDynamicRole("app/router.py", src); len(hits) != 0 {
		t.Errorf("allowlist-guarded role should not fire (got %d)", len(hits))
	}
}

func TestPyDynamicRoleIgnoresLiteralSystem(t *testing.T) {
	src := `messages = [{"role": "system", "content": text}]`
	if hits := scanPyDynamicRole("app/x.py", src); len(hits) != 0 {
		t.Errorf("literal role should not fire here (got %d)", len(hits))
	}
}

func TestPyPersonaPathRoleFires(t *testing.T) {
	src := `
class PersonaChat:
    def __init__(self, persona_name):
        text = open(f"personas/{persona_name}.txt").read()
        self.system_message = {"role": "system", "content": text}`
	if hits := scanPyPersonaPathRole("app/persona.py", src); len(hits) != 1 {
		t.Fatalf("open(f-string) + system role should fire (got %d)", len(hits))
	}
}

func TestPyPersonaPathRoleIgnoresWithoutSystemRole(t *testing.T) {
	src := `def load(name): return open(f"data/{name}.txt").read()`
	if hits := scanPyPersonaPathRole("app/loader.py", src); len(hits) != 0 {
		t.Errorf("no system role in file, should not fire (got %d)", len(hits))
	}
}

func TestPyKeyInResponseFires(t *testing.T) {
	src := `
@router.get("/config")
async def show_config():
    return {"model": settings.default_model, "api_key": settings.openai_api_key}`
	if hits := scanPyKeyInResponse("app/admin.py", src); len(hits) != 1 {
		t.Fatalf("api_key: settings.*key* in a returned dict should fire (got %d)", len(hits))
	}
}

func TestPyKeyInResponseIgnoresConstructorKwarg(t *testing.T) {
	src := `client = OpenAI(api_key=settings.openai_api_key)`
	if hits := scanPyKeyInResponse("app/client.py", src); len(hits) != 0 {
		t.Errorf("api_key= constructor kwarg (not a dict field) should not fire (got %d)", len(hits))
	}
}

func TestPyRagConcatFires(t *testing.T) {
	src := `
def answer(question, chunks):
    prompt = "Context:\n" + "\n".join(chunks) + "\nUser: " + question`
	if hits := scanPyRagConcat("app/rag.py", src); len(hits) != 1 {
		t.Fatalf("join-concat into prompt should fire (got %d)", len(hits))
	}
}

func TestPyRagConcatIgnoresDelimitedBuild(t *testing.T) {
	src := `
def build(user_message):
    return [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_message}]`
	if hits := scanPyRagConcat("app/builder.py", src); len(hits) != 0 {
		t.Errorf("delimited message build should not fire (got %d)", len(hits))
	}
}

func TestPyRowIntoPromptFires(t *testing.T) {
	src := `def build_prompt(profile_row): return f"Summarize this profile:\n{profile_row}"`
	if hits := scanPyRowIntoPrompt("app/profile.py", src); len(hits) != 1 {
		t.Fatalf("full row into f-string prompt should fire (got %d)", len(hits))
	}
}

func TestPyRowIntoPromptIgnoresProjectedContext(t *testing.T) {
	src := `def build(context): return f"User profile: {context}"`
	if hits := scanPyRowIntoPrompt("app/x.py", src); len(hits) != 0 {
		t.Errorf("projected context var (not a row) should not fire (got %d)", len(hits))
	}
}

// ── 0.5.6 CrewAI URM detectors ──────────────────────────────────

func TestPyCrewBackstoryInterpFires(t *testing.T) {
	src := `
from crewai import Agent
def build(user_topic):
    return Agent(role="researcher", goal="research",
                 backstory=f"You research: {user_topic}")`
	if hits := scanPyCrewBackstoryInterp("crew/agents/r.py", src); len(hits) != 1 {
		t.Fatalf("interpolated backstory should fire (got %d)", len(hits))
	}
}

func TestPyCrewBackstoryInterpIgnoresStaticBackstory(t *testing.T) {
	src := `
from crewai import Agent
def build():
    return Agent(role="researcher", goal="research",
                 backstory="You are a careful researcher. Stay factual.")`
	if hits := scanPyCrewBackstoryInterp("crew/agents/r.py", src); len(hits) != 0 {
		t.Errorf("static backstory should not fire (got %d)", len(hits))
	}
}

func TestPyCrewBackstoryInterpIgnoresAllowlistedFile(t *testing.T) {
	src := `
ALLOWED_ROLES = {"researcher", "writer"}
from crewai import Agent
def build(role):
    if role not in ALLOWED_ROLES:
        raise ValueError("bad role")
    return Agent(role=role, backstory=f"You are the {role}.")`
	if hits := scanPyCrewBackstoryInterp("crew/main_safe.py", src); len(hits) != 0 {
		t.Errorf("allowlist-guarded file should not fire (got %d)", len(hits))
	}
}

func TestPyCrewBackstoryFileFires(t *testing.T) {
	src := `
from crewai import Agent
def build(persona_name):
    return Agent(role="writer", backstory=open(f"personas/{persona_name}.txt").read())`
	if hits := scanPyCrewBackstoryFile("crew/agents/w.py", src); len(hits) != 1 {
		t.Fatalf("backstory from file should fire (got %d)", len(hits))
	}
}

func TestPyCrewAgentRoleFiresOnVariable(t *testing.T) {
	src := `
from crewai import Agent
def build(payload):
    return Agent(role=payload["role"], goal="analyze", backstory="static")`
	if hits := scanPyCrewAgentRole("crew/main.py", src); len(hits) != 1 {
		t.Fatalf("variable role= kwarg should fire (got %d)", len(hits))
	}
}

func TestPyCrewAgentRoleIgnoresLiteral(t *testing.T) {
	src := `Agent(role="manager", goal="coordinate", backstory="static")`
	if hits := scanPyCrewAgentRole("crew/main.py", src); len(hits) != 0 {
		t.Errorf("literal role= should not fire (got %d)", len(hits))
	}
}

func TestPyCrewAgentRoleIgnoresAllowlistedFile(t *testing.T) {
	src := `
ALLOWED_ROLES = {"a", "b"}
def build(role):
    return Agent(role=role, backstory="static")`
	if hits := scanPyCrewAgentRole("crew/main_safe.py", src); len(hits) != 0 {
		t.Errorf("allowlist-guarded role should not fire (got %d)", len(hits))
	}
}
