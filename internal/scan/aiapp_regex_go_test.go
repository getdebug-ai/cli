package scan

import "testing"

// All inputs carry an LLM-SDK marker ("openai"/"anthropic") so the
// activation gate (goLlmMarkerRe) lets the detectors run.

func goCats(src string) map[string]int {
	m := map[string]int{}
	for _, f := range scanAiAppRegexGo("x.go", src) {
		m[f.Category]++
	}
	return m
}

func TestGoGateSilentWithoutLlmMarker(t *testing.T) {
	src := `package x
func run(objective string) string {
	prompt := fmt.Sprintf("Do this: %s", objective)
	return prompt
}`
	if hits := scanAiAppRegexGo("x.go", src); len(hits) != 0 {
		t.Errorf("no LLM marker — gate should produce nothing (got %d)", len(hits))
	}
}

func TestGoPromptSprintfFires(t *testing.T) {
	src := `package x
import "github.com/openai/openai-go"
func run(objective string) {
	systemPrompt := fmt.Sprintf("You are an agent. Objective: %s", objective)
	_ = systemPrompt
}`
	if goCats(src)["prompt-injection"] != 1 {
		t.Errorf("fmt.Sprintf prompt should fire PI once: %+v", goCats(src))
	}
}

func TestGoStaticPromptDoesNotFire(t *testing.T) {
	src := `package x
import "github.com/openai/openai-go"
func run() { systemPrompt := "You are an agent."; _ = systemPrompt }`
	if goCats(src)["prompt-injection"] != 0 {
		t.Errorf("static prompt should not fire PI")
	}
}

func TestGoPromptJoinFires(t *testing.T) {
	src := `package x
import "github.com/openai/openai-go"
func run(chunks []string, q string) {
	prompt := "Context:\n" + strings.Join(chunks, "\n") + "\nQ: " + q
	_ = prompt
}`
	if goCats(src)["prompt-injection"] != 1 {
		t.Errorf("strings.Join concat should fire PI: %+v", goCats(src))
	}
}

func TestGoSystemInterpFires(t *testing.T) {
	src := `package x
import "github.com/anthropics/anthropic-sdk-go"
func run(role string) {
	_ = anthropic.MessageNewParams{System: anthropic.F(fmt.Sprintf("You are %s", role))}
}`
	if goCats(src)["unsafe-role-merge"] != 1 {
		t.Errorf("System: fmt.Sprintf should fire URM: %+v", goCats(src))
	}
}

func TestGoDynamicRoleFiresAndAllowlistSuppresses(t *testing.T) {
	vuln := `package x
import "github.com/openai/openai-go"
// role with no allowlist here
func run(incomingRole, content string) {
	_ = openai.ChatCompletionMessage{Role: incomingRole, Content: content}
}`
	if goCats(vuln)["unsafe-role-merge"] != 1 {
		t.Errorf("dynamic role should fire URM: %+v", goCats(vuln))
	}
	safe := `package x
import "github.com/openai/openai-go"
func run(incomingRole, content string) {
	allowed := map[string]bool{"user": true, "assistant": true}
	if !allowed[incomingRole] { return }
	_ = openai.ChatCompletionMessage{Role: incomingRole, Content: content}
}`
	if goCats(safe)["unsafe-role-merge"] != 0 {
		t.Errorf("allowlist-guarded role should not fire URM: %+v", goCats(safe))
	}
}

func TestGoReadFileInterpFires(t *testing.T) {
	src := `package x
import "github.com/anthropics/anthropic-sdk-go"
func run(name string) {
	data, _ := os.ReadFile(fmt.Sprintf("personas/%s.txt", name))
	_ = data
}`
	if goCats(src)["unsafe-role-merge"] != 1 {
		t.Errorf("os.ReadFile(fmt.Sprintf) should fire URM: %+v", goCats(src))
	}
}

func TestGoKeyInResponseFiresIncludingMultiDot(t *testing.T) {
	src := `package x
import "github.com/openai/openai-go"
func cfgHandler(w http.ResponseWriter, h *AdminHandler) {
	json.NewEncoder(w).Encode(map[string]string{"model": h.cfg.Model, "api_key": h.cfg.APIKey})
}`
	if goCats(src)["client-side-llm-key"] != 1 {
		t.Errorf("api_key: h.cfg.APIKey should fire CSK: %+v", goCats(src))
	}
}

func TestGoExecShellFiresArgvDoesNot(t *testing.T) {
	vuln := `package x
import "github.com/openai/openai-go"
func tool(args struct{ Command string }) {
	out, _ := exec.Command("sh", "-c", args.Command).CombinedOutput()
	_ = out
}`
	if goCats(vuln)["unsafe-tool-output"] != 1 {
		t.Errorf("exec sh -c should fire UTO: %+v", goCats(vuln))
	}
	safe := `package x
import "github.com/openai/openai-go"
func tool() { _, _ = exec.Command("ls", "-la").CombinedOutput() }`
	if goCats(safe)["unsafe-tool-output"] != 0 {
		t.Errorf("argv exec should not fire UTO")
	}
}

func TestGoSqlFmtFiresParamDoesNot(t *testing.T) {
	vuln := `package x
import "github.com/openai/openai-go"
func tool(db *sql.DB, args struct{ UserID string }) {
	rows, _ := db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %s", args.UserID))
	_ = rows
}`
	if goCats(vuln)["unsafe-tool-output"] != 1 {
		t.Errorf("fmt.Sprintf SQL should fire UTO: %+v", goCats(vuln))
	}
	safe := `package x
import "github.com/openai/openai-go"
func tool(db *sql.DB, id string) { rows, _ := db.Query("SELECT * FROM u WHERE id = $1", id); _ = rows }`
	if goCats(safe)["unsafe-tool-output"] != 0 {
		t.Errorf("parameterized query should not fire UTO")
	}
}

func TestGoMarshalUserFiresProjectedDoesNot(t *testing.T) {
	vuln := `package x
import "github.com/openai/openai-go"
func snap(user User) { blob, _ := json.Marshal(user); _ = blob }`
	if goCats(vuln)["pii-in-prompt"] != 1 {
		t.Errorf("json.Marshal(user) should fire PIP: %+v", goCats(vuln))
	}
	safe := `package x
import "github.com/openai/openai-go"
func snap(user User) {
	safe := struct{ Name string }{user.Name}
	blob, _ := json.Marshal(safe); _ = blob
}`
	if goCats(safe)["pii-in-prompt"] != 0 {
		t.Errorf("json.Marshal(projected) should not fire PIP: %+v", goCats(safe))
	}
}

func TestGoStreamBackgroundFiresTimeoutDoesNot(t *testing.T) {
	vuln := `package x
import "github.com/anthropics/anthropic-sdk-go"
func live(client *anthropic.Client, params anthropic.MessageNewParams) {
	stream := client.Messages.NewStreaming(context.Background(), params)
	_ = stream
}`
	if goCats(vuln)["unbounded-stream"] != 1 {
		t.Errorf("NewStreaming(context.Background()) should fire UBS: %+v", goCats(vuln))
	}
	safe := `package x
import "github.com/anthropics/anthropic-sdk-go"
func live(client *anthropic.Client, params anthropic.MessageNewParams) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	stream := client.Messages.NewStreaming(ctx, params)
	_ = stream
}`
	if goCats(safe)["unbounded-stream"] != 0 {
		t.Errorf("NewStreaming(ctx-with-timeout) should not fire UBS: %+v", goCats(safe))
	}
}

func TestGoHttpNoTimeoutFires(t *testing.T) {
	src := `package x
import "github.com/openai/openai-go"
func proxy(req *http.Request) {
	httpClient := &http.Client{}
	resp, _ := httpClient.Do(req)
	_ = resp
}`
	if goCats(src)["unbounded-stream"] != 1 {
		t.Errorf("&http.Client{} should fire UBS: %+v", goCats(src))
	}
}
