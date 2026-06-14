package scan

import "testing"

// All inputs carry an LLM-SDK marker so the gate (rbLlmMarkerRe) lets the
// detectors run.

func rbCats(src string) map[string]int {
	m := map[string]int{}
	for _, f := range scanAiAppRegexRuby("x.rb", src) {
		m[f.Category]++
	}
	return m
}

func TestRubyGateSilentWithoutLlmMarker(t *testing.T) {
	src := `class Helper
  def call(name)
    system_prompt = "You are #{name}"
    system_prompt
  end
end`
	if hits := scanAiAppRegexRuby("x.rb", src); len(hits) != 0 {
		t.Errorf("no LLM marker — gate should produce nothing (got %d)", len(hits))
	}
}

func TestRubyPromptInterpFires(t *testing.T) {
	src := `require "openai"
class Planner
  def call(params)
    system_prompt = "You are a planner. Objective: #{params[:objective]}"
    system_prompt
  end
end`
	if rbCats(src)["prompt-injection"] != 1 {
		t.Errorf("interpolated prompt should fire PI: %+v", rbCats(src))
	}
}

func TestRubyStaticPromptDoesNotFire(t *testing.T) {
	src := `require "openai"
class Planner
  def call
    system_prompt = "You are a planner."
    system_prompt
  end
end`
	if rbCats(src)["prompt-injection"] != 0 {
		t.Errorf("static prompt should not fire PI")
	}
}

func TestRubyPromptJoinFires(t *testing.T) {
	src := `require "openai"
class Rag
  def call(chunks, q)
    prompt = "Context:\n" + chunks.join("\n") + "\nQ: " + q
    prompt
  end
end`
	if rbCats(src)["prompt-injection"] != 1 {
		t.Errorf("join concat should fire PI: %+v", rbCats(src))
	}
}

func TestRubySystemInterpFires(t *testing.T) {
	src := `require "openai"
class Builder
  def call(user_role)
    messages = [{ role: "system", content: "Operate as: #{user_role}" }]
    messages
  end
end`
	if rbCats(src)["unsafe-role-merge"] != 1 {
		t.Errorf("system-role interpolation should fire URM: %+v", rbCats(src))
	}
}

func TestRubyDynamicRoleFiresIvarAndParamsAllowlistSuppresses(t *testing.T) {
	vuln := `require "openai"
class Router
  def call
    # role from request, no allowlist here
    messages = [{ role: @params[:role], content: @content }]
    messages
  end
end`
	if rbCats(vuln)["unsafe-role-merge"] != 1 {
		t.Errorf("@params[:role] dynamic role should fire URM: %+v", rbCats(vuln))
	}
	safe := `require "openai"
class Router
  ALLOWED_ROLES = %w[user assistant].freeze
  def call(role, content)
    raise "bad" unless ALLOWED_ROLES.include?(role)
    messages = [{ role: role, content: content }]
    messages
  end
end`
	if rbCats(safe)["unsafe-role-merge"] != 0 {
		t.Errorf("allowlist-guarded role should not fire URM: %+v", rbCats(safe))
	}
}

func TestRubyReadFileInterpFires(t *testing.T) {
	src := `require "openai"
class Persona
  def call(persona_name)
    system_text = File.read("personas/#{persona_name}.txt")
    system_text
  end
end`
	if rbCats(src)["unsafe-role-merge"] != 1 {
		t.Errorf("File.read interpolation should fire URM: %+v", rbCats(src))
	}
}

func TestRubyKeyInResponseFires(t *testing.T) {
	src := `require "openai"
class AdminController
  def config
    render json: { model: @config.model, api_key: ENV['OPENAI_API_KEY'] }
  end
end`
	if rbCats(src)["client-side-llm-key"] != 1 {
		t.Errorf("api_key: ENV[...] should fire CSK: %+v", rbCats(src))
	}
}

func TestRubyBacktickAndSystemAndSqlFire(t *testing.T) {
	bt := "require \"openai\"\nclass T\n  def call(args)\n    out = `#{args['command']}`\n    out\n  end\nend"
	if rbCats(bt)["unsafe-tool-output"] != 1 {
		t.Errorf("backtick exec should fire UTO: %+v", rbCats(bt))
	}
	sys := `require "openai"
class T
  def call(args)
    system("sh", "-c", args['cmd'])
  end
end`
	if rbCats(sys)["unsafe-tool-output"] != 1 {
		t.Errorf("system sh -c should fire UTO: %+v", rbCats(sys))
	}
	sql := `require "openai"
class T
  def call(args)
    ActiveRecord::Base.connection.execute("SELECT * FROM u WHERE id = #{args['id']}")
  end
end`
	if rbCats(sql)["unsafe-tool-output"] != 1 {
		t.Errorf("interpolated SQL should fire UTO: %+v", rbCats(sql))
	}
}

func TestRubySqlParameterizedDoesNotFire(t *testing.T) {
	src := `require "openai"
class T
  def call(args)
    ActiveRecord::Base.connection.exec_query("SELECT * FROM u WHERE id = ?", "q", [args['id']])
  end
end`
	if rbCats(src)["unsafe-tool-output"] != 0 {
		t.Errorf("parameterized exec_query should not fire UTO: %+v", rbCats(src))
	}
}

func TestRubyToJsonUserFiresProjectedDoesNot(t *testing.T) {
	vuln := `require "openai"
class Snap
  def call(user)
    context = user.to_json
    context
  end
end`
	if rbCats(vuln)["pii-in-prompt"] != 1 {
		t.Errorf("user.to_json should fire PIP: %+v", rbCats(vuln))
	}
	safe := `require "openai"
class Snap
  def call(user)
    context = { name: user.name, tier: user.tier }.to_json
    context
  end
end`
	if rbCats(safe)["pii-in-prompt"] != 0 {
		t.Errorf("projected .to_json should not fire PIP: %+v", rbCats(safe))
	}
}

func TestRubyStreamProcFiresTimeoutSuppresses(t *testing.T) {
	vuln := `require "openai"
class Live
  def call(msgs, stream_proc)
    @client = OpenAI::Client.new
    @client.chat(parameters: { model: "gpt-4o-mini", messages: msgs, stream: stream_proc })
  end
end`
	if rbCats(vuln)["unbounded-stream"] != 1 {
		t.Errorf("stream: proc with no request_timeout should fire UBS: %+v", rbCats(vuln))
	}
	safe := `require "openai"
class Live
  def call(msgs, stream_proc)
    @client = OpenAI::Client.new(request_timeout: 30)
    @client.chat(parameters: { messages: msgs, stream: stream_proc })
  end
end`
	if rbCats(safe)["unbounded-stream"] != 0 {
		t.Errorf("stream with request_timeout should not fire UBS: %+v", rbCats(safe))
	}
}

func TestRubyLiveStreamFiresEnsureSuppresses(t *testing.T) {
	vuln := `require "openai"
class SseController
  def stream
    loop do
      response.stream.write("data: #{chunk}\n\n")
    end
  end
end`
	if rbCats(vuln)["unbounded-stream"] != 1 {
		t.Errorf("response.stream.write with no ensure should fire UBS: %+v", rbCats(vuln))
	}
	safe := `require "openai"
class SseController
  def stream
    begin
      loop { response.stream.write("data: x\n\n"); break if Time.now > deadline }
    ensure
      response.stream.close
    end
  end
end`
	if rbCats(safe)["unbounded-stream"] != 0 {
		t.Errorf("ensure-guarded stream should not fire UBS: %+v", rbCats(safe))
	}
}
