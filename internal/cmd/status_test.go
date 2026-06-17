package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunCost(t *testing.T) {
	usd := func(f float64) *float64 { return &f }
	cases := []struct {
		name   string
		usd    *float64
		capped bool
		want   string
	}{
		{"no cost (older run)", nil, false, "-"},
		{"normal", usd(0.0123), false, "$0.0123"},
		{"budget-capped", usd(0.5), true, "$0.5000 ⚠cap"},
	}
	for _, c := range cases {
		if got := runCost(c.usd, c.capped); got != c.want {
			t.Errorf("%s: runCost = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRenderStatus_AICostColumn(t *testing.T) {
	// Drive the renderer through the wire shape the API returns, so the column
	// wiring (header + per-run cell) is exercised end to end on the CLI side.
	data := `{
      "user": {"email": "a@b.c"},
      "org": {"name": "Acme", "plan": "pro"},
      "recentRuns": [
        {"id":"1","project":"web","status":"completed","findings":2,"fixes":0,"estimatedCostUsd":0.0123,"budgetExceeded":false,"createdAt":"2026-06-17T00:00:00Z"},
        {"id":"2","project":"old","status":"completed","findings":0,"fixes":0,"estimatedCostUsd":null,"createdAt":"2026-06-17T00:00:00Z"},
        {"id":"3","project":"big","status":"completed","findings":1,"fixes":0,"estimatedCostUsd":0.5,"budgetExceeded":true,"createdAt":"2026-06-17T00:00:00Z"}
      ],
      "recentPRs": []
    }`
	var s statusResp
	if err := json.Unmarshal([]byte(data), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var buf bytes.Buffer
	renderStatus(&buf, &s)
	out := buf.String()

	for _, want := range []string{"AI COST", "$0.0123", "$0.5000 ⚠cap"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered status missing %q\n---\n%s", want, out)
		}
	}
}
