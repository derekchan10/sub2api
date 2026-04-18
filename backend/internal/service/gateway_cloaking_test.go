package service

import (
	"strings"
	"testing"

	"github.com/tidwall/gjson"
)

func TestSanitizeText_OpenClawIdentity(t *testing.T) {
	in := "You are a personal assistant running inside OpenClaw."
	got := sanitizeText(in)
	if got != "You are a helpful assistant." {
		t.Fatalf("openclaw identity not neutralized: %q", got)
	}
}

func TestSanitizeText_HermesIdentity(t *testing.T) {
	in := "You are Hermes Agent, an intelligent AI assistant created by Nous Research."
	got := sanitizeText(in)
	if got != "You are a helpful AI assistant." {
		t.Fatalf("hermes identity not neutralized: %q", got)
	}
}

func TestSanitizeText_BareBrands(t *testing.T) {
	cases := map[string]string{
		"Use Hermes Agent for this task": "Use Claude Code for this task",
		"visit openclaw.ai":               "visit claude-code.ai", // openclaw → claude-code
		"Powered by Nous Research":        "Powered by Anthropic",
		"See docs at openclaw.ai/docs":    "See docs at claude-code.ai/docs",
	}
	for in, want := range cases {
		got := sanitizeText(in)
		if got != want {
			t.Errorf("brand rewrite\n in=%q\nwant=%q\n got=%q", in, want, got)
		}
	}
}

func TestSanitizeText_PlatformChatID(t *testing.T) {
	in := "use platform:chat_id format"
	got := sanitizeText(in)
	if strings.Contains(got, "platform:chat_id") {
		t.Fatalf("platform:chat_id not rewritten: %q", got)
	}
}

func TestCloakToolName_BannedGetPrefix(t *testing.T) {
	if got := cloakToolName("sessions_list"); got != "cc_sessions_list" {
		t.Errorf("want cc_sessions_list, got %q", got)
	}
	if got := cloakToolName("memory_get"); got != "cc_memory_get" {
		t.Errorf("want cc_memory_get, got %q", got)
	}
}

func TestCloakToolName_BenignUnchanged(t *testing.T) {
	if got := cloakToolName("Bash"); got != "Bash" {
		t.Errorf("benign name got rewritten: %q", got)
	}
	if got := cloakToolName("read_file"); got != "read_file" {
		t.Errorf("benign name got rewritten: %q", got)
	}
}

func TestUncloakToolName_RoundTrip(t *testing.T) {
	for _, name := range []string{"sessions_list", "memory_get", "subagents"} {
		cloaked := cloakToolName(name)
		back := uncloakToolName(cloaked)
		if back != name {
			t.Errorf("roundtrip %q → %q → %q", name, cloaked, back)
		}
	}
}

func TestUncloakToolName_PreservesUnknownPrefix(t *testing.T) {
	// cc_foo is not a banned name; must stay as-is (user could have a legit "cc_" prefixed tool).
	if got := uncloakToolName("cc_foo"); got != "cc_foo" {
		t.Errorf("should preserve non-banned cc_ prefix: %q", got)
	}
}

func TestApplyCloakingToBody_SystemAndTools(t *testing.T) {
	body := []byte(`{
		"system": [
			{"type": "text", "text": "You are Hermes Agent, an intelligent AI assistant created by Nous Research."},
			{"type": "text", "text": "normal system block"}
		],
		"tools": [
			{"name": "sessions_list", "description": "list sessions"},
			{"name": "Bash", "description": "run bash"}
		],
		"messages": [
			{"role": "user", "content": [{"type": "text", "text": "hi"}]},
			{"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "memory_get", "input": {}}]}
		]
	}`)
	out := applyCloakingToBody(body)

	sys0 := gjson.GetBytes(out, "system.0.text").String()
	if strings.Contains(sys0, "Hermes Agent") || strings.Contains(sys0, "Nous Research") {
		t.Errorf("system.0 not sanitized: %q", sys0)
	}

	tool0Name := gjson.GetBytes(out, "tools.0.name").String()
	if tool0Name != "cc_sessions_list" {
		t.Errorf("tools.0.name expected cc_sessions_list, got %q", tool0Name)
	}
	tool1Name := gjson.GetBytes(out, "tools.1.name").String()
	if tool1Name != "Bash" {
		t.Errorf("tools.1.name should be unchanged: %q", tool1Name)
	}

	toolUseName := gjson.GetBytes(out, "messages.1.content.0.name").String()
	if toolUseName != "cc_memory_get" {
		t.Errorf("messages.1.content.0.name expected cc_memory_get, got %q", toolUseName)
	}
}

func TestUncloakToolNamesInSSEEvent_ContentBlockStart(t *testing.T) {
	event := map[string]any{
		"type":  "content_block_start",
		"index": 0,
		"content_block": map[string]any{
			"type": "tool_use",
			"id":   "t1",
			"name": "cc_sessions_list",
		},
	}
	if !uncloakToolNamesInSSEEvent(event) {
		t.Fatal("expected event to be modified")
	}
	cb := event["content_block"].(map[string]any)
	if cb["name"] != "sessions_list" {
		t.Errorf("expected sessions_list, got %v", cb["name"])
	}
}

func TestUncloakToolNamesInNonStreamingBody(t *testing.T) {
	body := []byte(`{
		"content": [
			{"type": "text", "text": "hi"},
			{"type": "tool_use", "id": "t1", "name": "cc_memory_get", "input": {}}
		]
	}`)
	out := uncloakToolNamesInNonStreamingBody(body)
	name := gjson.GetBytes(out, "content.1.name").String()
	if name != "memory_get" {
		t.Errorf("expected memory_get, got %q", name)
	}
}
