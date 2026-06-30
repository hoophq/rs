// Package types holds the domain model shared by every package: normalized
// sessions and messages collected from local AI coding tools.
package types

import "time"

// Role classifies who produced a message. It sets the guardrail direction for
// analysis: input rules check user content, output rules check assistant and
// tool content.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	// RoleTool marks tool/command outputs embedded in a conversation
	// (e.g. Claude tool_result blocks, OpenCode tool part outputs).
	RoleTool Role = "tool"
)

// GuardrailDirection maps a message role to the guardrail direction.
func (r Role) GuardrailDirection() string {
	if r == RoleUser {
		return "input"
	}
	return "output"
}

// Message is a single normalized conversation entry.
type Message struct {
	ID   string
	Role Role
	Text string
}

// Session is a normalized AI coding session with the content that still
// needs analysis (sources only return messages not yet recorded in state).
type Session struct {
	// Tool is the source tool name: claude, cursor or opencode
	Tool string
	// ID is the tool-native session identifier
	ID string
	// Project identifies the workspace the session belongs to
	Project string
	// Path is the on-disk location of the session data
	Path string
	// StartedAt is the session start time when the tool records it, or a
	// file-modification-time approximation otherwise. Zero when unknown.
	StartedAt time.Time
	// Messages contains the new (not yet analyzed) content
	Messages []Message
	// Marks are the state entries (file path -> consumed byte offset) to be
	// committed after the session content is successfully analyzed.
	Marks map[string]int64
}
