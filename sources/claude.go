package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hoophq/rs/state"
	"github.com/hoophq/rs/types"
)

// Claude reads Claude Code sessions stored as append-only JSONL files at
// ~/.claude/projects/<project-slug>/<session-uuid>.jsonl.
type Claude struct {
	root string
}

func NewClaude(home string) *Claude {
	return &Claude{root: filepath.Join(home, ".claude", "projects")}
}

func (s *Claude) Name() string { return "claude" }

func (s *Claude) Discover(st *state.State) ([]types.Session, error) {
	projects, err := os.ReadDir(s.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var sessions []types.Session
	for _, project := range projects {
		if !project.IsDir() {
			continue
		}
		projectDir := filepath.Join(s.root, project.Name())
		entries, err := os.ReadDir(projectDir)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".jsonl") {
				continue
			}
			path := filepath.Join(projectDir, entry.Name())
			session, err := s.parseSession(path, project.Name(), st)
			if err != nil {
				return nil, fmt.Errorf("claude session %s: %w", path, err)
			}
			if session != nil {
				sessions = append(sessions, *session)
			}
		}
	}
	return sessions, nil
}

// claudeLine is one JSONL event. Only user/assistant message events carry
// conversation content; other event types (mode, attachment, snapshots) are
// metadata and skipped.
type claudeLine struct {
	Type      string          `json:"type"`
	UUID      string          `json:"uuid"`
	Timestamp string          `json:"timestamp"`
	Message   json.RawMessage `json:"message"`
}

type claudeMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (s *Claude) parseSession(path, project string, st *state.State) (*types.Session, error) {
	lines, newOffset, err := readJSONLines(path, st.Offset(path))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}

	session := &types.Session{
		Tool:    s.Name(),
		ID:      strings.TrimSuffix(filepath.Base(path), ".jsonl"),
		Project: project,
		Path:    path,
		Marks:   map[string]int64{path: newOffset},
	}
	for i, raw := range lines {
		var line claudeLine
		if err := json.Unmarshal(raw, &line); err != nil {
			// tolerate single malformed lines: agents may crash mid-write
			continue
		}
		if session.StartedAt.IsZero() && line.Timestamp != "" {
			if ts, err := time.Parse(time.RFC3339, line.Timestamp); err == nil {
				session.StartedAt = ts
			}
		}
		if line.Type != "user" && line.Type != "assistant" {
			continue
		}
		var msg claudeMessage
		if err := json.Unmarshal(line.Message, &msg); err != nil {
			continue
		}
		id := line.UUID
		if id == "" {
			id = fmt.Sprintf("line-%d", i)
		}
		text, toolOutput := extractContent(msg.Content)
		if text != "" {
			role := types.RoleAssistant
			if line.Type == "user" {
				role = types.RoleUser
			}
			session.Messages = append(session.Messages, types.Message{ID: id, Role: role, Text: text})
		}
		if toolOutput != "" {
			session.Messages = append(session.Messages, types.Message{ID: id + "/tool", Role: types.RoleTool, Text: toolOutput})
		}
	}
	if len(session.Messages) == 0 {
		return nil, nil
	}
	if session.StartedAt.IsZero() {
		session.StartedAt = fileModTime(path)
	}
	return session, nil
}
