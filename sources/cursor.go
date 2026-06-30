package sources

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/hoophq/rs/state"
	"github.com/hoophq/rs/types"
)

// Cursor reads Cursor agent transcripts stored as append-only JSONL files at
// ~/.cursor/projects/<project-slug>/agent-transcripts/<uuid>/<uuid>.jsonl
// (older layouts place the .jsonl directly under agent-transcripts/).
type Cursor struct {
	root string
}

func NewCursor(home string) *Cursor {
	return &Cursor{root: filepath.Join(home, ".cursor", "projects")}
}

func (s *Cursor) Name() string { return "cursor" }

func (s *Cursor) Discover(st *state.State) ([]types.Session, error) {
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
		transcriptsDir := filepath.Join(s.root, project.Name(), "agent-transcripts")
		paths, err := transcriptFiles(transcriptsDir)
		if err != nil {
			return nil, err
		}
		for _, path := range paths {
			session, err := s.parseSession(path, project.Name(), st)
			if err != nil {
				return nil, fmt.Errorf("cursor session %s: %w", path, err)
			}
			if session != nil {
				sessions = append(sessions, *session)
			}
		}
	}
	return sessions, nil
}

// transcriptFiles lists transcript JSONL paths, supporting both the nested
// (<uuid>/<uuid>.jsonl) and flat (<uuid>.jsonl) layouts.
func transcriptFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if entry.IsDir() {
			nested, err := os.ReadDir(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, err
			}
			for _, file := range nested {
				if !file.IsDir() && strings.HasSuffix(file.Name(), ".jsonl") {
					paths = append(paths, filepath.Join(dir, entry.Name(), file.Name()))
				}
			}
			continue
		}
		if strings.HasSuffix(entry.Name(), ".jsonl") {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	return paths, nil
}

// cursorLine is one transcript JSONL entry: {role, message:{content:[blocks]}}.
type cursorLine struct {
	Role    string `json:"role"`
	Message struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
}

func (s *Cursor) parseSession(path, project string, st *state.State) (*types.Session, error) {
	startOffset := st.Offset(path)
	lines, newOffset, err := readJSONLines(path, startOffset)
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
		var line cursorLine
		if err := json.Unmarshal(raw, &line); err != nil {
			continue
		}
		if line.Role != "user" && line.Role != "assistant" {
			continue
		}
		// IDs are positional: offset-qualified so they stay unique across
		// incremental scans of the same file
		id := fmt.Sprintf("line-%d-%d", startOffset, i)
		text, toolOutput := extractContent(line.Message.Content)
		if text != "" {
			role := types.RoleAssistant
			if line.Role == "user" {
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
	// cursor transcripts carry no timestamps: approximate with file mtime
	session.StartedAt = fileModTime(path)
	return session, nil
}
