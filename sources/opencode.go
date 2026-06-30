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

// OpenCode reads OpenCode sessions stored as sharded JSON files:
//
//	<storage>/session/<projectID>/<sessionID>.json  session metadata
//	<storage>/message/<sessionID>/<messageID>.json  message metadata (role)
//	<storage>/part/<messageID>/<partID>.json        content parts
//
// Storage roots covered: ~/.local/share/opencode/storage (global) and
// ~/.local/share/opencode/project/*/storage (per-project, newer layouts).
// Part files are immutable once written, so incremental state marks each
// consumed part file at its full size.
type OpenCode struct {
	dataDir string
}

func NewOpenCode(home string) *OpenCode {
	return &OpenCode{dataDir: filepath.Join(home, ".local", "share", "opencode")}
}

func (s *OpenCode) Name() string { return "opencode" }

func (s *OpenCode) storageRoots() ([]string, error) {
	var roots []string
	global := filepath.Join(s.dataDir, "storage")
	if dirExists(global) {
		roots = append(roots, global)
	}
	projectsDir := filepath.Join(s.dataDir, "project")
	entries, err := os.ReadDir(projectsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return roots, nil
	}
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		root := filepath.Join(projectsDir, entry.Name(), "storage")
		if dirExists(root) {
			roots = append(roots, root)
		}
	}
	return roots, nil
}

func (s *OpenCode) Discover(st *state.State) ([]types.Session, error) {
	roots, err := s.storageRoots()
	if err != nil {
		return nil, err
	}
	var sessions []types.Session
	for _, root := range roots {
		rootSessions, err := s.discoverRoot(root, st)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, rootSessions...)
	}
	return sessions, nil
}

type opencodeSession struct {
	ID        string `json:"id"`
	ProjectID string `json:"projectID"`
	Directory string `json:"directory"`
	Time      struct {
		// Created is a unix timestamp in milliseconds
		Created int64 `json:"created"`
	} `json:"time"`
}

type opencodeMessage struct {
	ID   string `json:"id"`
	Role string `json:"role"`
}

// opencodePart is a message content part. Text and reasoning parts carry the
// content inline; tool parts carry the command output in state.output.
type opencodePart struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	State struct {
		Output string `json:"output"`
	} `json:"state"`
}

func (s *OpenCode) discoverRoot(root string, st *state.State) ([]types.Session, error) {
	sessionDir := filepath.Join(root, "session")
	projects, err := os.ReadDir(sessionDir)
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
		entries, err := os.ReadDir(filepath.Join(sessionDir, project.Name()))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(sessionDir, project.Name(), entry.Name())
			session, err := s.parseSession(root, path, st)
			if err != nil {
				return nil, fmt.Errorf("opencode session %s: %w", path, err)
			}
			if session != nil {
				sessions = append(sessions, *session)
			}
		}
	}
	return sessions, nil
}

func (s *OpenCode) parseSession(root, metaPath string, st *state.State) (*types.Session, error) {
	var meta opencodeSession
	if err := readJSONFile(metaPath, &meta); err != nil {
		return nil, err
	}
	if meta.ID == "" {
		return nil, nil
	}

	project := meta.Directory
	if project == "" {
		project = meta.ProjectID
	}
	session := &types.Session{
		Tool:    s.Name(),
		ID:      meta.ID,
		Project: project,
		Path:    metaPath,
		Marks:   map[string]int64{},
	}
	if meta.Time.Created > 0 {
		session.StartedAt = time.UnixMilli(meta.Time.Created).UTC()
	} else {
		session.StartedAt = fileModTime(metaPath)
	}

	messageDir := filepath.Join(root, "message", meta.ID)
	messageFiles, err := os.ReadDir(messageDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	for _, msgFile := range messageFiles {
		if msgFile.IsDir() || !strings.HasSuffix(msgFile.Name(), ".json") {
			continue
		}
		var msg opencodeMessage
		if err := readJSONFile(filepath.Join(messageDir, msgFile.Name()), &msg); err != nil {
			// tolerate single malformed files: opencode may be mid-write
			continue
		}
		if msg.ID == "" || (msg.Role != "user" && msg.Role != "assistant") {
			continue
		}
		if err := s.collectParts(root, msg, session, st); err != nil {
			return nil, err
		}
	}
	// sessions without new text content may still carry marks for consumed
	// non-text parts; returning them lets the scanner commit those marks so
	// the files are not re-read on every run
	if len(session.Messages) == 0 && len(session.Marks) == 0 {
		return nil, nil
	}
	return session, nil
}

func (s *OpenCode) collectParts(root string, msg opencodeMessage, session *types.Session, st *state.State) error {
	partDir := filepath.Join(root, "part", msg.ID)
	partFiles, err := os.ReadDir(partDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	role := types.RoleAssistant
	if msg.Role == "user" {
		role = types.RoleUser
	}
	for _, partFile := range partFiles {
		if partFile.IsDir() || !strings.HasSuffix(partFile.Name(), ".json") {
			continue
		}
		path := filepath.Join(partDir, partFile.Name())
		info, err := partFile.Info()
		if err != nil {
			return err
		}
		// already consumed in a previous scan
		if st.Offset(path) >= info.Size() && info.Size() > 0 {
			continue
		}
		var part opencodePart
		if err := readJSONFile(path, &part); err != nil {
			continue
		}
		partID := strings.TrimSuffix(partFile.Name(), ".json")
		switch part.Type {
		case "text", "reasoning":
			if part.Text != "" {
				session.Messages = append(session.Messages, types.Message{
					ID:   msg.ID + "/" + partID,
					Role: role,
					Text: part.Text,
				})
			}
		case "tool":
			if part.State.Output != "" {
				session.Messages = append(session.Messages, types.Message{
					ID:   msg.ID + "/" + partID,
					Role: types.RoleTool,
					Text: part.State.Output,
				})
			}
		}
		session.Marks[path] = info.Size()
	}
	return nil
}

func readJSONFile(path string, into any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
