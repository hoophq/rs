// Package state persists incremental scan progress so re-runs only analyze
// content appended since the previous scan.
package state

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// State maps file paths to the byte offset already consumed. JSONL session
// files (Claude, Cursor) are append-only, so an offset describes the processed
// prefix. OpenCode part files are immutable once written, so hooprs marks them
// consumed at their full size.
type State struct {
	path  string
	Files map[string]int64 `json:"files"`
}

// NewMemory returns an empty, file-less state for full snapshot scans that do
// not persist progress: every Offset lookup returns 0, so the sources read all
// available content. Never Save a memory state.
func NewMemory() *State {
	return &State{Files: map[string]int64{}}
}

// Load reads the state file at path, returning an empty state when the file
// does not exist yet.
func Load(path string) (*State, error) {
	st := &State{path: path, Files: map[string]int64{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	if st.Files == nil {
		st.Files = map[string]int64{}
	}
	return st, nil
}

// Offset returns the consumed byte offset for a file (0 when never scanned).
func (s *State) Offset(path string) int64 { return s.Files[path] }

// Mark records the consumed byte offset for a file.
func (s *State) Mark(path string, offset int64) { s.Files[path] = offset }

// Reset clears all recorded progress (used by full re-scans).
func (s *State) Reset() { s.Files = map[string]int64{} }

// Save atomically writes the state file, creating parent directories as needed.
func (s *State) Save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
