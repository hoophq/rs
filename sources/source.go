// Package sources discovers and parses local AI coding sessions from
// supported tools (Claude Code, Cursor, OpenCode) into the normalized
// types.Session model.
package sources

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"time"

	"github.com/hoophq/rs/state"
	"github.com/hoophq/rs/types"
)

// Source discovers sessions on disk and parses the content appended since the
// last scan recorded in st. Returned sessions carry the state marks to commit
// once their content is successfully analyzed.
type Source interface {
	Name() string
	Discover(st *state.State) ([]types.Session, error)
}

// maxLineSize bounds a single JSONL line (agent transcripts can embed large
// tool outputs in one line).
const maxLineSize = 16 * 1024 * 1024

// readJSONLines reads complete JSON lines from path starting at offset and
// returns the raw lines plus the offset of the last fully terminated line.
// A trailing line without a newline is left for the next scan, since the tool
// may still be appending to it.
func readJSONLines(path string, offset int64) (lines []json.RawMessage, newOffset int64, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()

	if offset > 0 {
		info, err := f.Stat()
		if err != nil {
			return nil, offset, err
		}
		// the file was truncated/rewritten since the last scan: start over
		if offset > info.Size() {
			offset = 0
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, offset, err
		}
	}

	newOffset = offset
	reader := bufio.NewReaderSize(f, 256*1024)
	for {
		line, err := readFullLine(reader)
		if err == io.EOF {
			// partial trailing line: do not consume it
			return lines, newOffset, nil
		}
		if err != nil {
			return lines, newOffset, err
		}
		newOffset += int64(len(line))
		trimmed := trimLine(line)
		if len(trimmed) == 0 {
			continue
		}
		lines = append(lines, json.RawMessage(trimmed))
	}
}

// readFullLine reads one newline-terminated line of arbitrary length.
// io.EOF is returned for a trailing chunk that has no newline yet.
func readFullLine(r *bufio.Reader) ([]byte, error) {
	var full []byte
	for {
		chunk, err := r.ReadBytes('\n')
		full = append(full, chunk...)
		if err == nil {
			return full, nil
		}
		if err == io.EOF {
			return full, io.EOF
		}
		if len(full) > maxLineSize {
			return full, io.ErrShortBuffer
		}
		if err != bufio.ErrBufferFull && err != nil {
			return full, err
		}
	}
}

func trimLine(line []byte) []byte {
	for len(line) > 0 && (line[len(line)-1] == '\n' || line[len(line)-1] == '\r') {
		line = line[:len(line)-1]
	}
	return line
}

// contentBlock is the anthropic-style message content block used by both
// Claude Code and Cursor transcripts.
type contentBlock struct {
	Type    string          `json:"type"`
	Text    string          `json:"text"`
	Content json.RawMessage `json:"content"`
}

// extractContent splits an anthropic-style message content payload (string or
// block array) into the conversational text and the embedded tool outputs.
func extractContent(raw json.RawMessage) (text string, toolOutput string) {
	if len(raw) == 0 {
		return "", ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return asString, ""
	}
	var blocks []contentBlock
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return "", ""
	}
	for _, block := range blocks {
		switch block.Type {
		case "text":
			text = joinText(text, block.Text)
		case "tool_result":
			// tool_result content is a string or a nested block array
			nestedText, nestedTool := extractContent(block.Content)
			toolOutput = joinText(toolOutput, nestedText)
			toolOutput = joinText(toolOutput, nestedTool)
		}
	}
	return text, toolOutput
}

// fileModTime approximates a session start time for sources that do not
// record timestamps. Returns the zero time when the file cannot be stat-ed.
func fileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func joinText(current, next string) string {
	if next == "" {
		return current
	}
	if current == "" {
		return next
	}
	return current + "\n" + next
}
