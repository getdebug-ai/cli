// Simple line-based chunking for the local-mode indexer.
//
// v0.2 first cut: 30 lines per chunk, 5-line overlap between adjacent
// chunks. Not semantically aware — a function may be split across
// chunks, a 3-line helper may share a chunk with unrelated code. The
// trade-off is staying pure Go: tree-sitter bindings require CGO and
// would force a cross-compile matrix change.
//
// When the local mode has user traction we'll port chunkFile from
// workers/src/parse/chunk.ts (see workers/src/code-index.ts) for
// semantic-unit chunks. For now line-based is honest, predictable,
// and good enough for "find me where validate-input lives" search.

package localchunk

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/getdebug-ai/cli/internal/localindex"
)

const (
	linesPerChunk = 30
	overlap       = 5
	// Skip anything bigger than this — generated bundles, fixtures, etc.
	maxFileBytes = 512 * 1024
)

// SKIP_DIRS mirrors the Node walker (workers/src/parse/walk.ts) so the
// local and server paths agree on what's "source code" vs "noise."
var skipDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	".next":        {},
	".turbo":       {},
	".cache":       {},
	"dist":         {},
	"build":        {},
	".venv":        {},
	"venv":         {},
	"__pycache__":  {},
	"vendor":       {},
	"target":       {},
	".getdebug-backup-": {}, // any backup dir from `getdebug fix --apply`
}

// Extension → language mapping. Small, expandable. Only what we'd actually
// want to embed for code intel.
var langByExt = map[string]string{
	".ts":   "typescript",
	".tsx":  "tsx",
	".js":   "javascript",
	".jsx":  "javascript",
	".mjs":  "javascript",
	".cjs":  "javascript",
	".py":   "python",
	".go":   "go",
	".rs":   "rust",
	".java": "java",
	".kt":   "kotlin",
	".rb":   "ruby",
	".php":  "php",
	".cs":   "csharp",
	".swift": "swift",
	".sql":  "sql",
	".md":   "markdown",
	".sh":   "shell",
	".yaml": "yaml",
	".yml":  "yaml",
	".json": "json",
}

// ChunkRepo walks root and yields chunks. Returns the count of files
// considered so the caller can show progress. Errors on per-file reads
// are logged via the callback (if non-nil) but don't abort the walk.
func ChunkRepo(root string, onFileError func(path string, err error)) ([]localindex.Chunk, int, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, 0, fmt.Errorf("abs %q: %w", root, err)
	}
	var chunks []localindex.Chunk
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			if onFileError != nil {
				onFileError(path, werr)
			}
			// Don't abort the whole walk on one unreadable dir.
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		// Reject symlinks for both files and directories. WalkDir resolves
		// the dirent's type via Lstat (no follow), so this catches them
		// before they're descended into. A repo with `.tooling -> /etc`
		// would otherwise let the indexer slurp system files into the
		// local pgvector store — and in the hosted path, ship them to the
		// embedding provider.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if _, skip := skipDirs[name]; skip {
				return fs.SkipDir
			}
			// Pattern match for prefixed names like .getdebug-backup-<ts>.
			for prefix := range skipDirs {
				if strings.HasSuffix(prefix, "-") && strings.HasPrefix(name, prefix) {
					return fs.SkipDir
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		lang, ok := langByExt[ext]
		if !ok {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if onFileError != nil {
				onFileError(path, err)
			}
			return nil
		}
		if info.Size() > maxFileBytes {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}

		fileChunks, err := chunkFile(path, rel, lang)
		if err != nil {
			if onFileError != nil {
				onFileError(path, err)
			}
			return nil
		}
		files++
		chunks = append(chunks, fileChunks...)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return chunks, files, nil
}

// chunkFile reads a single source file and splits it into overlapping
// line windows. Each chunk carries enough context (rel_path + line range
// + the actual content) for search results to be useful.
func chunkFile(absPath, relPath, language string) ([]localindex.Chunk, error) {
	f, err := os.Open(absPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	// Allow long lines (minified bundles, generated configs).
	buf := make([]byte, 0, 64*1024)
	sc.Buffer(buf, 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if !utf8.ValidString(l) {
			// Binary-ish content; bail on the whole file rather than ship
			// garbage to the embedding model.
			return nil, nil
		}
		lines = append(lines, l)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}

	step := linesPerChunk - overlap
	if step <= 0 {
		step = 1
	}
	var out []localindex.Chunk
	for start := 0; start < len(lines); start += step {
		end := start + linesPerChunk
		if end > len(lines) {
			end = len(lines)
		}
		body := strings.Join(lines[start:end], "\n")
		out = append(out, localindex.Chunk{
			RelPath:     relPath,
			Language:    language,
			Kind:        "lines",
			LineStart:   start + 1,
			LineEnd:     end,
			ContentText: body,
			ContentHash: hashChunk(relPath, language, start+1, end, body),
		})
		if end == len(lines) {
			break
		}
	}
	return out, nil
}

func hashChunk(relPath, lang string, lineStart, lineEnd int, body string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%d\x00", relPath, lang, lineStart, lineEnd)
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}
