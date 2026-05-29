// Local-only code intelligence index.
//
// CLAUDE.md Rule 2 (--local-only): nothing reaches getdebug's servers.
// Chunks + embeddings live in a sqlite DB at ~/.getdebug/projects/<id>/.
// Cosine similarity is brute-forced in-process — fine at the ~30k chunks
// a typical single-repo dev sees, so we skip the sqlite-vec extension
// dance (would require CGO, conflicts with our pure-Go cross-compile).
//
// Storage layout:
//
//   ~/.getdebug/projects/<project-key>/
//     index.db        ← sqlite with chunks + embeddings (vector as BLOB)
//     manifest.json   ← model, dim, last-indexed-sha, last-indexed-at
//
// project-key is sha256(git_origin_url) when set, else sha256(repo_root).
// The same repo cloned on two machines maps to the same key by default
// (so a future "sync your local index" feature can work), but two repos
// at the same path on different machines are still distinct.

package localindex

import (
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go sqlite, no cgo
)

const schemaVersion = 1

// Chunk is what the indexer hands us — minimal enough to be language-agnostic.
type Chunk struct {
	RelPath     string
	Language    string
	Kind        string // "lines" for v0.2 first cut; "function|method|class|module" once tree-sitter ports
	LineStart   int
	LineEnd     int
	ContentText string
	ContentHash string
}

// SearchResult mirrors the server-side shape so the CLI renderer can be shared.
type SearchResult struct {
	ChunkID   string
	RelPath   string
	Language  string
	Kind      string
	LineStart int
	LineEnd   int
	Score     float64 // 1 - cosine_distance; higher is better
	Content   string
}

// Manifest sits next to index.db so we can detect model/dim mismatches
// without opening the DB.
type Manifest struct {
	SchemaVersion   int       `json:"schemaVersion"`
	Model           string    `json:"model"`
	Dim             int       `json:"dim"`
	LastIndexedSha  string    `json:"lastIndexedSha,omitempty"`
	LastIndexedAt   time.Time `json:"lastIndexedAt"`
	ProjectKey      string    `json:"projectKey"`
	OriginURL       string    `json:"originUrl,omitempty"`
	RepoRoot        string    `json:"repoRoot,omitempty"`
}

// Store wraps the sqlite handle + the manifest path so callers don't track them separately.
type Store struct {
	db           *sql.DB
	dir          string
	manifestPath string
}

// projectKey derives a stable id for a repo. Origin URL is preferred so two
// machines with the same clone match; falls back to the absolute repo root.
func projectKey(originURL, repoRoot string) string {
	src := strings.TrimSpace(originURL)
	if src == "" {
		src = "root:" + repoRoot
	}
	h := sha256.Sum256([]byte(src))
	return hex.EncodeToString(h[:])[:16]
}

// ProjectDir returns where this repo's index lives, creating parents.
func ProjectDir(originURL, repoRoot string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	key := projectKey(originURL, repoRoot)
	dir := filepath.Join(home, ".getdebug", "projects", key)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	return dir, nil
}

// Open opens (or creates) the local index for a repo. model + dim are
// recorded in the manifest on first open; a subsequent Open with a
// different model+dim errors so we never mix vectors of different
// shapes in the same DB.
func Open(originURL, repoRoot, model string, dim int) (*Store, error) {
	dir, err := ProjectDir(originURL, repoRoot)
	if err != nil {
		return nil, err
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	dbPath := filepath.Join(dir, "index.db")

	// Check manifest for an existing model commitment. Fresh dirs are fine.
	existing, mErr := readManifest(manifestPath)
	if mErr == nil {
		if existing.Model != model || existing.Dim != dim {
			return nil, fmt.Errorf(
				"local index at %s was built with %s (dim %d); current call wants %s (dim %d). Delete the project dir to rebuild",
				dir, existing.Model, existing.Dim, model, dim,
			)
		}
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %s: %w", dbPath, err)
	}
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS chunks (
			id TEXT PRIMARY KEY,
			rel_path TEXT NOT NULL,
			language TEXT NOT NULL,
			kind TEXT NOT NULL,
			line_start INTEGER NOT NULL,
			line_end INTEGER NOT NULL,
			content_text TEXT NOT NULL,
			content_hash TEXT NOT NULL UNIQUE,
			embedding BLOB NOT NULL,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS chunks_rel_path_idx ON chunks(rel_path);
	`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	// Write/refresh the manifest. We deliberately bump LastIndexedAt only
	// after a real index run completes — Open is just preparing the store.
	if mErr != nil {
		m := Manifest{
			SchemaVersion: schemaVersion,
			Model:         model,
			Dim:           dim,
			ProjectKey:    projectKey(originURL, repoRoot),
			OriginURL:     originURL,
			RepoRoot:      repoRoot,
		}
		if err := writeManifest(manifestPath, &m); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	return &Store{db: db, dir: dir, manifestPath: manifestPath}, nil
}

// Close releases the sqlite handle.
func (s *Store) Close() error { return s.db.Close() }

// Dir returns the on-disk directory holding this store's files.
func (s *Store) Dir() string { return s.dir }

// HasChunk returns true if a chunk with this content_hash already exists
// (the indexer uses this to skip re-embedding unchanged content).
func (s *Store) HasChunk(contentHash string) (bool, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM chunks WHERE content_hash = ?", contentHash).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Upsert stores (or skips) a chunk + its embedding. Idempotent on content_hash.
func (s *Store) Upsert(id string, c Chunk, embedding []float32) error {
	blob := vectorToBlob(embedding)
	_, err := s.db.Exec(`
		INSERT INTO chunks (id, rel_path, language, kind, line_start, line_end, content_text, content_hash, embedding)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(content_hash) DO NOTHING
	`, id, c.RelPath, c.Language, c.Kind, c.LineStart, c.LineEnd, c.ContentText, c.ContentHash, blob)
	return err
}

// CountChunks returns how many chunks are in the index — used by `index`
// status output and by tests.
func (s *Store) CountChunks() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM chunks").Scan(&n)
	return n, err
}

// Search runs brute-force cosine similarity. Fine at the v0.2 scale (≤30k
// chunks per repo). When that ceiling is hit, swap to sqlite-vec (or split
// the index into shards) — the row scan model stays.
func (s *Store) Search(query []float32, k int, languages []string) ([]SearchResult, error) {
	if len(query) == 0 {
		return nil, nil
	}

	// Pull every row; in-memory rank. Avoids per-row sqlite roundtrips for
	// distance calculation we'd otherwise need with a custom function.
	args := []any{}
	where := ""
	if len(languages) > 0 {
		placeholders := strings.Repeat("?,", len(languages)-1) + "?"
		where = fmt.Sprintf("WHERE language IN (%s)", placeholders)
		for _, l := range languages {
			args = append(args, l)
		}
	}
	rows, err := s.db.Query(
		"SELECT id, rel_path, language, kind, line_start, line_end, content_text, embedding FROM chunks "+where,
		args...,
	)
	if err != nil {
		return nil, fmt.Errorf("scan chunks: %w", err)
	}
	defer rows.Close()

	type scored struct {
		r     SearchResult
		score float64
	}
	scoredAll := []scored{}
	qn := norm(query)
	if qn == 0 {
		return nil, nil
	}

	for rows.Next() {
		var (
			id          string
			relPath     string
			language    string
			kind        string
			lineStart   int
			lineEnd     int
			contentText string
			blob        []byte
		)
		if err := rows.Scan(&id, &relPath, &language, &kind, &lineStart, &lineEnd, &contentText, &blob); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}
		vec := vectorFromBlob(blob)
		if len(vec) != len(query) {
			// Dim mismatch — shouldn't happen if we gate Open on dim, but
			// skip rather than crash to keep search resilient.
			continue
		}
		dn := norm(vec)
		if dn == 0 {
			continue
		}
		dot := dotProduct(query, vec)
		// Cosine similarity (in [-1, 1]; 1 = identical direction). We report
		// it directly so users see a familiar score.
		sim := float64(dot) / (qn * dn)
		scoredAll = append(scoredAll, scored{
			r: SearchResult{
				ChunkID:   id,
				RelPath:   relPath,
				Language:  language,
				Kind:      kind,
				LineStart: lineStart,
				LineEnd:   lineEnd,
				Score:     sim,
				Content:   contentText,
			},
			score: sim,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Slice(scoredAll, func(i, j int) bool { return scoredAll[i].score > scoredAll[j].score })
	if k > len(scoredAll) {
		k = len(scoredAll)
	}
	out := make([]SearchResult, k)
	for i := 0; i < k; i++ {
		out[i] = scoredAll[i].r
	}
	return out, nil
}

// ReadManifest re-reads the manifest from disk — used by `getdebug status`
// or future commands that want index metadata without opening the DB.
func (s *Store) ReadManifest() (*Manifest, error) {
	return readManifest(s.manifestPath)
}

// UpdateLastIndexed bumps the manifest's last-indexed bookkeeping after a
// successful index run.
func (s *Store) UpdateLastIndexed(sha string) error {
	m, err := readManifest(s.manifestPath)
	if err != nil {
		return err
	}
	m.LastIndexedSha = sha
	m.LastIndexedAt = time.Now().UTC()
	return writeManifest(s.manifestPath, m)
}

// ─── helpers ────────────────────────────────────────────────────

func readManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse manifest %s: %w", path, err)
	}
	return &m, nil
}

func writeManifest(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// vectorToBlob is little-endian float32 — same shape on every platform we
// build for, so the file is portable.
func vectorToBlob(v []float32) []byte {
	buf := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

func vectorFromBlob(b []byte) []float32 {
	if len(b)%4 != 0 {
		return nil
	}
	v := make([]float32, len(b)/4)
	for i := range v {
		v[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return v
}

func dotProduct(a, b []float32) float32 {
	var s float32
	for i := range a {
		s += a[i] * b[i]
	}
	return s
}

func norm(v []float32) float64 {
	var s float32
	for _, x := range v {
		s += x * x
	}
	return math.Sqrt(float64(s))
}
