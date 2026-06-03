// AI-app regex prefilters — Phase 1.7 Item 1b.
//
// Port of the regex-only patterns from workers/src/security/llm-app.ts
// (CLIENT_SIDE_LLM_KEY and UNBOUNDED_STREAM). Deterministic, no LLM call,
// no network — runs alongside the secrets pass on every analyze.
//
// Why this exists: the local LLM SAST shipped in Phase 1.7 Item 1 covers
// these categories via the model, but a small local model misses
// well-defined regex shapes that the hosted side already catches with
// these prefilters. Adding them locally closes the precision/recall gap
// without requiring Ollama at all — every getdebug analyze gets
// AI-free coverage for two more categories.
//
// Categories:
//   - client-side-llm-key (CWE-798, severity critical) — an LLM
//     provider key referenced via NEXT_PUBLIC_/VITE_/EXPO_PUBLIC_/etc.
//     env vars that frameworks inline into the client bundle. If the
//     pattern matches, this IS a key leak.
//   - unbounded-stream (CWE-770, severity medium) — `stream: true` on
//     an LLM call with no AbortController in the surrounding ±40-line
//     scope. The TextDecoder.decode({ stream: true }) Web-Streams shape
//     is filtered out explicitly (most common false positive).
//
// Both prefilters use the same comment/string-literal skip the hosted
// helpers apply, so doc examples and changelogs don't fire.

package scan

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Severity floors for the two categories. Mirror the hosted defaults
// from workers/src/security/llm-app.ts. The CLI's sastlocal pass has
// its own floor enforcement; this surface keeps the same contract.
const (
	clientLlmKeySeverity   = SeverityCritical
	unboundedStreamSeverity = SeverityMedium
)

// Same provider-name list the hosted side uses — narrow + capitalised
// so loose word matches like "AI" don't over-fire. Drift between
// hosted + local hurts precision symmetry.
var clientLlmKeyRe = regexp.MustCompile(
	`(?:process\.env|import\.meta\.env|Bun\.env)\.((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|PUBLIC|REACT_APP)_[A-Z0-9_]*(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|XAI|GROK|COHERE|MISTRAL|PERPLEXITY|DEEPSEEK|GROQ|REPLICATE|HUGGINGFACE|TOGETHER|FIREWORKS|OLLAMA)[A-Z0-9_]*(?:KEY|API_KEY|SECRET|TOKEN))\b`,
)

var streamTrueDetectorRe = regexp.MustCompile(`\bstream\s*:\s*true\b`)

// decoder.decode(...{stream:true...}) — the false positive the hosted
// side specifically filters. Look back ≤80 chars from the match for an
// unclosed `.decode(`.
var decoderDecodeLookbackRe = regexp.MustCompile(`\.decode\s*\([^)]*$`)

// AbortController / signal: / .abort( in the surrounding window means
// the stream is bounded already. Skip.
var abortInScopeRe = regexp.MustCompile(`\b(?:AbortController|signal\s*:|\.abort\s*\()`)

// AiAppRegexResult mirrors the existing scan-pass return shapes so the
// CLI's analyze command can emit honest coverage numbers (files
// considered, scanned, errors, etc.) the same way as secrets +
// sastlocal.
type AiAppRegexResult struct {
	Findings        []Finding
	FilesConsidered int
	FilesScanned    int
	FilesSkipped    int
	Errors          int
}

// ScanAiAppRegex walks workdir for JS/TS/JSX/TSX files and applies both
// regex prefilters. Mirrors the file-walk shape secrets.go uses, with
// the same vendor + lockfile skips, so a clean analyze run never
// double-walks. Best-effort: read errors are logged via logf and the
// walk continues.
func ScanAiAppRegex(workdir string, logf func(format string, args ...any)) (*AiAppRegexResult, error) {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	res := &AiAppRegexResult{Findings: []Finding{}}
	err := filepath.WalkDir(workdir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			logf("ai-app regex: walk error at %s: %v — continuing", path, err)
			return nil
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			if strings.HasPrefix(d.Name(), ".getdebug-backup-") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		switch ext {
		case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs":
			// supported
		default:
			return nil
		}
		res.FilesConsidered++
		info, err := d.Info()
		if err != nil {
			res.FilesSkipped++
			return nil
		}
		// Same per-file size cap as the local SAST pass. A megabyte of
		// generated JS bundle has no source-of-truth value here.
		if info.Size() > 256*1024 {
			res.FilesSkipped++
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			res.Errors++
			logf("ai-app regex: read %s: %v — skipping", path, err)
			return nil
		}
		rel, err := filepath.Rel(workdir, path)
		if err != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)
		res.FilesScanned++
		res.Findings = append(res.Findings, scanAiAppRegex(rel, string(raw))...)
		return nil
	})
	if err != nil {
		return res, err
	}
	return res, nil
}

// scanAiAppRegex applies both prefilters to one file's source. Split
// out so unit tests can exercise the regexes without a workdir walk.
func scanAiAppRegex(relPath, source string) []Finding {
	var out []Finding
	out = append(out, scanClientSideLlmKey(relPath, source)...)
	out = append(out, scanUnboundedStream(relPath, source)...)
	return out
}

// scanClientSideLlmKey applies the CLIENT_SIDE_LLM_KEY prefilter from
// workers/src/security/llm-app.ts. Deterministic — every match is a
// real key leak (severity critical).
func scanClientSideLlmKey(relPath, source string) []Finding {
	var out []Finding
	for _, loc := range clientLlmKeyRe.FindAllStringSubmatchIndex(source, -1) {
		matchStart := loc[0]
		if inNonCodeContext(source, matchStart) {
			continue
		}
		matchedSpan := source[loc[2]:loc[3]] // capture group 1: the env var name
		line := lineNumberAt(source, matchStart)
		title := "LLM provider key exposed to client bundle"
		explanation := "An LLM provider API key is being referenced through a build-time public env var. Frameworks like Next.js (NEXT_PUBLIC_*), Vite (VITE_*), and Expo (EXPO_PUBLIC_*) inline these values into the client bundle — once shipped, the key is published. Move the call to a server route or API handler and read the key from a non-public env var."
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "client-side-llm-key",
			Severity:    clientLlmKeySeverity,
			Title:       title,
			Explanation: explanation,
			ContentHash: hashAiAppFinding(relPath, line, "client-side-llm-key", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-798",
			OWASP:       "A02",
			Detection:   "regex",
		})
	}
	return out
}

// scanUnboundedStream applies the UNBOUNDED_STREAM prefilter from
// workers/src/security/llm-app.ts. Heuristic — skips TextDecoder
// false-positives explicitly and clears any stream:true that has an
// AbortController shape within ±40 lines.
func scanUnboundedStream(relPath, source string) []Finding {
	var out []Finding
	lines := strings.Split(source, "\n")
	for _, loc := range streamTrueDetectorRe.FindAllStringIndex(source, -1) {
		pos := loc[0]
		if inNonCodeContext(source, pos) {
			continue
		}
		// TextDecoder.decode({stream: true}) — Web Streams API, not LLM.
		lookbackStart := pos - 80
		if lookbackStart < 0 {
			lookbackStart = 0
		}
		if decoderDecodeLookbackRe.MatchString(source[lookbackStart:pos]) {
			continue
		}
		line := lineNumberAt(source, pos)
		// ±40 line window for AbortController scope check.
		from := line - 1 - 40
		if from < 0 {
			from = 0
		}
		to := line + 40
		if to > len(lines) {
			to = len(lines)
		}
		window := strings.Join(lines[from:to], "\n")
		if abortInScopeRe.MatchString(window) {
			continue
		}
		matchedSpan := source[loc[0]:loc[1]]
		title := "Streaming LLM call without abort handling"
		explanation := "A streaming LLM call (stream: true) has no AbortController / signal in its surrounding scope. If the client disconnects or the model hangs, the request keeps a worker slot occupied and continues billing tokens. Pass `signal: controller.signal` and abort the controller when the caller leaves."
		out = append(out, Finding{
			FilePath:    relPath,
			LineStart:   line,
			LineEnd:     line,
			Category:    "unbounded-stream",
			Severity:    unboundedStreamSeverity,
			Title:       title,
			Explanation: explanation,
			ContentHash: hashAiAppFinding(relPath, line, "unbounded-stream", matchedSpan),
			Snippet:     extractLine(source, line),
			CWE:         "CWE-770",
			OWASP:       "A04",
			Detection:   "regex",
		})
	}
	return out
}

// ── Helpers (ported from workers/src/security/llm-app.ts) ────────

// lineNumberAt returns the 1-based line containing position pos. O(pos)
// — fine for the prefilter sizes; the regex itself is the cost driver.
func lineNumberAt(source string, pos int) int {
	if pos > len(source) {
		pos = len(source)
	}
	return strings.Count(source[:pos], "\n") + 1
}

// inNonCodeContext is true when the match sits inside a comment or a
// string literal — same shape as the hosted helper. Filters the doc-
// example + changelog + JSDoc false positives the hosted side already
// learned about.
func inNonCodeContext(source string, pos int) bool {
	if pos < 0 || pos > len(source) {
		return false
	}
	lineStart := strings.LastIndexByte(source[:pos], '\n') + 1 // 0 if no newline
	before := strings.TrimLeft(source[lineStart:pos], " \t")
	if strings.HasPrefix(before, "//") || strings.HasPrefix(before, "*") {
		return true
	}
	if pos == 0 {
		return false
	}
	prev := source[pos-1]
	return prev == '"' || prev == '\'' || prev == '`'
}

func extractLine(source string, line1Based int) string {
	if line1Based < 1 {
		return ""
	}
	lines := strings.Split(source, "\n")
	if line1Based > len(lines) {
		return ""
	}
	return lines[line1Based-1]
}

// hashAiAppFinding mirrors the secrets pass content-hash shape so the
// dedup downstream (sastlocal vs prefilter) keeps the regex hit when
// the LLM finds the same shape — the regex pass is the source of truth
// when both agree.
func hashAiAppFinding(filePath string, line int, category, span string) string {
	return hashFinding(filePath, strconv.Itoa(line), category, span)
}
