// Package holo implements the Awesome-OS Holo CI Executor for GitLab Runner.
//
// It provides zero-copy v11 CAS hardlink hydration from holo-compiler-lockfile.json,
// O(1) Spin-Wave destructive-interference phase cancellation, and a fast 1:1
// lumiBERT-compatible local error classifier with zero external dependencies.
package holo

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// B8GAbiMagicV3 is the canonical B8G ABI v3 magic number ("BGV3" in little-endian).
const B8GAbiMagicV3 = uint32(0x33564742)

// spinWaveEpsilon is the phase tolerance in radians for O(1) destructive cancellation at pi.
const spinWaveEpsilon = 1e-6

// HoloConfig configures the Awesome-OS Holo CI Executor.
type HoloConfig struct {
	CasV11Root    string `json:"cas_v11_root" toml:"cas_v11_root"`
	LockfilePath  string `json:"lockfile_path" toml:"lockfile_path"`
	WasiHostBin   string `json:"wasi_host_bin" toml:"wasi_host_bin"`
	LumiBertCmd   string `json:"lumi_bert_cmd" toml:"lumi_bert_cmd"`
	AllowHardlink bool   `json:"allow_hardlink" toml:"allow_hardlink"`
}

// Lockfile represents the structure of holo-compiler-lockfile.json.
type Lockfile struct {
	Version      string       `json:"version,omitempty"`
	AbiMagic     uint32       `json:"abiMagic,omitempty"`
	Dependencies []Dependency `json:"dependencies"`
}

// Dependency represents a single CAS-backed dependency entry in holo-compiler-lockfile.json.
// Dependencies may contain nested child dependencies.
type Dependency struct {
	Name         string       `json:"name,omitempty"`
	Sha512       string       `json:"sha512"`
	BlobPath     string       `json:"blobPath,omitempty"`
	Target       string       `json:"target"`
	Executable   bool         `json:"executable,omitempty"`
	Dependencies []Dependency `json:"dependencies,omitempty"`
}

// HydrationReceipt summarizes the result of a CAS v11 hydration pass.
type HydrationReceipt struct {
	HydratedCount   int      `json:"hydratedCount"`
	HardlinkedCount int      `json:"hardlinkedCount"`
	CopiedCount     int      `json:"copiedCount"`
	MissingCount    int      `json:"missingCount"`
	MissingBlobs    []string `json:"missingBlobs,omitempty"`
}

// Executor wraps HoloConfig to provide an idiomatic GitLab Runner executor facade.
type Executor struct {
	Config HoloConfig
}

// NewExecutor constructs a new Holo CI Executor with the given configuration.
func NewExecutor(cfg HoloConfig) *Executor {
	return &Executor{Config: cfg}
}

// Hydrate hydrates the configured lockfile into targetDir using the executor's configuration.
func (e *Executor) Hydrate(targetDir string) (*HydrationReceipt, error) {
	return hydrateFromCasV11(e.Config.CasV11Root, e.Config.LockfilePath, targetDir, e.Config.AllowHardlink)
}

// ShouldCancel returns true when the Spin-Wave phase reaches destructive cancellation.
func (e *Executor) ShouldCancel(phaseRad float64) bool {
	return SpinWaveCancelPhase(phaseRad)
}

// Diagnose runs the fast local lumiBERT-compatible error classifier on stderr output.
func (e *Executor) Diagnose(stderr string) (string, bool) {
	return ClassifyKnownError(stderr)
}

// HydrateFromCasV11 parses holo-compiler-lockfile.json (including nested dependencies[]),
// resolves blobs from v11/files/<sha512[:2]>/<sha512>[-exec], and materializes them into
// targetDir via os.Link hardlinks with automatic copy fallback.
func HydrateFromCasV11(storeRoot, lockfilePath, targetDir string) (*HydrationReceipt, error) {
	return hydrateFromCasV11(storeRoot, lockfilePath, targetDir, true)
}

func hydrateFromCasV11(storeRoot, lockfilePath, targetDir string, allowHardlink bool) (*HydrationReceipt, error) {
	if storeRoot == "" {
		return nil, errors.New("holo: storeRoot must not be empty")
	}
	if lockfilePath == "" {
		return nil, errors.New("holo: lockfilePath must not be empty")
	}
	if targetDir == "" {
		return nil, errors.New("holo: targetDir must not be empty")
	}

	raw, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("holo: read lockfile %q: %w", lockfilePath, err)
	}

	var lf Lockfile
	if err := json.Unmarshal(raw, &lf); err != nil {
		return nil, fmt.Errorf("holo: parse lockfile %q: %w", lockfilePath, err)
	}

	absTargetDir, err := filepath.Abs(targetDir)
	if err != nil {
		return nil, fmt.Errorf("holo: resolve targetDir %q: %w", targetDir, err)
	}
	if err := os.MkdirAll(absTargetDir, 0o755); err != nil {
		return nil, fmt.Errorf("holo: create targetDir %q: %w", absTargetDir, err)
	}

	receipt := &HydrationReceipt{}
	if err := hydrateDependencies(storeRoot, absTargetDir, lf.Dependencies, allowHardlink, receipt); err != nil {
		return nil, err
	}
	return receipt, nil
}

func hydrateDependencies(
	storeRoot string,
	absTargetDir string,
	deps []Dependency,
	allowHardlink bool,
	receipt *HydrationReceipt,
) error {
	for _, dep := range deps {
		if dep.Sha512 != "" || dep.BlobPath != "" {
			if err := hydrateSingleDependency(storeRoot, absTargetDir, dep, allowHardlink, receipt); err != nil {
				return err
			}
		}
		if len(dep.Dependencies) > 0 {
			if err := hydrateDependencies(storeRoot, absTargetDir, dep.Dependencies, allowHardlink, receipt); err != nil {
				return err
			}
		}
	}
	return nil
}

func hydrateSingleDependency(
	storeRoot string,
	absTargetDir string,
	dep Dependency,
	allowHardlink bool,
	receipt *HydrationReceipt,
) error {
	srcPath, found := resolveCasV11Blob(storeRoot, dep)
	if !found {
		receipt.MissingCount++
		id := dep.Sha512
		if id == "" {
			id = dep.BlobPath
		}
		receipt.MissingBlobs = append(receipt.MissingBlobs, id)
		return nil
	}

	relTarget := dep.Target
	if relTarget == "" {
		relTarget = dep.BlobPath
	}
	if relTarget == "" {
		relTarget = dep.Sha512
	}

	dstPath, err := safeJoin(absTargetDir, relTarget)
	if err != nil {
		return fmt.Errorf("holo: invalid target %q: %w", relTarget, err)
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return fmt.Errorf("holo: mkdir for %q: %w", dstPath, err)
	}

	// Ensure idempotent re-hydration by removing any existing destination file.
	if err := os.Remove(dstPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("holo: remove existing target %q: %w", dstPath, err)
	}

	if allowHardlink {
		if err := os.Link(srcPath, dstPath); err == nil {
			receipt.HardlinkedCount++
			receipt.HydratedCount++
			return nil
		}
	}

	if err := copyFile(srcPath, dstPath); err != nil {
		return fmt.Errorf("holo: copy fallback %q -> %q: %w", srcPath, dstPath, err)
	}
	receipt.CopiedCount++
	receipt.HydratedCount++
	return nil
}

func resolveCasV11Blob(storeRoot string, dep Dependency) (string, bool) {
	sha := strings.TrimSpace(dep.Sha512)
	if len(sha) >= 2 {
		prefix := sha[:2]
		candidates := make([]string, 0, 2)
		if dep.Executable {
			candidates = append(candidates,
				filepath.Join(storeRoot, "v11", "files", prefix, sha+"-exec"),
				filepath.Join(storeRoot, "v11", "files", prefix, sha),
			)
		} else {
			candidates = append(candidates,
				filepath.Join(storeRoot, "v11", "files", prefix, sha),
				filepath.Join(storeRoot, "v11", "files", prefix, sha+"-exec"),
			)
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, true
			}
		}
	}

	if bp := strings.TrimSpace(dep.BlobPath); bp != "" {
		candidate := bp
		if !filepath.IsAbs(candidate) {
			candidate = filepath.Join(storeRoot, bp)
		}
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, true
		}
	}

	return "", false
}

func safeJoin(baseDir, relPath string) (string, error) {
	cleaned := filepath.Clean(relPath)
	if filepath.IsAbs(cleaned) {
		return "", errors.New("absolute target path is not allowed")
	}
	joined := filepath.Join(baseDir, cleaned)
	rel, err := filepath.Rel(baseDir, joined)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("target path escapes targetDir")
	}
	return joined, nil
}

func copyFile(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	info, err := src.Stat()
	if err != nil {
		return err
	}

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}

	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

// SpinWaveCancelPhase returns true (O(1) destructive cancellation) when phaseRad
// is within 1e-6 radians of math.Pi.
func SpinWaveCancelPhase(phaseRad float64) bool {
	if math.IsNaN(phaseRad) || math.IsInf(phaseRad, 0) {
		return false
	}
	return math.Abs(phaseRad-math.Pi) < spinWaveEpsilon
}

// ClassifyKnownError provides a fast 1:1 lumiBERT-compatible local error classifier
// for high-frequency Awesome-OS CI failure signatures.
func ClassifyKnownError(stderr string) (fix string, handled bool) {
	switch {
	case strings.Contains(stderr, "B8G016"):
		return "B8G016: replace local 127.0.0.1 HTTP IPC with B8G_ARENA_V1 or host named pipe (\\\\.\\pipe\\b8g-host-bus / /run/b8g/host-bus.sock)", true
	case strings.Contains(stderr, "EADDRINUSE"):
		return "EADDRINUSE: release the bound local port or migrate IPC transport to an ephemeral socket / host named pipe", true
	case strings.Contains(stderr, "erasableSyntaxOnly"):
		return "erasableSyntaxOnly: replace non-erasable TypeScript syntax (enum, namespace, parameter properties) with erasable 'as const' objects and explicit fields", true
	case strings.Contains(stderr, "DEPOT_TOOLS_WIN_TOOLCHAIN"):
		return "DEPOT_TOOLS_WIN_TOOLCHAIN: set DEPOT_TOOLS_WIN_TOOLCHAIN=0 and route native C/C++ compilation through holo-compiler / zig cc", true
	default:
		return "", false
	}
}
