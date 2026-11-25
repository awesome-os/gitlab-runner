package holo

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCasV11Blob(t *testing.T, storeRoot, sha512 string, execSuffix bool, content []byte) string {
	t.Helper()
	name := sha512
	if execSuffix {
		name += "-exec"
	}
	blobPath := filepath.Join(storeRoot, "v11", "files", sha512[:2], name)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("mkdir blob dir: %v", err)
	}
	if err := os.WriteFile(blobPath, content, 0o644); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	return blobPath
}

func TestB8GAbiMagicV3(t *testing.T) {
	if B8GAbiMagicV3 != 0x33564742 {
		t.Fatalf("expected B8GAbiMagicV3=0x33564742, got 0x%08X", B8GAbiMagicV3)
	}
}

func TestHydrateFromCasV11_HardlinkAndNestedDependencies(t *testing.T) {
	tmp := t.TempDir()
	storeRoot := filepath.Join(tmp, "cas-store")
	targetDir := filepath.Join(tmp, "workspace")
	lockfilePath := filepath.Join(tmp, "holo-compiler-lockfile.json")

	shaRoot := "ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd"
	shaExec := "cd9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedc"

	rootContent := []byte("holo-v11-root-library-payload")
	execContent := []byte("#!/bin/sh\necho holo-exec\n")

	srcRoot := writeCasV11Blob(t, storeRoot, shaRoot, false, rootContent)
	srcExec := writeCasV11Blob(t, storeRoot, shaExec, true, execContent)

	lockfile := Lockfile{
		Version:  "11",
		AbiMagic: B8GAbiMagicV3,
		Dependencies: []Dependency{
			{
				Name:     "b8g-runtime",
				Sha512:   shaRoot,
				BlobPath: filepath.Join("v11", "files", shaRoot[:2], shaRoot),
				Target:   "lib/b8g-runtime.b8p",
				Dependencies: []Dependency{
					{
						Name:       "sectium-es",
						Sha512:     shaExec,
						BlobPath:   filepath.Join("v11", "files", shaExec[:2], shaExec+"-exec"),
						Target:     "bin/sectium-es",
						Executable: true,
					},
				},
			},
		},
	}

	raw, err := json.MarshalIndent(lockfile, "", "  ")
	if err != nil {
		t.Fatalf("marshal lockfile: %v", err)
	}
	if err := os.WriteFile(lockfilePath, raw, 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	receipt, err := HydrateFromCasV11(storeRoot, lockfilePath, targetDir)
	if err != nil {
		t.Fatalf("HydrateFromCasV11 failed: %v", err)
	}

	if receipt.HydratedCount != 2 {
		t.Fatalf("expected HydratedCount=2, got %d", receipt.HydratedCount)
	}
	if receipt.HardlinkedCount != 2 {
		t.Fatalf("expected HardlinkedCount=2, got %d (copied=%d)", receipt.HardlinkedCount, receipt.CopiedCount)
	}
	if receipt.CopiedCount != 0 {
		t.Fatalf("expected CopiedCount=0, got %d", receipt.CopiedCount)
	}
	if receipt.MissingCount != 0 {
		t.Fatalf("expected MissingCount=0, got %d", receipt.MissingCount)
	}

	dstRoot := filepath.Join(targetDir, "lib", "b8g-runtime.b8p")
	dstExec := filepath.Join(targetDir, "bin", "sectium-es")

	// Verify file contents.
	gotRoot, err := os.ReadFile(dstRoot)
	if err != nil {
		t.Fatalf("read hydrated root: %v", err)
	}
	if string(gotRoot) != string(rootContent) {
		t.Fatalf("root content mismatch: got %q, want %q", gotRoot, rootContent)
	}

	gotExec, err := os.ReadFile(dstExec)
	if err != nil {
		t.Fatalf("read hydrated exec: %v", err)
	}
	if string(gotExec) != string(execContent) {
		t.Fatalf("exec content mismatch: got %q, want %q", gotExec, execContent)
	}

	// Verify hardlink identity (same underlying file / inode via os.SameFile).
	srcRootInfo, err := os.Stat(srcRoot)
	if err != nil {
		t.Fatalf("stat srcRoot: %v", err)
	}
	dstRootInfo, err := os.Stat(dstRoot)
	if err != nil {
		t.Fatalf("stat dstRoot: %v", err)
	}
	if !os.SameFile(srcRootInfo, dstRootInfo) {
		t.Fatalf("expected %q and %q to share the same underlying inode/file via hardlink", srcRoot, dstRoot)
	}

	srcExecInfo, err := os.Stat(srcExec)
	if err != nil {
		t.Fatalf("stat srcExec: %v", err)
	}
	dstExecInfo, err := os.Stat(dstExec)
	if err != nil {
		t.Fatalf("stat dstExec: %v", err)
	}
	if !os.SameFile(srcExecInfo, dstExecInfo) {
		t.Fatalf("expected %q and %q to share the same underlying inode/file via hardlink", srcExec, dstExec)
	}
}

func TestHydrateFromCasV11_CopyFallbackViaConfig(t *testing.T) {
	tmp := t.TempDir()
	storeRoot := filepath.Join(tmp, "cas-store")
	targetDir := filepath.Join(tmp, "workspace-copy")
	lockfilePath := filepath.Join(tmp, "holo-compiler-lockfile.json")

	sha := "ef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd"
	payload := []byte("copy-fallback-payload")
	srcPath := writeCasV11Blob(t, storeRoot, sha, false, payload)

	lf := Lockfile{
		Dependencies: []Dependency{
			{Sha512: sha, Target: "out/payload.bin"},
		},
	}
	raw, _ := json.Marshal(lf)
	if err := os.WriteFile(lockfilePath, raw, 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	exec := NewExecutor(HoloConfig{
		CasV11Root:    storeRoot,
		LockfilePath:  lockfilePath,
		WasiHostBin:   "b8g-wasi-host",
		LumiBertCmd:   "lumibert-classify",
		AllowHardlink: false,
	})

	receipt, err := exec.Hydrate(targetDir)
	if err != nil {
		t.Fatalf("Hydrate failed: %v", err)
	}
	if receipt.HydratedCount != 1 || receipt.CopiedCount != 1 || receipt.HardlinkedCount != 0 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}

	dstPath := filepath.Join(targetDir, "out", "payload.bin")
	srcInfo, _ := os.Stat(srcPath)
	dstInfo, _ := os.Stat(dstPath)
	if os.SameFile(srcInfo, dstInfo) {
		t.Fatalf("expected copy fallback to create a distinct file, not a hardlink")
	}
}

func TestHydrateFromCasV11_MissingBlobDetection(t *testing.T) {
	tmp := t.TempDir()
	storeRoot := filepath.Join(tmp, "cas-store")
	targetDir := filepath.Join(tmp, "workspace")
	lockfilePath := filepath.Join(tmp, "holo-compiler-lockfile.json")

	presentSha := "11aabbccddeeff00112233445566778899aabbccddeeff001122334455667788"
	missingSha := "99ffeeddccbbaa99887766554433221100ffeeddccbbaa998877665544332211"

	writeCasV11Blob(t, storeRoot, presentSha, false, []byte("present-data"))

	lf := Lockfile{
		Dependencies: []Dependency{
			{Name: "present", Sha512: presentSha, Target: "ok.bin"},
			{Name: "missing", Sha512: missingSha, Target: "missing.bin"},
		},
	}
	raw, _ := json.Marshal(lf)
	if err := os.WriteFile(lockfilePath, raw, 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	receipt, err := HydrateFromCasV11(storeRoot, lockfilePath, targetDir)
	if err != nil {
		t.Fatalf("HydrateFromCasV11 returned unexpected error: %v", err)
	}

	if receipt.HydratedCount != 1 {
		t.Fatalf("expected HydratedCount=1, got %d", receipt.HydratedCount)
	}
	if receipt.MissingCount != 1 {
		t.Fatalf("expected MissingCount=1, got %d", receipt.MissingCount)
	}
	if len(receipt.MissingBlobs) != 1 || receipt.MissingBlobs[0] != missingSha {
		t.Fatalf("expected MissingBlobs=[%s], got %v", missingSha, receipt.MissingBlobs)
	}
}

func TestSpinWaveCancelPhase(t *testing.T) {
	tests := []struct {
		name     string
		phaseRad float64
		want     bool
	}{
		{name: "exact pi cancels", phaseRad: math.Pi, want: true},
		{name: "within epsilon below pi cancels", phaseRad: math.Pi - 5e-7, want: true},
		{name: "within epsilon above pi cancels", phaseRad: math.Pi + 5e-7, want: true},
		{name: "outside epsilon does not cancel", phaseRad: math.Pi + 1e-5, want: false},
		{name: "zero phase constructive", phaseRad: 0, want: false},
		{name: "two pi constructive", phaseRad: 2 * math.Pi, want: false},
		{name: "negative pi does not cancel", phaseRad: -math.Pi, want: false},
		{name: "NaN does not cancel", phaseRad: math.NaN(), want: false},
		{name: "Inf does not cancel", phaseRad: math.Inf(1), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := SpinWaveCancelPhase(tc.phaseRad); got != tc.want {
				t.Fatalf("SpinWaveCancelPhase(%v) = %v, want %v", tc.phaseRad, got, tc.want)
			}
		})
	}
}

func TestClassifyKnownError(t *testing.T) {
	tests := []struct {
		name        string
		stderr      string
		wantHandled bool
		wantSubstr  string
	}{
		{
			name:        "B8G016 local HTTP IPC",
			stderr:      "ERROR [B8G016]: forbidden 127.0.0.1 HTTP IPC listener detected",
			wantHandled: true,
			wantSubstr:  "B8G_ARENA_V1",
		},
		{
			name:        "EADDRINUSE port conflict",
			stderr:      "Error: listen EADDRINUSE: address already in use :::8080",
			wantHandled: true,
			wantSubstr:  "EADDRINUSE",
		},
		{
			name:        "erasableSyntaxOnly TS error",
			stderr:      "error TS1294: This syntax is not allowed when 'erasableSyntaxOnly' is enabled.",
			wantHandled: true,
			wantSubstr:  "as const",
		},
		{
			name:        "DEPOT_TOOLS_WIN_TOOLCHAIN mismatch",
			stderr:      "Exception: Please set DEPOT_TOOLS_WIN_TOOLCHAIN=0 in your environment",
			wantHandled: true,
			wantSubstr:  "DEPOT_TOOLS_WIN_TOOLCHAIN=0",
		},
		{
			name:        "unknown stderr not handled",
			stderr:      "fatal: completely unrecognized error signature",
			wantHandled: false,
			wantSubstr:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fix, handled := ClassifyKnownError(tc.stderr)
			if handled != tc.wantHandled {
				t.Fatalf("ClassifyKnownError(%q) handled=%v, want %v", tc.stderr, handled, tc.wantHandled)
			}
			if tc.wantSubstr != "" && !strings.Contains(fix, tc.wantSubstr) {
				t.Fatalf("ClassifyKnownError(%q) fix=%q, expected substring %q", tc.stderr, fix, tc.wantSubstr)
			}
		})
	}
}
