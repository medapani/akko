package akko

import (
	"os"
	"path/filepath"
	"testing"
)

// header byte offsets, matching format.go's marshal() layout.
const (
	offVersion   = len(magic)
	offAlgorithm = len(magic) + 1
	offKDF       = len(magic) + 2
	offSalt      = len(magic) + 3 + 4 + 4 + 1
	offNonceBase = offSalt + saltSize
	// OriginalMode (4 bytes) follows NonceBase before the extension length/bytes.
	offOriginalMode = offNonceBase + 8
)

func encryptSample(t *testing.T, dir string, plain []byte) (input, enc string) {
	t.Helper()
	input = filepath.Join(dir, "plain.bin")
	enc = filepath.Join(dir, "plain.bin.akko")
	if err := os.WriteFile(input, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, enc, []byte("correct-password"), false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	return input, enc
}

func flipByte(t *testing.T, path string, offset int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if offset >= len(b) {
		t.Fatalf("offset %d out of range (len %d)", offset, len(b))
	}
	b[offset] ^= 0xFF
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTamperCiphertextFailsAuth(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("some secret payload"))
	dec := filepath.Join(dir, "out.dec")

	// flip the last byte of the (authenticated) extension field, still within the header.
	flipByte(t, enc, offOriginalMode+4+4+1)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed, got %v", err)
	}
	if _, statErr := os.Stat(dec); !os.IsNotExist(statErr) {
		t.Fatalf("output should not exist after tamper: %v", statErr)
	}
}

func TestTamperSaltFailsAuth(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	flipByte(t, enc, offSalt)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed for tampered salt, got %v", err)
	}
}

func TestTamperNonceBaseFailsAuth(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	flipByte(t, enc, offNonceBase)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrAuthFailed {
		t.Fatalf("expected ErrAuthFailed for tampered nonce base, got %v", err)
	}
}

func TestTamperVersionRejected(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	flipByte(t, enc, offVersion)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrUnsupportedVersion {
		t.Fatalf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestTamperAlgorithmRejected(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	flipByte(t, enc, offAlgorithm)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrUnsupportedAlgorithm {
		t.Fatalf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestTamperKDFRejected(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	flipByte(t, enc, offKDF)

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err != ErrUnsupportedKDF {
		t.Fatalf("expected ErrUnsupportedKDF, got %v", err)
	}
}

func TestNotAkkoFileDetectedAsPlaintext(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "notakko.bin")
	if err := os.WriteFile(input, []byte("just some regular bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	mode, err := DetectMode(input)
	if err != nil {
		t.Fatal(err)
	}
	if mode != ModeEncrypt {
		t.Fatalf("expected ModeEncrypt for non-akko file, got %v", mode)
	}
}

func TestTruncatedHeaderRejected(t *testing.T) {
	dir := t.TempDir()
	_, enc := encryptSample(t, dir, []byte("payload"))
	dec := filepath.Join(dir, "out.dec")

	// truncate to only the magic bytes plus a few, simulating a broken file.
	if err := os.Truncate(enc, int64(len(magic)+2)); err != nil {
		t.Fatal(err)
	}

	err := DecryptFile(enc, dec, []byte("correct-password"), false)
	if err == nil {
		t.Fatal("expected error for truncated header")
	}
}
