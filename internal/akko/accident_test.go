package akko

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptEmptyFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "empty.txt")
	enc := filepath.Join(dir, "empty.txt.akko")
	dec := filepath.Join(dir, "empty.txt.dec")

	if err := os.WriteFile(input, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pw := []byte("password")
	if err := EncryptFile(input, enc, pw, false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err := DecryptFile(enc, dec, pw, false); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty output, got %d bytes", len(got))
	}
}

func TestEncryptSameInputTwiceProducesDifferentCiphertext(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	enc1 := filepath.Join(dir, "enc1.akko")
	enc2 := filepath.Join(dir, "enc2.akko")

	if err := os.WriteFile(input, []byte("identical plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}

	pw := []byte("password")
	if err := EncryptFile(input, enc1, pw, false); err != nil {
		t.Fatalf("encrypt 1 failed: %v", err)
	}
	if err := EncryptFile(input, enc2, pw, false); err != nil {
		t.Fatalf("encrypt 2 failed: %v", err)
	}

	b1, err := os.ReadFile(enc1)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := os.ReadFile(enc2)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(b1, b2) {
		t.Fatal("expected different ciphertext for repeated encryption of identical plaintext")
	}

	h1, err := PeekHeader(enc1)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := PeekHeader(enc2)
	if err != nil {
		t.Fatal(err)
	}
	if h1.Salt == h2.Salt {
		t.Fatal("expected different salt between encryptions")
	}
	if h1.NonceBase == h2.NonceBase {
		t.Fatal("expected different nonce base between encryptions")
	}
}

func TestEncryptedFileIsNotDoubleEncrypted(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.akko")

	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	pw := []byte("password")
	if err := EncryptFile(input, enc, pw, false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// running Action on an already-encrypted file must decrypt, not re-encrypt.
	mode, _, _, err := Action(enc, "", pw, true, nil)
	if err != nil {
		t.Fatalf("action on akko file failed: %v", err)
	}
	if mode != ModeDecrypt {
		t.Fatalf("expected ModeDecrypt for already-encrypted input, got %v", mode)
	}
}

func TestEnsureOutputPathRejectsSameInputOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "same.txt")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ensureOutputPath(path, path, false); err == nil {
		t.Fatal("expected error when input and output are the same path")
	}
}

func TestEnsureOutputPathRejectsExistingWithoutForce(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	output := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ensureOutputPath(input, output, false); err == nil {
		t.Fatal("expected error when output already exists and force is false")
	}
	if err := ensureOutputPath(input, output, true); err != nil {
		t.Fatalf("expected no error with force=true, got %v", err)
	}
}

func TestEnsureOutputPathRejectsMissingParentDir(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "in.txt")
	output := filepath.Join(dir, "no-such-dir", "out.txt")
	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := ensureOutputPath(input, output, false); err == nil {
		t.Fatal("expected error when output parent directory does not exist")
	}
}

func TestEnsureRegularFileRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := ensureRegularFile(dir); err == nil {
		t.Fatal("expected error when input is a directory")
	}
}
