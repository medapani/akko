package akko

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.akko")
	dec := filepath.Join(dir, "plain.txt.dec")

	plain := []byte("hello akko")
	if err := os.WriteFile(input, plain, 0o600); err != nil {
		t.Fatal(err)
	}

	pw := []byte("test-password")
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
	if string(got) != string(plain) {
		t.Fatalf("round trip mismatch: got %q want %q", string(got), string(plain))
	}
}

func TestDefaultOutputPathNoDoubleExtension(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sample.txt")
	enc := filepath.Join(dir, "sample.txt.akko")

	if err := os.WriteFile(input, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, enc, []byte("password"), false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	got := DefaultOutputPath(enc, ModeDecrypt, ".txt")
	want := filepath.Join(dir, "sample.txt")
	if got != want {
		t.Fatalf("default output path mismatch: got %q want %q", got, want)
	}
}

func TestActionRoundTripDefaultOutputPreservesName(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "sample.txt")
	pw := []byte("password")

	if err := os.WriteFile(input, []byte("hello akko"), 0o600); err != nil {
		t.Fatal(err)
	}

	mode, encPath, count, err := Action(input, "", pw, false, nil)
	if err != nil {
		t.Fatalf("encrypt action failed: %v", err)
	}
	if mode != ModeEncrypt {
		t.Fatalf("expected ModeEncrypt, got %v", mode)
	}
	if count != 1 {
		t.Fatalf("expected processed count 1, got %d", count)
	}
	if err := os.Remove(input); err != nil {
		t.Fatal(err)
	}

	mode, decPath, count, err := Action(encPath, "", pw, false, nil)
	if err != nil {
		t.Fatalf("decrypt action failed: %v", err)
	}
	if mode != ModeDecrypt {
		t.Fatalf("expected ModeDecrypt, got %v", mode)
	}
	if count != 1 {
		t.Fatalf("expected processed count 1, got %d", count)
	}
	if decPath != input {
		t.Fatalf("expected decrypted path %q, got %q", input, decPath)
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "plain.bin")
	enc := filepath.Join(dir, "plain.bin.akko")
	dec := filepath.Join(dir, "plain.bin.dec")

	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, enc, []byte("correct"), false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	err := DecryptFile(enc, dec, []byte("wrong"), false)
	if err == nil {
		t.Fatal("expected auth failure")
	}
	if !os.IsNotExist(err) && err != ErrAuthFailed {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, statErr := os.Stat(dec); !os.IsNotExist(statErr) {
		t.Fatalf("output should not exist on auth failure: %v", statErr)
	}
}

func TestDecryptExpiredFileRejected(t *testing.T) {
	SetDefaultExpiryUnix(time.Now().Add(-1 * time.Minute).Unix())
	t.Cleanup(func() { SetDefaultExpiryUnix(0) })

	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.akko")
	dec := filepath.Join(dir, "plain.txt.dec")

	if err := os.WriteFile(input, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, enc, []byte("correct"), false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	err := DecryptFile(enc, dec, []byte("correct"), false)
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
	if _, statErr := os.Stat(dec); !os.IsNotExist(statErr) {
		t.Fatalf("output should not exist for expired file: %v", statErr)
	}
}

func TestDecryptNonExpiredFileAllowed(t *testing.T) {
	SetDefaultExpiryUnix(time.Now().Add(1 * time.Hour).Unix())
	t.Cleanup(func() { SetDefaultExpiryUnix(0) })

	dir := t.TempDir()
	input := filepath.Join(dir, "plain.txt")
	enc := filepath.Join(dir, "plain.txt.akko")
	dec := filepath.Join(dir, "plain.txt.dec")

	plain := []byte("hello")
	if err := os.WriteFile(input, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(input, enc, []byte("correct"), false); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	if err := DecryptFile(enc, dec, []byte("correct"), false); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	got, err := os.ReadFile(dec)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(plain) {
		t.Fatalf("round trip mismatch: got %q want %q", string(got), string(plain))
	}
}
