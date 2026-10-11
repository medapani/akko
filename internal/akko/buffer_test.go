package akko

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestReusableBufferRoundTrip(t *testing.T) {
	for _, size := range []int{chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 137} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			dir := t.TempDir()
			plain := make([]byte, size)
			for i := range plain {
				plain[i] = byte(i % 251)
			}

			_, encrypted := encryptSample(t, dir, plain)
			output := filepath.Join(dir, "decoded.bin")
			if err := DecryptFile(encrypted, output, []byte("correct-password"), false); err != nil {
				t.Fatal(err)
			}

			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatal("round trip changed the plaintext")
			}
		})
	}
}

func TestReusableBufferRejectsDamagedLaterChunk(t *testing.T) {
	dir := t.TempDir()
	_, encrypted := encryptSample(t, dir, bytes.Repeat([]byte("secret"), chunkSize))
	data, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 1
	if err := os.WriteFile(encrypted, data, 0o600); err != nil {
		t.Fatal(err)
	}

	output := filepath.Join(dir, "decoded.bin")
	if err := DecryptFile(encrypted, output, []byte("correct-password"), false); !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("expected authentication failure, got %v", err)
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unauthenticated output was published: %v", err)
	}
}

func TestReusableBufferRejectsInvalidChunkLength(t *testing.T) {
	dir := t.TempDir()
	_, encrypted := encryptSample(t, dir, []byte("secret"))
	original, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(original)
	if _, _, err := unmarshalHeader(reader); err != nil {
		t.Fatal(err)
	}
	offset := len(original) - reader.Len()

	for _, length := range []uint32{0, 15, chunkSize + 17, ^uint32(0)} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			data := bytes.Clone(original)
			binary.BigEndian.PutUint32(data[offset:offset+4], length)
			if err := os.WriteFile(encrypted, data, 0o600); err != nil {
				t.Fatal(err)
			}

			output := filepath.Join(dir, "decoded.bin")
			if err := DecryptFile(encrypted, output, []byte("correct-password"), false); !errors.Is(err, ErrInvalidAkkoFile) {
				t.Fatalf("expected invalid chunk length, got %v", err)
			}
			if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid output was published: %v", err)
			}
		})
	}
}
