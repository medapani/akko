package akko

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateKDFParams(t *testing.T) {
	tests := []struct {
		name      string
		params    KDFParams
		wantError string
	}{
		{name: "standard", params: KDFParams{Memory: 64 * 1024, Iterations: 3, Parallelism: 2}},
		{name: "secure", params: HighSecurityKDFParams},
		{name: "minimum", params: KDFParams{Memory: 8, Iterations: 1, Parallelism: 1}},
		{name: "minimum two lanes", params: KDFParams{Memory: 16, Iterations: 1, Parallelism: 2}},
		{name: "maximum", params: KDFParams{Memory: maxKDFMemoryKiB, Iterations: maxKDFIterations, Parallelism: 2}},
		{name: "minimum for maximum lanes", params: KDFParams{Memory: 8 * 2, Iterations: 1, Parallelism: 2}},
		{name: "zero memory", params: KDFParams{Memory: 0, Iterations: 1, Parallelism: 1}, wantError: "invalid kdf parameters"},
		{name: "zero iterations", params: KDFParams{Memory: 8, Iterations: 0, Parallelism: 1}, wantError: "invalid kdf parameters"},
		{name: "zero lanes", params: KDFParams{Memory: 8, Iterations: 1, Parallelism: 0}, wantError: "invalid kdf parameters"},
		{name: "below minimum", params: KDFParams{Memory: 7, Iterations: 1, Parallelism: 1}, wantError: "invalid kdf parameters"},
		{name: "below minimum two lanes", params: KDFParams{Memory: 15, Iterations: 1, Parallelism: 2}, wantError: "invalid kdf parameters"},
		{name: "memory above maximum", params: KDFParams{Memory: maxKDFMemoryKiB + 1, Iterations: 1, Parallelism: 1}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
		{name: "iterations above maximum", params: KDFParams{Memory: 8, Iterations: maxKDFIterations + 1, Parallelism: 1}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
		{name: "parallelism above maximum", params: KDFParams{Memory: 24, Iterations: 1, Parallelism: 3}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
		{name: "maximum uint8 parallelism", params: KDFParams{Memory: 8 * 255, Iterations: 1, Parallelism: 255}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
		{name: "maximum uint32 memory", params: KDFParams{Memory: ^uint32(0), Iterations: 1, Parallelism: 1}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
		{name: "maximum uint32 iterations", params: KDFParams{Memory: 8, Iterations: ^uint32(0), Parallelism: 1}, wantError: "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate boundaries without running Argon2id at the resource limits.
			err := validateKDFParams(tt.params)
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || err.Error() != tt.wantError {
				t.Fatalf("got %v, want %q", err, tt.wantError)
			}
		})
	}
}

func TestDeriveKeyValidatesParams(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, saltSize)
	if _, err := deriveKey([]byte("password"), salt, KDFParams{Memory: 1, Iterations: 1, Parallelism: 1}); err == nil || err.Error() != "invalid kdf parameters" {
		t.Fatalf("expected invalid kdf parameters, got %v", err)
	}
	key, err := deriveKey([]byte("password"), salt, KDFParams{Memory: 8, Iterations: 1, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != keySize {
		t.Fatalf("got key size %d, want %d", len(key), keySize)
	}
	if _, err := deriveKey([]byte("password"), salt[:saltSize-1], KDFParams{Memory: 8, Iterations: 1, Parallelism: 1}); err == nil {
		t.Fatal("expected invalid salt length")
	}
}

func TestDecryptRejectsExcessiveKDFParams(t *testing.T) {
	tests := []struct {
		name   string
		params KDFParams
	}{
		{name: "memory", params: KDFParams{Memory: 256*1024 + 1, Iterations: 1, Parallelism: 1}},
		{name: "iterations", params: KDFParams{Memory: 8, Iterations: 5, Parallelism: 1}},
		{name: "parallelism", params: KDFParams{Memory: 24, Iterations: 1, Parallelism: 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "excessive.akko")
			output := filepath.Join(dir, "decrypted.bin")
			header := Header{
				Version:   versionV1,
				Algorithm: algAESGCM,
				KDF:       kdfArgon2,
				KDFParams: tt.params,
			}

			data, err := header.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(input, data, 0o600); err != nil {
				t.Fatal(err)
			}

			err = DecryptFile(input, output, []byte("password"), false)
			if err == nil || err.Error() != "KDF resource limit exceeded (maximum 256 MiB, 4 iterations, parallelism 2)" {
				t.Fatalf("expected KDF resource limit error, got %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("output should not exist for rejected KDF parameters: %v", err)
			}
		})
	}
}
