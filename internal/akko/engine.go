package akko

import (
	"archive/tar"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Mode indicates whether the input should be encrypted or decrypted.
type Mode int

const (
	ModeEncrypt Mode = iota + 1
	ModeDecrypt
	ModeDecryptArchive
)

// archiveMarkerExt is stored as the (authenticated) OriginalExt of an akko
// file whose payload is a tar bundle of multiple input files, rather than a
// single file's contents. It is not a real file extension.
const archiveMarkerExt = ".akkoarchive"

func DetectMode(inputPath string) (Mode, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	buf := make([]byte, len(magic))
	if _, err := io.ReadFull(f, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return ModeEncrypt, nil
		}
		return 0, err
	}
	if string(buf) == magic {
		return ModeDecrypt, nil
	}
	return ModeEncrypt, nil
}

func DefaultOutputPath(inputPath string, mode Mode, originalExt string) string {
	if mode == ModeEncrypt {
		return inputPath + ".akko"
	}
	// standard "<name>.akko" naming already has the original extension embedded.
	if strings.HasSuffix(inputPath, ".akko") {
		return strings.TrimSuffix(inputPath, ".akko")
	}
	if originalExt == "" {
		return inputPath + ".dec"
	}
	base := strings.TrimSuffix(inputPath, filepath.Ext(inputPath))
	return base + originalExt
}

func PeekHeader(inputPath string) (Header, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return Header{}, err
	}
	defer f.Close()

	h, _, err := unmarshalHeader(f)
	return h, err
}

func EncryptFile(inputPath, outputPath string, password []byte, force bool) error {
	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}
	if err := ensureRegularFile(inputPath); err != nil {
		return err
	}
	if err := ensureOutputPath(inputPath, outputPath, force); err != nil {
		return err
	}

	st, err := os.Stat(inputPath)
	if err != nil {
		return err
	}

	salt, err := randomBytes(saltSize)
	if err != nil {
		return err
	}
	nonceBase, err := randomBytes(8)
	if err != nil {
		return err
	}

	var h Header
	h.Version = versionV1
	h.Algorithm = algAESGCM
	h.KDF = kdfArgon2
	h.KDFParams = defaultKDFParams
	copy(h.Salt[:], salt)
	copy(h.NonceBase[:], nonceBase)
	h.OriginalMode = uint32(st.Mode().Perm())
	h.OriginalExt = filepath.Ext(inputPath)
	h.ExpiryUnix = defaultExpiryUnix

	headBytes, err := h.marshal()
	if err != nil {
		return err
	}

	key, err := deriveKey(password, salt, h.KDFParams)
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	return safeWriteFile(outputPath, func(out *os.File) error {
		if _, err := out.Write(headBytes); err != nil {
			return err
		}

		buf := make([]byte, chunkSize)
		var idx uint32
		for {
			n, readErr := in.Read(buf)
			if n > 0 {
				nonce := chunkNonce(h.NonceBase, idx)
				ciphertext := gcm.Seal(nil, nonce, buf[:n], headBytes)
				var lenBuf [4]byte
				binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ciphertext)))
				if _, err := out.Write(lenBuf[:]); err != nil {
					return err
				}
				if _, err := out.Write(ciphertext); err != nil {
					return err
				}
				idx++
			}
			if errors.Is(readErr, io.EOF) {
				break
			}
			if readErr != nil {
				return readErr
			}
		}
		return nil
	})
}

func DecryptFile(inputPath, outputPath string, password []byte, force bool) error {
	if len(password) == 0 {
		return errors.New("password cannot be empty")
	}
	if err := ensureRegularFile(inputPath); err != nil {
		return err
	}
	if err := ensureOutputPath(inputPath, outputPath, force); err != nil {
		return err
	}

	in, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer in.Close()

	h, headBytes, err := unmarshalHeader(in)
	if err != nil {
		return err
	}
	if h.ExpiryUnix > 0 && time.Now().Unix() > h.ExpiryUnix {
		return ErrExpired
	}

	key, err := deriveKey(password, h.Salt[:], h.KDFParams)
	if err != nil {
		return err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}

	if err := safeWriteFile(outputPath, func(out *os.File) error {
		var idx uint32
		var lenBuf [4]byte
		for {
			_, err := io.ReadFull(in, lenBuf[:])
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return ErrInvalidAkkoFile
			}

			chunkLen := binary.BigEndian.Uint32(lenBuf[:])
			if chunkLen == 0 {
				return ErrInvalidAkkoFile
			}

			ciphertext := make([]byte, chunkLen)
			if _, err := io.ReadFull(in, ciphertext); err != nil {
				return ErrInvalidAkkoFile
			}

			nonce := chunkNonce(h.NonceBase, idx)
			plaintext, err := gcm.Open(nil, nonce, ciphertext, headBytes)
			if err != nil {
				return ErrAuthFailed
			}
			if _, err := out.Write(plaintext); err != nil {
				return err
			}
			idx++
		}

		return nil
	}); err != nil {
		return err
	}

	if h.OriginalMode != 0 {
		if err := os.Chmod(outputPath, os.FileMode(h.OriginalMode)); err != nil {
			return err
		}
	}
	return nil
}

// onEntry, when non-nil, is called with the archive-relative name of each
// file as it is packed into (or unpacked from) an akko archive, so callers
// can print progress similar to `tar -v` / `unzip`.
type onEntryFunc func(name string)

func Action(inputPath, outputPath string, password []byte, force bool, onEntry onEntryFunc) (Mode, string, int, error) {
	mode, err := DetectMode(inputPath)
	if err != nil {
		return 0, "", 0, err
	}

	if mode == ModeDecrypt {
		h, err := PeekHeader(inputPath)
		if err != nil {
			if errors.Is(err, ErrNotAkkoFile) {
				return 0, "", 0, ErrInvalidAkkoFile
			}
			return 0, "", 0, err
		}
		if h.OriginalExt == archiveMarkerExt {
			outDir := outputPath
			if outDir == "" {
				outDir = "."
			}
			extracted, err := DecryptArchive(inputPath, outDir, password, force, onEntry)
			if err != nil {
				return 0, "", 0, err
			}
			return ModeDecryptArchive, outDir, len(extracted), nil
		}
		if outputPath == "" {
			outputPath = DefaultOutputPath(inputPath, mode, h.OriginalExt)
		}
		err = DecryptFile(inputPath, outputPath, password, force)
		if err != nil {
			return mode, outputPath, 0, err
		}
		return mode, outputPath, 1, nil
	}

	if outputPath == "" {
		outputPath = DefaultOutputPath(inputPath, mode, "")
	}
	err = EncryptFile(inputPath, outputPath, password, force)
	if err != nil {
		return mode, outputPath, 0, err
	}
	return mode, outputPath, 1, nil
}

// archiveEntry pairs a source file path with the (structure-preserving)
// name it will be stored under inside the tar payload.
type archiveEntry struct {
	path string
	name string
}

// archiveEntryName derives a tar entry name from a source path that
// preserves its directory structure, while sanitizing it into a safe
// relative path (no leading "/", volume name, or ".." traversal).
func archiveEntryName(path string) (string, error) {
	clean := filepath.Clean(path)
	clean = strings.TrimPrefix(clean, filepath.VolumeName(clean))
	name := filepath.ToSlash(clean)
	name = strings.TrimPrefix(name, "/")
	for strings.HasPrefix(name, "../") {
		name = strings.TrimPrefix(name, "../")
	}
	if name == "" || name == "." || name == ".." {
		return "", fmt.Errorf("cannot determine an archive entry name for %s", path)
	}
	return name, nil
}

// EncryptArchive bundles multiple regular files into a single tar payload
// and encrypts it as one akko file. Each file's relative path (sanitized to
// remove any leading "/" or "..") is preserved as the archive entry name, so
// duplicates are only rejected when the resulting entry names collide.
func EncryptArchive(inputs []string, outputPath string, password []byte, force bool, onEntry onEntryFunc) (string, error) {
	if len(inputs) == 0 {
		return "", errors.New("no input files to archive")
	}

	entries := make([]archiveEntry, 0, len(inputs))
	seenNames := make(map[string]bool, len(inputs))
	for _, in := range inputs {
		if err := ensureRegularFile(in); err != nil {
			return "", fmt.Errorf("%s: %w", in, err)
		}
		name, err := archiveEntryName(in)
		if err != nil {
			return "", err
		}
		if seenNames[name] {
			return "", fmt.Errorf("duplicate file name in archive: %s", name)
		}
		seenNames[name] = true
		entries = append(entries, archiveEntry{path: in, name: name})
	}

	if outputPath == "" {
		outputPath = "archive.akko"
	}

	tmpDir, err := os.MkdirTemp("", "akko-archive-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)

	tarPath := filepath.Join(tmpDir, "bundle"+archiveMarkerExt)
	if err := writeTarArchive(tarPath, entries, onEntry); err != nil {
		return "", err
	}

	if err := EncryptFile(tarPath, outputPath, password, force); err != nil {
		return "", err
	}
	return outputPath, nil
}

// DecryptArchive decrypts an akko archive file and extracts its contents
// into outputDir, returning the paths of the extracted files.
func DecryptArchive(inputPath, outputDir string, password []byte, force bool, onEntry onEntryFunc) ([]string, error) {
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "akko-archive-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	tarPath := filepath.Join(tmpDir, "bundle.tar")
	if err := DecryptFile(inputPath, tarPath, password, true); err != nil {
		return nil, err
	}

	return extractTarArchive(tarPath, outputDir, force, onEntry)
}

func writeTarArchive(tarPath string, entries []archiveEntry, onEntry onEntryFunc) error {
	out, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer out.Close()

	tw := tar.NewWriter(out)
	for _, e := range entries {
		if onEntry != nil {
			onEntry(e.name)
		}
		if err := addFileToTar(tw, e.path, e.name); err != nil {
			tw.Close()
			return err
		}
	}
	return tw.Close()
}

func addFileToTar(tw *tar.Writer, path, name string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}

	hdr := &tar.Header{
		Name: name,
		Mode: int64(st.Mode().Perm()),
		Size: st.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

func extractTarArchive(tarPath, outputDir string, force bool, onEntry onEntryFunc) ([]string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var extracted []string
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return extracted, ErrInvalidAkkoFile
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}

		// reject path traversal / absolute paths from a maliciously crafted archive.
		name := filepath.Clean(hdr.Name)
		if name == "." || name == ".." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			return extracted, ErrInvalidAkkoFile
		}

		if onEntry != nil {
			onEntry(name)
		}

		target := filepath.Join(outputDir, name)
		if !force {
			if _, err := os.Stat(target); err == nil {
				return extracted, fmt.Errorf("output file already exists (use -force to overwrite): %s", target)
			}
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return extracted, err
		}

		mode := os.FileMode(hdr.Mode) & 0o777
		if mode == 0 {
			mode = 0o600
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
		if err != nil {
			return extracted, err
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return extracted, err
		}
		out.Close()
		if err := os.Chmod(target, mode); err != nil {
			return extracted, err
		}
		extracted = append(extracted, target)
	}
	return extracted, nil
}
