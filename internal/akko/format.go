package akko

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	magic            = "AKKO"
	versionV1 uint8  = 1
	algAESGCM uint8  = 1
	kdfArgon2 uint8  = 1
	chunkSize        = 64 * 1024
	maxExtLen uint16 = 255
)

var (
	ErrNotAkkoFile          = errors.New("not an akko file")
	ErrInvalidAkkoFile      = errors.New("invalid akko file")
	ErrUnsupportedVersion   = errors.New("unsupported akko version")
	ErrUnsupportedAlgorithm = errors.New("unsupported encryption algorithm")
	ErrUnsupportedKDF       = errors.New("unsupported KDF")
	ErrAuthFailed           = errors.New("invalid password or corrupted file")
	ErrExpired              = errors.New("encrypted file has expired")
)

// Header is authenticated using AES-GCM AAD.
type Header struct {
	Version      uint8
	Algorithm    uint8
	KDF          uint8
	KDFParams    KDFParams
	Salt         [saltSize]byte
	NonceBase    [8]byte
	OriginalMode uint32
	OriginalExt  string
	ExpiryUnix   int64
}

func (h Header) marshal() ([]byte, error) {
	ext := []byte(h.OriginalExt)
	if len(ext) > int(maxExtLen) {
		return nil, fmt.Errorf("file extension too long")
	}
	if h.Version != versionV1 {
		return nil, ErrUnsupportedVersion
	}

	total := len(magic) + 1 + 1 + 1 + 4 + 4 + 1 + saltSize + 8 + 4 + 2 + len(ext) + 8
	out := make([]byte, total)
	o := 0

	copy(out[o:], []byte(magic))
	o += len(magic)
	out[o] = h.Version
	o++
	out[o] = h.Algorithm
	o++
	out[o] = h.KDF
	o++
	binary.BigEndian.PutUint32(out[o:o+4], h.KDFParams.Memory)
	o += 4
	binary.BigEndian.PutUint32(out[o:o+4], h.KDFParams.Iterations)
	o += 4
	out[o] = h.KDFParams.Parallelism
	o++
	copy(out[o:o+saltSize], h.Salt[:])
	o += saltSize
	copy(out[o:o+8], h.NonceBase[:])
	o += 8
	binary.BigEndian.PutUint32(out[o:o+4], h.OriginalMode)
	o += 4
	binary.BigEndian.PutUint16(out[o:o+2], uint16(len(ext)))
	o += 2
	copy(out[o:], ext)
	o += len(ext)
	binary.BigEndian.PutUint64(out[o:o+8], uint64(h.ExpiryUnix))

	return out, nil
}

func unmarshalHeader(r io.Reader) (Header, []byte, error) {
	var h Header

	fixedLen := len(magic) + 1 + 1 + 1 + 4 + 4 + 1 + saltSize + 8 + 4 + 2
	fixed := make([]byte, fixedLen)
	if _, err := io.ReadFull(r, fixed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return h, nil, ErrNotAkkoFile
		}
		return h, nil, err
	}

	o := 0
	if string(fixed[o:o+len(magic)]) != magic {
		return h, nil, ErrNotAkkoFile
	}
	o += len(magic)

	h.Version = fixed[o]
	o++
	if h.Version != versionV1 {
		return h, nil, ErrUnsupportedVersion
	}
	h.Algorithm = fixed[o]
	o++
	h.KDF = fixed[o]
	o++
	h.KDFParams.Memory = binary.BigEndian.Uint32(fixed[o : o+4])
	o += 4
	h.KDFParams.Iterations = binary.BigEndian.Uint32(fixed[o : o+4])
	o += 4
	h.KDFParams.Parallelism = fixed[o]
	o++
	copy(h.Salt[:], fixed[o:o+saltSize])
	o += saltSize
	copy(h.NonceBase[:], fixed[o:o+8])
	o += 8
	h.OriginalMode = binary.BigEndian.Uint32(fixed[o : o+4])
	o += 4
	extLen := binary.BigEndian.Uint16(fixed[o : o+2])

	if extLen > maxExtLen {
		return h, nil, ErrInvalidAkkoFile
	}

	ext := make([]byte, extLen)
	if _, err := io.ReadFull(r, ext); err != nil {
		return h, nil, ErrInvalidAkkoFile
	}
	h.OriginalExt = string(ext)

	var expiryBuf [8]byte
	if _, err := io.ReadFull(r, expiryBuf[:]); err != nil {
		return h, nil, ErrInvalidAkkoFile
	}
	h.ExpiryUnix = int64(binary.BigEndian.Uint64(expiryBuf[:]))
	if h.Algorithm != algAESGCM {
		return h, nil, ErrUnsupportedAlgorithm
	}
	if h.KDF != kdfArgon2 {
		return h, nil, ErrUnsupportedKDF
	}

	head, err := h.marshal()
	if err != nil {
		return h, nil, ErrInvalidAkkoFile
	}

	return h, head, nil
}

func chunkNonce(base [8]byte, idx uint32) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:8], base[:])
	binary.BigEndian.PutUint32(nonce[8:], idx)
	return nonce
}
