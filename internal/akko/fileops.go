package akko

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func ensureRegularFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("input file does not exist")
		}
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("input must be a regular file")
	}
	return nil
}

func ensureOutputPath(inputPath, outputPath string, force bool) error {
	inAbs, err := filepath.Abs(inputPath)
	if err != nil {
		return err
	}
	outAbs, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	if inAbs == outAbs {
		return errors.New("input and output must be different files")
	}

	parent := filepath.Dir(outAbs)
	st, err := os.Stat(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errors.New("output parent directory does not exist")
		}
		return err
	}
	if !st.IsDir() {
		return errors.New("output parent is not a directory")
	}

	if _, err := os.Stat(outAbs); err == nil && !force {
		return errors.New("output file already exists (use -force to overwrite)")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}

func safeWriteFile(outputPath string, writeFn func(tmp *os.File) error) error {
	dir := filepath.Dir(outputPath)
	pattern := fmt.Sprintf(".%s.tmp-*", filepath.Base(outputPath))
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := writeFn(tmp); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}

	if err := os.Rename(tmpName, outputPath); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
