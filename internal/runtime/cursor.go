package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func loadCursor(path string) (uint64, error) {
	if path == "" {
		return 0, nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("runtime: read cursor: %w", err)
	}
	cursor, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("runtime: parse cursor: %w", err)
	}
	return cursor, nil
}

func saveCursor(path string, cursor uint64) error {
	if path == "" {
		return nil
	}
	current, err := loadCursor(path)
	if err != nil {
		return err
	}
	if cursor < current {
		return fmt.Errorf("runtime: cursor rollback from %d to %d", current, cursor)
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("runtime: create cursor directory: %w", err)
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("runtime: create cursor temporary file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("runtime: secure cursor temporary file: %w", err)
	}
	if _, err := fmt.Fprintf(file, "%d\n", cursor); err != nil {
		_ = file.Close()
		return fmt.Errorf("runtime: write cursor: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("runtime: sync cursor: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("runtime: close cursor: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("runtime: replace cursor: %w", err)
	}
	dir, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("runtime: open cursor directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("runtime: sync cursor directory: %w", err)
	}
	return nil
}
