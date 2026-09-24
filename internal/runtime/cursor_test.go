package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCursorRoundTripUsesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cursor")
	if err := saveCursor(path, 42); err != nil {
		t.Fatal(err)
	}
	cursor, err := loadCursor(path)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 42 {
		t.Fatalf("cursor = %d, want 42", cursor)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("cursor mode = %o, want 600", info.Mode().Perm())
	}
}

func TestCursorWriteCreatesParentAndRejectsRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "cursor")
	if err := saveCursor(path, 8); err != nil {
		t.Fatal(err)
	}
	if err := saveCursor(path, 7); err == nil {
		t.Fatal("saveCursor accepted cursor rollback")
	}
	cursor, err := loadCursor(path)
	if err != nil {
		t.Fatal(err)
	}
	if cursor != 8 {
		t.Fatalf("cursor = %d, want 8", cursor)
	}
}

func TestCursorRejectsEmptyAndMalformedState(t *testing.T) {
	for name, contents := range map[string]string{
		"empty":     "",
		"malformed": "nope\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cursor")
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadCursor(path); err == nil {
				t.Fatal("loadCursor accepted invalid state")
			}
		})
	}
}
