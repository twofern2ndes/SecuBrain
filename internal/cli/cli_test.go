package cli

import (
	"reflect"
	"testing"
)

func TestSplitCommandWindowsPath(t *testing.T) {
	args, err := splitCommand(`scan --path "C:\Users\Dev\My Project" --out "C:\Temp\reports"`)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"scan", "--path", `C:\Users\Dev\My Project`, "--out", `C:\Temp\reports`}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("got %#v want %#v", args, expected)
	}
}

func TestPositionalFolderAfterFlags(t *testing.T) {
	args := movePositionals([]string{"./api", "--out", "./reports", "--max-files", "30", "--authorized"})
	expected := []string{"--out", "./reports", "--max-files", "30", "--authorized", "./api"}
	if !reflect.DeepEqual(args, expected) {
		t.Fatalf("got %#v", args)
	}
}
