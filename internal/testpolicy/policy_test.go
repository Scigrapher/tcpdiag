package testpolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This test enforces a repository rule rather than application behaviour:
//
//	The default test suite must not create a wildcard (0.0.0.0) listening
//	socket or call the wildcard probe entry points. On Windows a listening
//	socket bound to all interfaces, for an unsigned binary, raises a
//	firewall/elevation dialog, which makes `go test` unusable in an automated
//	context. Anything that genuinely needs it must be opt-in behind
//	TCPDIAG_TEST_NETWORK=1.
//
// Encoding the rule as a test means CI fails loudly if someone reintroduces a
// prompting call, instead of the rule decaying silently.

const optInMarker = "TCPDIAG_TEST_NETWORK"

func repoRoot(t *testing.T) string {
	t.Helper()
	_, this, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("cannot determine the test file path")
	}
	dir := filepath.Dir(this)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate the module root")
	return ""
}

var forbidden = []struct {
	bad     string
	good    string
	suggest string
}{
	{"StartServer(", "StartServerOn(", `bind loopback with StartServerOn("127.0.0.1", 0)`},
	{"NewClient(", "NewClientOn(", `bind loopback with NewClientOn("127.0.0.1", 0)`},
	{`"0.0.0.0"`, "", "bind 127.0.0.1, or gate the test behind " + optInMarker},
}

func TestDefaultSuiteMakesNoPromptingSocketCalls(t *testing.T) {
	root := repoRoot(t)
	var offenders []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if name := d.Name(); name == "bin" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if strings.Contains(rel, "policy_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		text := string(src)
		if strings.Contains(text, optInMarker) {
			return nil
		}
		for _, f := range forbidden {
			if !containsCall(text, f.bad) {
				continue
			}
			offenders = append(offenders, rel+": uses "+f.bad+" - "+f.suggest)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("the default test suite would prompt on Windows:\n  %s", strings.Join(offenders, "\n  "))
	}
}

// containsCall reports whether text really calls name(, as opposed to merely
// containing it inside a longer identifier such as StartServerOn(.
func containsCall(text, name string) bool {
	// name ends with "(" (or a quote), so the character following a match is
	// the start of the argument and means nothing. Only a preceding identifier
	// character means the hit is really part of a longer name such as
	// notStartServer(. Note that "StartServer(" is not a substring of
	// "StartServerOn(" at all, so no trailing check is needed.
	idx := 0
	for {
		j := strings.Index(text[idx:], name)
		if j < 0 {
			return false
		}
		at := idx + j
		if at > 0 && isIdentChar(text[at-1]) {
			idx = at + 1
			continue
		}
		return true
	}
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
