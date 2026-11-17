package main

import (
	"regexp"
	"testing"
)

// The build scripts rewrite this exact semver form, so keep it machine-readable.
func TestVersionIsSemver(t *testing.T) {
	if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
		t.Fatalf("version %q is not x.y.z; scripts/build.{ps1,sh} cannot bump it", version)
	}
}
