package test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// goListDeps lists the packages env-registry's binary and tests import.
func goListDeps(t *testing.T, pattern string, test bool) []string {
	t.Helper()
	args := []string{"list", "-deps"}
	if test {
		args = append(args, "-test")
	}
	args = append(args, "-f", "{{.ImportPath}}", pattern)
	cmd := exec.Command("go", args...)
	cmd.Dir = serviceDir(t)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %v: %v", args, err)
	}
	return strings.Fields(string(out))
}

// Requirement: service-platform service runs from its own directory and image.
func TestServicePlatformServiceRunsFromItsOwnDirectoryAndImage(t *testing.T) {
	t.Run("Change to one service selects only its tests", func(t *testing.T) {
		// env-registry's code and tests import no other service, so a change
		// elsewhere cannot affect them and a change here needs only them.
		for _, pkg := range append(goListDeps(t, "./...", true), goListDeps(t, "./...", false)...) {
			const module = "github.com/pandops/flowai-env-registry"
			if strings.HasPrefix(pkg, "github.com/flowai/platform/") ||
				(strings.HasPrefix(pkg, "github.com/pandops/flowai-") && pkg != module && !strings.HasPrefix(pkg, module+"/")) {
				t.Errorf("env-registry depends on %s", pkg)
			}
		}
		raw, err := os.ReadFile(filepath.Join(serviceDir(t), "qualification", "gitea-declarations.json"))
		if err != nil {
			t.Fatal(err)
		}
		var declarations struct {
			Services map[string]string `json:"services"`
		}
		if err := json.Unmarshal(raw, &declarations); err != nil {
			t.Fatal(err)
		}
		if declarations.Services["env-registry"] != "svc/env-registry" {
			t.Error("Gitea test ownership does not map env-registry to svc/env-registry")
		}
	})
}
