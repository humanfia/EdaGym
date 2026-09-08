package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const canonicalTestPlan = `{"arguments":[],"capability":"rtl_simulation","driver_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","environment":[],"executable":"sh","input_manifest_digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","invocation_id":"vm_protocol_test","outputs":[],"recipe":[],"run_id":"sha256:3333333333333333333333333333333333333333333333333333333333333333","tool_id":"shell","view":"participant","working_directory":"."}`

func launchForPlan(plan string) []byte {
	return []byte(fmt.Sprintf(
		`{"artifact_target":"/edagym/artifacts","assets":[],"environment_digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","invocation_digest":"%s","kind":"launch","output_limit_bytes":4096,"plan":%s,"schema_version":1,"wall_seconds":1,"workspace":{"entries":[],"readonly":false,"root_blob":null,"root_is_file":false,"root_mode":448,"target":"/edagym/workspace"}}`,
		domainDigest("invocation-plan-v2", []byte(plan)),
		plan,
	))
}

func TestDecodeLaunchBindsCanonicalPlan(t *testing.T) {
	request, err := decodeLaunch(launchForPlan(canonicalTestPlan))
	if err != nil {
		t.Fatalf("canonical request rejected: %v", err)
	}
	if request.InvocationDigest != domainDigest("invocation-plan-v2", []byte(canonicalTestPlan)) {
		t.Fatal("decoded request lost its invocation identity")
	}
	if !validLaunch(request) {
		t.Fatal("canonical request violated the fixed guest namespace")
	}

	mutated := strings.Replace(canonicalTestPlan, `"arguments":[]`, `"arguments":["changed"]`, 1)
	content := launchForPlan(canonicalTestPlan)
	content = []byte(strings.Replace(string(content), canonicalTestPlan, mutated, 1))
	if _, err := decodeLaunch(content); err == nil {
		t.Fatal("plan content changed without changing its digest")
	}

	if _, err := decodeLaunch(append([]byte(" "), launchForPlan(canonicalTestPlan)...)); err == nil {
		t.Fatal("noncanonical request whitespace was accepted")
	}

	unknown := strings.Replace(canonicalTestPlan, `"view":"participant"`, `"unexpected":false,"view":"participant"`, 1)
	if _, err := decodeLaunch(launchForPlan(unknown)); err == nil {
		t.Fatal("unknown invocation-plan field was accepted")
	}
}

func TestReadOutputRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("not an output"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Fatal(err)
	}
	budget := int64(4096)
	output, err := readOutput(
		root,
		outputDeclaration{LogicalID: "result", Path: "redirect/secret", Required: true},
		&budget,
	)
	if err == nil || output != nil {
		t.Fatal("descriptor-safe output collection followed a symlinked parent")
	}
}
