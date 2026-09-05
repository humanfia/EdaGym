package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	channelPath  = "/dev/virtio-ports/org.edagym.control.0"
	frameLimit   = 64 * 1024 * 1024
	guestUID     = 65534
	guestGID     = 65534
	guestRunRoot = "/edagym"
)

var (
	identifierPattern  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	executablePattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	environmentPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	integerPattern     = regexp.MustCompile(`^(?:0|-?[1-9][0-9]*)$`)
	debugEnabled       = guestDebugEnabled()
)

func guestDebugEnabled() bool {
	content, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return false
	}
	for _, token := range strings.Fields(string(content)) {
		if token == "edagym.debug=1" {
			return true
		}
	}
	return false
}

func debugLog(message string) {
	if !debugEnabled {
		return
	}
	console, err := os.OpenFile("/dev/console", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	_, _ = console.WriteString("edagym-vm-agent: " + message + "\n")
	_ = console.Close()
}

type inlineBlob struct {
	Digest        string `json:"digest"`
	SizeBytes     int64  `json:"size_bytes"`
	ContentBase64 string `json:"content_base64"`
}

type treeEntry struct {
	Path string      `json:"path"`
	Kind string      `json:"kind"`
	Mode uint32      `json:"mode"`
	Blob *inlineBlob `json:"blob"`
}

type transferTree struct {
	Target     string      `json:"target"`
	Readonly   bool        `json:"readonly"`
	RootIsFile bool        `json:"root_is_file"`
	RootMode   uint32      `json:"root_mode"`
	RootBlob   *inlineBlob `json:"root_blob"`
	Entries    []treeEntry `json:"entries"`
}

type assetTransfer struct {
	AssetID          string       `json:"asset_id"`
	RestrictedDigest string       `json:"restricted_digest"`
	Tree             transferTree `json:"tree"`
}

type environmentEntry struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type outputDeclaration struct {
	LogicalID     string `json:"logical_id"`
	Path          string `json:"path"`
	MediaType     string `json:"media_type"`
	ArtifactClass string `json:"artifact_class"`
	Required      bool   `json:"required"`
}

type invocationPlan struct {
	InvocationID string              `json:"invocation_id"`
	Capability   string              `json:"capability"`
	ToolID       string              `json:"tool_id"`
	DriverDigest string              `json:"driver_digest"`
	View         string              `json:"view"`
	Executable   string              `json:"executable"`
	Arguments    []string            `json:"arguments"`
	WorkingDir   string              `json:"working_directory"`
	Environment  []environmentEntry  `json:"environment"`
	InputDigest  string              `json:"input_manifest_digest"`
	Recipe       []json.RawMessage   `json:"recipe"`
	Outputs      []outputDeclaration `json:"outputs"`
}

type launchRequest struct {
	Kind              string          `json:"kind"`
	SchemaVersion     int             `json:"schema_version"`
	Plan              invocationPlan  `json:"plan"`
	InvocationDigest  string          `json:"invocation_digest"`
	EnvironmentDigest string          `json:"environment_digest"`
	Workspace         transferTree    `json:"workspace"`
	ArtifactTarget    string          `json:"artifact_target"`
	Assets            []assetTransfer `json:"assets"`
	WallSeconds       int             `json:"wall_seconds"`
	OutputLimitBytes  int             `json:"output_limit_bytes"`
	RequestDigest     string          `json:"-"`
}

type launchWire struct {
	Kind              string          `json:"kind"`
	SchemaVersion     int             `json:"schema_version"`
	Plan              json.RawMessage `json:"plan"`
	InvocationDigest  string          `json:"invocation_digest"`
	EnvironmentDigest string          `json:"environment_digest"`
	Workspace         transferTree    `json:"workspace"`
	ArtifactTarget    string          `json:"artifact_target"`
	Assets            []assetTransfer `json:"assets"`
	WallSeconds       int             `json:"wall_seconds"`
	OutputLimitBytes  int             `json:"output_limit_bytes"`
}

type controlRequest struct {
	Kind             string `json:"kind"`
	SchemaVersion    int    `json:"schema_version"`
	InvocationID     string `json:"invocation_id"`
	InvocationDigest string `json:"invocation_digest"`
}

type requestEnvelope struct {
	Kind string `json:"kind"`
}

type replyIdentity struct {
	Kind             string `json:"kind"`
	SchemaVersion    int    `json:"schema_version"`
	InvocationID     string `json:"invocation_id"`
	InvocationDigest string `json:"invocation_digest"`
	RequestDigest    string `json:"request_digest"`
}

type guestOutput struct {
	LogicalID string     `json:"logical_id"`
	Blob      inlineBlob `json:"blob"`
}

type resultReply struct {
	Kind              string        `json:"kind"`
	SchemaVersion     int           `json:"schema_version"`
	InvocationID      string        `json:"invocation_id"`
	InvocationDigest  string        `json:"invocation_digest"`
	RequestDigest     string        `json:"request_digest"`
	EnvironmentDigest string        `json:"environment_digest"`
	State             string        `json:"state"`
	ExitCode          int           `json:"exit_code"`
	Failure           *string       `json:"failure"`
	Stdout            inlineBlob    `json:"stdout"`
	Stderr            inlineBlob    `json:"stderr"`
	Outputs           []guestOutput `json:"outputs"`
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (writer *boundedBuffer) Write(content []byte) (int, error) {
	remaining := writer.limit - writer.buffer.Len()
	if remaining > 0 {
		accepted := len(content)
		if accepted > remaining {
			accepted = remaining
		}
		_, _ = writer.buffer.Write(content[:accepted])
	}
	if len(content) > remaining {
		writer.overflow = true
	}
	return len(content), nil
}

type invocation struct {
	mutex     sync.Mutex
	request   launchRequest
	command   *exec.Cmd
	result    *resultReply
	cancelled bool
}

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func domainDigest(domain string, content []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("edagym\x00" + domain + "\x00"))
	_, _ = digest.Write(content)
	return "sha256:" + hex.EncodeToString(digest.Sum(nil))
}

func strictDecode(content []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("JSON message has trailing content")
	}
	return nil
}

func canonicalJSON(content []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("JSON message has trailing content")
	}
	var result bytes.Buffer
	if err := appendCanonicalJSON(&result, value); err != nil {
		return nil, err
	}
	return result.Bytes(), nil
}

func appendCanonicalJSON(output *bytes.Buffer, value any) error {
	switch typed := value.(type) {
	case nil:
		output.WriteString("null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
	case string:
		encoded, err := encodeCanonicalString(typed)
		if err != nil {
			return err
		}
		output.Write(encoded)
	case json.Number:
		rendered := typed.String()
		if !integerPattern.MatchString(rendered) {
			return errors.New("VM messages only permit canonical integers")
		}
		integer, err := strconv.ParseInt(rendered, 10, 64)
		if err != nil || integer < -9007199254740991 || integer > 9007199254740991 {
			return errors.New("VM message integer exceeds its canonical bound")
		}
		output.WriteString(strconv.FormatInt(integer, 10))
	case []any:
		output.WriteByte('[')
		for index, item := range typed {
			if index != 0 {
				output.WriteByte(',')
			}
			if err := appendCanonicalJSON(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output.WriteByte('{')
		for index, key := range keys {
			if index != 0 {
				output.WriteByte(',')
			}
			encoded, err := encodeCanonicalString(key)
			if err != nil {
				return err
			}
			output.Write(encoded)
			output.WriteByte(':')
			if err := appendCanonicalJSON(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
	default:
		return errors.New("unsupported JSON value")
	}
	return nil
}

func encodeCanonicalString(value string) ([]byte, error) {
	var encoded bytes.Buffer
	encoder := json.NewEncoder(&encoded)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	result := bytes.TrimSuffix(encoded.Bytes(), []byte{'\n'})
	result = bytes.ReplaceAll(result, []byte(`\u2028`), []byte("\u2028"))
	result = bytes.ReplaceAll(result, []byte(`\u2029`), []byte("\u2029"))
	return result, nil
}

func decodeLaunch(content []byte) (launchRequest, error) {
	canonical, err := canonicalJSON(content)
	if err != nil || !bytes.Equal(canonical, content) {
		return launchRequest{}, errors.New("launch request is not canonical JSON")
	}
	var wire launchWire
	if err := strictDecode(content, &wire); err != nil {
		return launchRequest{}, err
	}
	var plan invocationPlan
	if err := strictDecode(wire.Plan, &plan); err != nil {
		return launchRequest{}, err
	}
	if domainDigest("invocation-plan-v1", wire.Plan) != wire.InvocationDigest {
		return launchRequest{}, errors.New("invocation plan digest is invalid")
	}
	return launchRequest{
		Kind:              wire.Kind,
		SchemaVersion:     wire.SchemaVersion,
		Plan:              plan,
		InvocationDigest:  wire.InvocationDigest,
		EnvironmentDigest: wire.EnvironmentDigest,
		Workspace:         wire.Workspace,
		ArtifactTarget:    wire.ArtifactTarget,
		Assets:            wire.Assets,
		WallSeconds:       wire.WallSeconds,
		OutputLimitBytes:  wire.OutputLimitBytes,
		RequestDigest:     domainDigest("vm-guest-protocol-v1", content),
	}, nil
}

func makeBlob(content []byte) inlineBlob {
	return inlineBlob{
		Digest:        digestBytes(content),
		SizeBytes:     int64(len(content)),
		ContentBase64: base64.StdEncoding.EncodeToString(content),
	}
}

func decodeBlob(blob inlineBlob, maximum int64) ([]byte, error) {
	if blob.SizeBytes < 0 || blob.SizeBytes > maximum {
		return nil, errors.New("inline content exceeds its bound")
	}
	content, err := base64.StdEncoding.Strict().DecodeString(blob.ContentBase64)
	if err != nil || int64(len(content)) != blob.SizeBytes || digestBytes(content) != blob.Digest {
		return nil, errors.New("inline content identity is invalid")
	}
	if base64.StdEncoding.EncodeToString(content) != blob.ContentBase64 {
		return nil, errors.New("inline content encoding is not canonical")
	}
	return content, nil
}

func validTarget(target string) bool {
	if !strings.HasPrefix(target, "/") || target == "/" || filepath.Clean(target) != target {
		return false
	}
	if !strings.HasPrefix(target, guestRunRoot+"/") {
		return false
	}
	for _, reserved := range []string{"/dev", "/proc", "/sys", "/run"} {
		if target == reserved || strings.HasPrefix(target, reserved+"/") {
			return false
		}
	}
	return true
}

func prepareTargetParents(target string) error {
	parent := filepath.Dir(target)
	parents := []string{}
	for parent != "/" && parent != "." {
		parents = append(parents, parent)
		parent = filepath.Dir(parent)
	}
	for index := len(parents) - 1; index >= 0; index-- {
		if err := os.MkdirAll(parents[index], 0755); err != nil {
			return err
		}
		if err := os.Chmod(parents[index], 0755); err != nil {
			return err
		}
	}
	return nil
}

func validRelative(path string) bool {
	return path != "" && path != "." && !filepath.IsAbs(path) && filepath.Clean(path) == path &&
		path != ".." && !strings.HasPrefix(path, "../")
}

func materializeTree(tree transferTree, budget *int64) error {
	if !validTarget(tree.Target) || (tree.RootMode != 0600 && tree.RootMode != 0700) {
		return errors.New("invalid transfer root")
	}
	if err := prepareTargetParents(tree.Target); err != nil {
		return err
	}
	if tree.RootIsFile {
		if tree.RootBlob == nil || len(tree.Entries) != 0 {
			return errors.New("invalid root file")
		}
		content, err := decodeBlob(*tree.RootBlob, *budget)
		if err != nil {
			return err
		}
		*budget -= int64(len(content))
		if err := os.MkdirAll(filepath.Dir(tree.Target), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(tree.Target, content, os.FileMode(tree.RootMode)); err != nil {
			return err
		}
		if tree.Readonly {
			mode := os.FileMode(0444)
			if tree.RootMode&0100 != 0 {
				mode = 0555
			}
			return os.Chmod(tree.Target, mode)
		}
		return nil
	}
	if tree.RootBlob != nil {
		return errors.New("directory root carries content")
	}
	if err := os.MkdirAll(tree.Target, 0700); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, entry := range tree.Entries {
		if !validRelative(entry.Path) || seen[entry.Path] ||
			(entry.Mode != 0600 && entry.Mode != 0700) {
			return errors.New("invalid transfer entry")
		}
		seen[entry.Path] = true
		destination := filepath.Join(tree.Target, entry.Path)
		if entry.Kind == "directory" {
			if entry.Blob != nil {
				return errors.New("directory carries content")
			}
			if err := os.MkdirAll(destination, 0700); err != nil {
				return err
			}
			continue
		}
		if entry.Kind != "file" || entry.Blob == nil {
			return errors.New("file content is missing")
		}
		content, err := decodeBlob(*entry.Blob, *budget)
		if err != nil {
			return err
		}
		*budget -= int64(len(content))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(destination, content, os.FileMode(entry.Mode)); err != nil {
			return err
		}
	}
	if tree.Readonly {
		return filepath.Walk(tree.Target, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			mode := os.FileMode(0444)
			if info.IsDir() || info.Mode()&0100 != 0 {
				mode = 0555
			}
			return os.Chmod(path, mode)
		})
	}
	return nil
}

func grantWritableTree(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if err := os.Chown(path, guestUID, guestGID); err != nil {
			return err
		}
		mode := os.FileMode(0600)
		if info.IsDir() || info.Mode()&0100 != 0 {
			mode = 0700
		}
		return os.Chmod(path, mode)
	})
}

func sameStat(left *syscall.Stat_t, right *syscall.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Uid == right.Uid && left.Gid == right.Gid && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}

func readOutput(root string, declaration outputDeclaration, budget *int64) (*guestOutput, error) {
	if !validRelative(declaration.Path) {
		return nil, errors.New("invalid output path")
	}
	rootDescriptor, err := syscall.Open(
		root,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, errors.New("output root is unavailable")
	}
	descriptor := rootDescriptor
	parts := strings.Split(declaration.Path, "/")
	for _, part := range parts[:len(parts)-1] {
		child, openError := syscall.Openat(
			descriptor,
			part,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
			0,
		)
		if descriptor != rootDescriptor {
			_ = syscall.Close(descriptor)
		}
		if openError != nil {
			_ = syscall.Close(rootDescriptor)
			if errors.Is(openError, syscall.ENOENT) && !declaration.Required {
				return nil, nil
			}
			return nil, errors.New("output parent is unavailable")
		}
		descriptor = child
	}
	fileDescriptor, openError := syscall.Openat(
		descriptor,
		parts[len(parts)-1],
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK,
		0,
	)
	if descriptor != rootDescriptor {
		_ = syscall.Close(descriptor)
	}
	_ = syscall.Close(rootDescriptor)
	if openError != nil {
		if errors.Is(openError, syscall.ENOENT) && !declaration.Required {
			return nil, nil
		}
		return nil, errors.New("required output is unavailable")
	}
	file := os.NewFile(uintptr(fileDescriptor), "vm-output")
	defer file.Close()
	var before syscall.Stat_t
	if syscall.Fstat(fileDescriptor, &before) != nil || before.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		before.Nlink != 1 || before.Size < 0 || before.Size > *budget {
		return nil, errors.New("output is not a bounded regular file")
	}
	content, err := io.ReadAll(io.LimitReader(file, *budget+1))
	var after syscall.Stat_t
	if err != nil || int64(len(content)) != before.Size || syscall.Fstat(fileDescriptor, &after) != nil ||
		!sameStat(&before, &after) {
		return nil, errors.New("output changed while read")
	}
	*budget -= int64(len(content))
	return &guestOutput{LogicalID: declaration.LogicalID, Blob: makeBlob(content)}, nil
}

func validLaunch(request launchRequest) bool {
	if request.SchemaVersion != 1 || request.Kind != "launch" ||
		!identifierPattern.MatchString(request.Plan.InvocationID) ||
		!digestPattern.MatchString(request.InvocationDigest) ||
		!digestPattern.MatchString(request.EnvironmentDigest) ||
		!digestPattern.MatchString(request.Plan.DriverDigest) ||
		!digestPattern.MatchString(request.Plan.InputDigest) ||
		!digestPattern.MatchString(request.RequestDigest) ||
		!executablePattern.MatchString(request.Plan.Executable) ||
		request.WallSeconds <= 0 || request.OutputLimitBytes < 4096 ||
		request.OutputLimitBytes > frameLimit || len(request.Plan.Recipe) != 0 ||
		(request.Plan.WorkingDir != "." && !validRelative(request.Plan.WorkingDir)) {
		return false
	}
	if request.Workspace.Target != filepath.Join(guestRunRoot, "workspace") ||
		request.ArtifactTarget != filepath.Join(guestRunRoot, "artifacts") ||
		request.Workspace.Readonly || request.Workspace.RootIsFile {
		return false
	}
	seenAssets := make(map[string]bool)
	for _, asset := range request.Assets {
		if !identifierPattern.MatchString(asset.AssetID) || seenAssets[asset.AssetID] ||
			!digestPattern.MatchString(asset.RestrictedDigest) || !asset.Tree.Readonly ||
			asset.Tree.Target != filepath.Join(guestRunRoot, "assets", asset.AssetID) {
			return false
		}
		seenAssets[asset.AssetID] = true
	}
	for _, value := range append(
		append([]string{}, request.Plan.Arguments...),
		request.Plan.Executable,
	) {
		if strings.ContainsAny(value, "\x00\r\n") {
			return false
		}
	}
	seenEnvironment := make(map[string]bool)
	for _, entry := range request.Plan.Environment {
		if !environmentPattern.MatchString(entry.Name) || seenEnvironment[entry.Name] ||
			strings.ContainsAny(entry.Value, "\x00\r\n") {
			return false
		}
		for _, marker := range []string{"AUTH", "CREDENTIAL", "KEY", "LICENSE", "PASS", "SECRET", "TOKEN"} {
			if strings.Contains(entry.Name, marker) {
				return false
			}
		}
		seenEnvironment[entry.Name] = true
	}
	seenOutputs := make(map[string]bool)
	for _, output := range request.Plan.Outputs {
		if !identifierPattern.MatchString(output.LogicalID) || !validRelative(output.Path) ||
			seenOutputs[output.LogicalID] || output.MediaType == "" ||
			(output.ArtifactClass != "diagnostic" && output.ArtifactClass != "evidence") {
			return false
		}
		seenOutputs[output.LogicalID] = true
	}
	_, trusted := trustedExecutable(request.Plan.Executable)
	return trusted
}

func trustedExecutable(name string) (string, bool) {
	for _, directory := range []string{"/usr/local/bin", "/usr/bin", "/bin"} {
		candidate := filepath.Join(directory, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || !filepath.IsAbs(resolved) {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil {
			continue
		}
		metadata, validMetadata := info.Sys().(*syscall.Stat_t)
		if validMetadata && info.Mode().IsRegular() &&
			info.Mode().Perm()&0022 == 0 && info.Mode().Perm()&0111 != 0 && metadata.Uid == 0 {
			return resolved, true
		}
	}
	return "", false
}

func execute(current *invocation) {
	request := current.request
	workingDirectory := request.Workspace.Target
	if request.Plan.WorkingDir != "." {
		workingDirectory = filepath.Join(workingDirectory, request.Plan.WorkingDir)
	}
	executable, trusted := trustedExecutable(request.Plan.Executable)
	if !trusted {
		return
	}
	command := exec.Command(executable, request.Plan.Arguments...)
	command.Args[0] = request.Plan.Executable
	command.Dir = workingDirectory
	command.Env = []string{
		"HOME=" + request.Workspace.Target,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"PWD=" + workingDirectory,
		"TMPDIR=" + request.Workspace.Target + "/.tmp",
		"XDG_CACHE_HOME=" + request.Workspace.Target + "/.cache",
		"XDG_CONFIG_HOME=" + request.Workspace.Target + "/.config",
	}
	for _, entry := range request.Plan.Environment {
		command.Env = append(command.Env, entry.Name+"="+entry.Value)
	}
	limit := request.OutputLimitBytes / 4
	if limit < 4096 {
		limit = 4096
	}
	stdout := &boundedBuffer{limit: limit}
	stderr := &boundedBuffer{limit: limit}
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.SysProcAttr.Credential = &syscall.Credential{Uid: guestUID, Gid: guestGID}

	current.mutex.Lock()
	current.command = command
	cancelledBeforeStart := current.cancelled
	current.mutex.Unlock()

	started := !cancelledBeforeStart && command.Start() == nil
	timedOut := false
	if started {
		done := make(chan error, 1)
		go func() { done <- command.Wait() }()
		timer := time.NewTimer(time.Duration(request.WallSeconds) * time.Second)
		select {
		case <-timer.C:
			timedOut = true
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		case <-done:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
	}

	current.mutex.Lock()
	cancelled := current.cancelled
	current.mutex.Unlock()
	state := "failed"
	exitCode := 1
	failure := "candidate"
	if cancelled {
		state, exitCode, failure = "cancelled", 143, "cancelled"
	} else if timedOut {
		state, exitCode, failure = "timed_out", 137, "timeout"
	} else if started && command.ProcessState.Success() && !stdout.overflow && !stderr.overflow {
		state, exitCode = "completed", 0
		failure = ""
	} else if started {
		exitCode = command.ProcessState.ExitCode()
		if exitCode < 0 || exitCode > 255 {
			exitCode = 1
		}
	}
	result := &resultReply{
		Kind:              "result",
		SchemaVersion:     1,
		InvocationID:      request.Plan.InvocationID,
		InvocationDigest:  request.InvocationDigest,
		RequestDigest:     request.RequestDigest,
		EnvironmentDigest: request.EnvironmentDigest,
		State:             state,
		ExitCode:          exitCode,
		Stdout:            makeBlob(stdout.buffer.Bytes()),
		Stderr:            makeBlob(stderr.buffer.Bytes()),
		Outputs:           []guestOutput{},
	}
	if failure != "" {
		result.Failure = &failure
	}
	if state == "completed" {
		budget := int64(request.OutputLimitBytes - len(stdout.buffer.Bytes()) - len(stderr.buffer.Bytes()))
		for _, declaration := range request.Plan.Outputs {
			output, err := readOutput(request.Workspace.Target, declaration, &budget)
			if err != nil {
				result.State, result.ExitCode = "failed", 1
				candidate := "candidate"
				result.Failure = &candidate
				result.Outputs = []guestOutput{}
				break
			}
			if output != nil {
				result.Outputs = append(result.Outputs, *output)
			}
		}
	}
	current.mutex.Lock()
	current.result = result
	current.mutex.Unlock()
}

func receiveFrame(channel io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(channel, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > frameLimit {
		return nil, errors.New("invalid frame size")
	}
	content := make([]byte, size)
	_, err := io.ReadFull(channel, content)
	return content, err
}

func sendFrame(channel io.Writer, message any) error {
	content, err := json.Marshal(message)
	if err != nil || len(content) == 0 || len(content) > frameLimit {
		return errors.New("reply exceeds its bound")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(content)))
	if _, err = channel.Write(header); err != nil {
		return err
	}
	_, err = channel.Write(content)
	return err
}

func main() {
	_ = os.Chmod(filepath.Dir(channelPath), 0700)
	_ = os.Chmod(channelPath, 0600)
	for _, device := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		_ = os.Chmod(device, 0666)
	}
	channel, err := os.OpenFile(channelPath, os.O_RDWR, 0)
	if err != nil {
		panic("guest control channel unavailable")
	}
	debugLog("control-ready")
	defer channel.Close()
	var current *invocation
	for {
		content, err := receiveFrame(channel)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		debugLog("request-received")
		var envelope requestEnvelope
		if json.Unmarshal(content, &envelope) != nil {
			debugLog("envelope-rejected")
			continue
		}
		switch envelope.Kind {
		case "launch":
			if current != nil {
				debugLog("duplicate-launch-rejected")
				continue
			}
			request, decodeError := decodeLaunch(content)
			if decodeError != nil {
				debugLog("launch-codec-rejected")
				continue
			}
			if !validLaunch(request) {
				debugLog("launch-contract-rejected")
				continue
			}
			budget := int64(request.OutputLimitBytes)
			if materializeTree(request.Workspace, &budget) != nil ||
				!validTarget(request.ArtifactTarget) ||
				prepareTargetParents(request.ArtifactTarget) != nil ||
				os.MkdirAll(request.ArtifactTarget, 0700) != nil {
				debugLog("writable-transfer-rejected")
				continue
			}
			validAssets := true
			for _, asset := range request.Assets {
				if asset.AssetID == "" || !asset.Tree.Readonly || materializeTree(asset.Tree, &budget) != nil {
					validAssets = false
					break
				}
			}
			if !validAssets {
				debugLog("asset-transfer-rejected")
				continue
			}
			for _, directory := range []string{".tmp", ".cache", ".config"} {
				if os.MkdirAll(filepath.Join(request.Workspace.Target, directory), 0700) != nil {
					validAssets = false
				}
			}
			if !validAssets {
				debugLog("workspace-runtime-rejected")
				continue
			}
			if grantWritableTree(request.Workspace.Target) != nil ||
				grantWritableTree(request.ArtifactTarget) != nil {
				debugLog("workspace-ownership-rejected")
				continue
			}
			current = &invocation{request: request}
			go execute(current)
			_ = sendFrame(channel, replyIdentity{
				Kind:             "accepted",
				SchemaVersion:    1,
				InvocationID:     request.Plan.InvocationID,
				InvocationDigest: request.InvocationDigest,
				RequestDigest:    request.RequestDigest,
			})
			debugLog("launch-accepted")
		case "status", "cancel":
			if current == nil {
				continue
			}
			var control controlRequest
			if strictDecode(content, &control) != nil || control.SchemaVersion != 1 ||
				control.InvocationID != current.request.Plan.InvocationID ||
				control.InvocationDigest != current.request.InvocationDigest {
				continue
			}
			current.mutex.Lock()
			if control.Kind == "cancel" && current.result == nil {
				current.cancelled = true
				if current.command != nil && current.command.Process != nil {
					_ = syscall.Kill(-current.command.Process.Pid, syscall.SIGKILL)
				}
			}
			result := current.result
			current.mutex.Unlock()
			if result == nil {
				_ = sendFrame(channel, replyIdentity{
					Kind:             "running",
					SchemaVersion:    1,
					InvocationID:     control.InvocationID,
					InvocationDigest: control.InvocationDigest,
					RequestDigest:    current.request.RequestDigest,
				})
			} else {
				_ = sendFrame(channel, result)
			}
		}
	}
}
