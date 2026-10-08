package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/delegation"
	"github.com/golang/glog"
)

const completionMaxRecords = 256
const completionMaxBytes = 4 << 20
const completionMaxRecordBytes = 32 << 10
const completionMaxAge = 7 * 24 * 3600

var completionName = regexp.MustCompile(`^terminal-[a-f0-9]{64}\.json$`)
var completionRegistry = struct {
	sync.Mutex
	queues map[string]*completionSpool
}{queues: make(map[string]*completionSpool)}

// This private spool is not an audit log: only short signed tickets and stable
// terminal metadata live here. Agent/API Key secrets are never serialized.
type completionRecord struct {
	Version     int    `json:"version"`
	Token       string `json:"token"`
	State       string `json:"state"`
	Outcome     string `json:"outcome"`
	FailureCode string `json:"failureCode,omitempty"`
	ExpiresAt   int64  `json:"expiresAt"`
}
type completionSpool struct {
	mu                   sync.Mutex
	dir                  string
	now                  func() time.Time
	maxRecords, maxBytes int
	replayCursor         string
}

func receiptExpiry(envelope map[string]interface{}) int64 {
	issued, ok := delegation.Integer(envelope["issuedAt"])
	if !ok || issued <= 0 || issued > time.Now().Unix()+30 {
		return 0
	}
	return issued + completionMaxAge
}
func completionID(token string) string {
	sum := sha256.Sum256([]byte("apiKey-stream-terminal-v1|" + token))
	return hex.EncodeToString(sum[:])
}
func (a *StreamAudit) record(state string) completionRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return completionRecord{1, a.token, state, a.outcome, a.failureCode, a.expiresAt}
}
func configuredCompletionSpool() (*completionSpool, error) {
	dir := config.Config.CompletionSpoolDir
	if dir == "" {
		root := ""
		for _, name := range []string{"PASTURESTACK_STATE_DIR", "CATTLE_STATE_DIR", "PASTURESTACK_HOME", "CATTLE_HOME"} {
			if value := os.Getenv(name); value != "" {
				root = value
				break
			}
		}
		if root == "" {
			root = "/var/lib/pasturestack"
		}
		dir = filepath.Join(root, "host-api", "completion-spool")
	}
	if !filepath.IsAbs(dir) {
		return nil, errors.New("completion spool must be absolute")
	}
	completionRegistry.Lock()
	defer completionRegistry.Unlock()
	if queue := completionRegistry.queues[dir]; queue != nil {
		return queue, nil
	}
	queue, err := openCompletionSpool(dir)
	if err == nil {
		completionRegistry.queues[dir] = queue
	}
	return queue, err
}
func openCompletionSpool(dir string) (*completionSpool, error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) || filepath.Base(dir) != "completion-spool" {
		return nil, errors.New("completion spool must be an absolute dedicated completion-spool directory")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		ancestor, err := os.Lstat(current)
		if err != nil || ancestor.Mode()&os.ModeSymlink != 0 || !completionTrustedAncestor(ancestor) {
			return nil, errors.New("unsafe completion spool ancestor")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !completionOwnedByProcess(info) {
		return nil, errors.New("unsafe completion spool directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	return &completionSpool{dir: dir, now: time.Now, maxRecords: completionMaxRecords, maxBytes: completionMaxBytes}, nil
}
func (q *completionSpool) path(id string) string { return filepath.Join(q.dir, "terminal-"+id+".json") }
func (q *completionSpool) read(path string) (completionRecord, int, error) {
	var record completionRecord
	info, err := os.Lstat(path)
	if err != nil {
		return record, 0, err
	}
	if !info.Mode().IsRegular() || !completionOwnedByProcess(info) || (runtime.GOOS != "windows" && info.Mode().Perm() != 0600) || info.Size() > completionMaxRecordBytes {
		return record, 0, errors.New("unsafe completion evidence file")
	}
	file, err := os.Open(path)
	if err != nil {
		return record, 0, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, completionMaxRecordBytes+1))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, 0, err
	}
	if decoder.Decode(new(interface{})) != io.EOF {
		return record, 0, errors.New("invalid completion evidence suffix")
	}
	if record.Version != 1 || len(record.Token) == 0 || len(record.Token) > delegation.MaxTokenBytes || (record.State != "PENDING" && record.State != "TERMINAL") || record.ExpiresAt <= 0 || record.ExpiresAt > q.now().Unix()+completionMaxAge+30 || filepath.Base(path) != "terminal-"+completionID(record.Token)+".json" {
		return record, 0, errors.New("invalid completion evidence")
	}
	return record, int(info.Size()), nil
}
func (q *completionSpool) syncDirectory() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (q *completionSpool) write(record completionRecord) error {
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > completionMaxRecordBytes {
		return errors.New("completion evidence too large")
	}
	file, err := os.CreateTemp(q.dir, ".terminal-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(encoded)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(name, q.path(completionID(record.Token))); err != nil {
		return err
	}
	return q.syncDirectory()
}
func (q *completionSpool) capacity(extra completionRecord) error {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	count, size := 0, 0
	for _, entry := range entries {
		if !completionName.MatchString(entry.Name()) {
			continue
		}
		record, _, err := q.read(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			return err
		}
		if record.ExpiresAt <= q.now().Unix() {
			if err := os.Remove(filepath.Join(q.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		count++
		size += completionMaxRecordBytes // Reserve terminal-write space before execution.
	}
	if count >= q.maxRecords || size+completionMaxRecordBytes > q.maxBytes {
		return errors.New("completion evidence capacity reached")
	}
	return nil
}
func (q *completionSpool) reserve(record completionRecord) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if record.ExpiresAt <= q.now().Unix() {
		return errors.New("expired completion evidence")
	}
	if _, _, err := q.read(q.path(completionID(record.Token))); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := q.capacity(record); err != nil {
		return err
	}
	return q.write(record)
}
func (q *completionSpool) complete(record completionRecord) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if record.ExpiresAt <= q.now().Unix() {
		return errors.New("expired completion evidence")
	}
	existing, _, err := q.read(q.path(completionID(record.Token)))
	if err == nil && existing.State == "TERMINAL" {
		return nil
	} // First terminal result is immutable.
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if os.IsNotExist(err) {
		if err := q.capacity(record); err != nil {
			return err
		}
	}
	return q.write(record)
}
func (q *completionSpool) deliverOne(ctx context.Context, id string) bool {
	q.mu.Lock()
	record, _, err := q.read(q.path(id))
	q.mu.Unlock()
	if err != nil || record.State != "TERMINAL" {
		return false
	}
	if record.ExpiresAt <= q.now().Unix() {
		q.mu.Lock()
		os.Remove(q.path(id))
		q.syncDirectory()
		q.mu.Unlock()
		return false
	}
	audit := BeginStreamAudit(record.Token) // Current trusted endpoint/agent credentials, never stored ones.
	if !audit.enabled {
		return false
	}
	audit.outcome, audit.failureCode = record.Outcome, record.FailureCode
	if !audit.deliver(ctx) {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := os.Remove(q.path(id)); err != nil && !os.IsNotExist(err) {
		return false
	}
	return q.syncDirectory() == nil
}
func (q *completionSpool) recoverPending() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".terminal-") {
			info, err := os.Lstat(filepath.Join(q.dir, entry.Name()))
			if err != nil || !info.Mode().IsRegular() || info.Size() > completionMaxRecordBytes {
				return errors.New("unsafe incomplete completion file")
			}
			if err := os.Remove(filepath.Join(q.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if !completionName.MatchString(entry.Name()) {
			continue
		}
		record, _, err := q.read(filepath.Join(q.dir, entry.Name()))
		if err != nil {
			return err
		}
		if record.ExpiresAt <= q.now().Unix() {
			if err := os.Remove(filepath.Join(q.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		if record.State == "PENDING" {
			record.State = "TERMINAL"
			record.Outcome = "CANCELLED"
			record.FailureCode = "StreamCancelled"
			if err := q.write(record); err != nil {
				return err
			}
		}
	}
	return q.syncDirectory()
}
func (q *completionSpool) replayOnce(ctx context.Context) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return
	}
	q.mu.Lock()
	cursor := q.replayCursor
	q.mu.Unlock()
	ordered := append([]os.DirEntry{}, entries...)
	for i, entry := range entries {
		if entry.Name() > cursor {
			ordered = append(append([]os.DirEntry{}, entries[i:]...), entries[:i]...)
			break
		}
	}
	count := 0
	for _, entry := range ordered {
		if !completionName.MatchString(entry.Name()) {
			continue
		}
		if ctx.Err() != nil || count >= 16 {
			return
		}
		count++
		q.mu.Lock()
		q.replayCursor = entry.Name()
		q.mu.Unlock()
		attempt, cancel := context.WithTimeout(ctx, 7*time.Second)
		q.deliverOne(attempt, entry.Name()[len("terminal-"):len("terminal-")+64])
		cancel()
	}
}

// Call once at process startup. Recovery records interruption, never reruns work.
func StartCompletionReplay(parent context.Context) context.CancelFunc {
	ctx, cancel := context.WithCancel(parent)
	queue, err := configuredCompletionSpool()
	if err != nil || queue.recoverPending() != nil {
		glog.Warning("API key completion replay is unavailable")
		return cancel
	}
	go func() {
		queue.replayOnce(ctx)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				queue.replayOnce(ctx)
			}
		}
	}()
	return cancel
}
