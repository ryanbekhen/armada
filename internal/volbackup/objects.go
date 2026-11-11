package volbackup

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// Object is one listed object.
type Object struct {
	Key      string
	Size     int64
	Modified time.Time
}

// Objects is the bucket a repository lives in.
type Objects interface {
	Put(ctx context.Context, key string, data []byte) error
	// Get returns ErrNotExist for a missing object and refuses objects
	// larger than max.
	Get(ctx context.Context, key string, max int64) ([]byte, error)
	List(ctx context.Context, prefix string, fn func(Object) error) error
	Delete(ctx context.Context, key string) error
}

// ErrNotExist is returned by Get for a missing object.
var ErrNotExist = errors.New("object does not exist")

// requestTimeout bounds one request to the bucket.
const requestTimeout = 5 * time.Minute

// S3 opens the bucket of t.
func S3(t Target) (Objects, error) {
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       90 * time.Second,
	}
	c, err := minio.New(t.Endpoint, &minio.Options{
		Creds:        credentials.NewStaticV4(t.AccessKey, t.SecretKey, ""),
		Secure:       t.Secure,
		Region:       t.Region,
		BucketLookup: minio.BucketLookupPath,
		Transport:    tr,
		MaxRetries:   3,
	})
	if err != nil {
		return nil, errTarget("cannot use the endpoint")
	}
	return &s3Objects{c: c, bucket: t.Bucket}, nil
}

type s3Objects struct {
	c      *minio.Client
	bucket string
}

// bucketErr keeps what the bucket answered without request URLs.
func bucketErr(op string, err error) error {
	if r := minio.ToErrorResponse(err); r.Code != "" {
		return fmt.Errorf("bucket: %s: %s (HTTP %d)", op, r.Code, r.StatusCode)
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return fmt.Errorf("bucket: %s: %w", op, err)
}

func (s *s3Objects) Put(ctx context.Context, key string, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	_, err := s.c.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType:      "application/octet-stream",
		DisableMultipart: true,
		SendContentMd5:   true,
	})
	if err != nil {
		return bucketErr("write", err)
	}
	return nil
}

func (s *s3Objects) Get(ctx context.Context, key string, max int64) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	o, err := s.c.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, bucketErr("read", err)
	}
	defer o.Close()
	b, err := io.ReadAll(io.LimitReader(o, max+1))
	if err != nil {
		if minio.ToErrorResponse(err).Code == "NoSuchKey" {
			return nil, ErrNotExist
		}
		return nil, bucketErr("read", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("bucket: object larger than %d bytes", max)
	}
	return b, nil
}

func (s *s3Objects) List(ctx context.Context, prefix string, fn func(Object) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for o := range s.c.ListObjects(ctx, s.bucket, minio.ListObjectsOptions{Prefix: prefix, Recursive: true}) {
		if o.Err != nil {
			return bucketErr("list", o.Err)
		}
		if err := fn(Object{Key: o.Key, Size: o.Size, Modified: o.LastModified}); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *s3Objects) Delete(ctx context.Context, key string) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	if err := s.c.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return bucketErr("delete", err)
	}
	return nil
}

// Memory is a bucket in memory, for tests.
type Memory struct {
	mu   sync.Mutex
	objs map[string]memObject
	// Now, if set, dates objects.
	Now func() time.Time
	// FailPut, if set, fails writes of keys it returns true for.
	FailPut func(key string) bool
}

type memObject struct {
	data []byte
	mod  time.Time
}

// NewMemory returns an empty bucket.
func NewMemory() *Memory { return &Memory{objs: map[string]memObject{}} }

// Put stores an object.
func (m *Memory) Put(_ context.Context, key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailPut != nil && m.FailPut(key) {
		return errors.New("bucket: write: refused")
	}
	now := time.Now()
	if m.Now != nil {
		now = m.Now()
	}
	m.objs[key] = memObject{data: slices.Clone(data), mod: now}
	return nil
}

// Get reads an object.
func (m *Memory) Get(_ context.Context, key string, max int64) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objs[key]
	if !ok {
		return nil, ErrNotExist
	}
	if int64(len(o.data)) > max {
		return nil, fmt.Errorf("bucket: object larger than %d bytes", max)
	}
	return slices.Clone(o.data), nil
}

// List calls fn for each object under prefix, in key order.
func (m *Memory) List(_ context.Context, prefix string, fn func(Object) error) error {
	m.mu.Lock()
	var out []Object
	for k, o := range m.objs {
		if strings.HasPrefix(k, prefix) {
			out = append(out, Object{Key: k, Size: int64(len(o.data)), Modified: o.mod})
		}
	}
	m.mu.Unlock()
	slices.SortFunc(out, func(a, b Object) int { return strings.Compare(a.Key, b.Key) })
	for _, o := range out {
		if err := fn(o); err != nil {
			return err
		}
	}
	return nil
}

// Delete removes an object.
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objs, key)
	return nil
}

// Keys lists every object's key, sorted.
func (m *Memory) Keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.objs {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// Set replaces an object's bytes, for tests that damage a repository.
func (m *Memory) Set(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.objs[key]
	o.data = data
	m.objs[key] = o
}
