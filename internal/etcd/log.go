package etcd

import (
	"context"
	"log/slog"
	"sync/atomic"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// slogCore forwards etcd's zap logs at warning level and above to slog.
// Once the member is closing it drops everything: etcd reports its own
// listeners shutting down as errors.
type slogCore struct {
	log     *slog.Logger
	fields  []zapcore.Field
	closing *atomic.Bool
}

// benign are warnings etcd prints on every start that do not apply here:
// the client port serves only gRPC (the HTTP gateway is off and nothing else
// is exposed on it), and etcd's own authentication, whose tokens the second
// one is about, is not used: clients are authenticated by certificate.
var benign = map[string]bool{
	"Running http and grpc server on single port. This is not recommended for production.": true,
	"simple token is not cryptographically signed":                                         true,
}

func newZapLogger(log *slog.Logger, closing *atomic.Bool) *zap.Logger {
	return zap.New(&slogCore{log: log.With("component", "etcd"), closing: closing})
}

func (c *slogCore) Enabled(l zapcore.Level) bool {
	return l >= zapcore.WarnLevel && !c.closing.Load()
}

func (c *slogCore) With(fs []zapcore.Field) zapcore.Core {
	return &slogCore{log: c.log, fields: append(append([]zapcore.Field(nil), c.fields...), fs...), closing: c.closing}
}

func (c *slogCore) Check(e zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(e.Level) && !benign[e.Message] {
		return ce.AddCore(e, c)
	}
	return ce
}

func (c *slogCore) Write(e zapcore.Entry, fs []zapcore.Field) error {
	enc := zapcore.NewMapObjectEncoder()
	for _, f := range append(append([]zapcore.Field(nil), c.fields...), fs...) {
		f.AddTo(enc)
	}
	attrs := make([]any, 0, 2*len(enc.Fields))
	for k, v := range enc.Fields {
		attrs = append(attrs, k, v)
	}
	level := slog.LevelWarn
	if e.Level >= zapcore.ErrorLevel {
		level = slog.LevelError
	}
	c.log.Log(context.Background(), level, e.Message, attrs...)
	return nil
}

func (c *slogCore) Sync() error { return nil }
