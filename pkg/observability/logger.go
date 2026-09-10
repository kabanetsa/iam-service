// Package observability wires structured logging, Prometheus metrics and health
// probes for the service.
package observability

import (
	"os"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger builds the process logger: JSON in production, human-readable
// console output in development, always on stdout.
func NewLogger(environment, level string) (*zap.Logger, error) {
	lvl := zapcore.InfoLevel
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		lvl = zapcore.DebugLevel
	case "warn", "warning":
		lvl = zapcore.WarnLevel
	case "error":
		lvl = zapcore.ErrorLevel
	case "", "info":
		lvl = zapcore.InfoLevel
	}

	var cfg zap.Config
	if environment == "development" || environment == "test" {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "ts"
		cfg.EncoderConfig.EncodeTime = zapcore.EpochTimeEncoder
	}
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.OutputPaths = []string{"stdout"}
	cfg.ErrorOutputPaths = []string{"stderr"}

	logger, err := cfg.Build(zap.AddStacktrace(zapcore.ErrorLevel))
	if err != nil {
		return nil, err
	}
	return logger.With(zap.String("service", "iam-service")), nil
}

// Sync flushes buffered log entries; it is safe to call on shutdown.
func Sync(logger *zap.Logger) {
	if logger == nil {
		return
	}
	// stdout may legitimately refuse syncing (e.g. when redirected to a file).
	_ = logger.Sync()
	_ = os.Stderr.Sync()
}
