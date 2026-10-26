package rpc

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/grpclog"
)

// ConfigureFrameworkLogger is called once by a process entry point before
// creating any gRPC servers or clients. It does not replace business loggers.
func ConfigureFrameworkLogger(log *slog.Logger) {
	grpclog.SetLoggerV2(frameworkLogger{log: log.With("component", "grpc")})
}

type frameworkLogger struct{ log *slog.Logger }

var _ grpclog.LoggerV2 = frameworkLogger{}

func (l frameworkLogger) V(level int) bool {
	return level <= 0 || l.log.Enabled(context.Background(), slog.LevelDebug)
}
func (l frameworkLogger) Info(values ...any) {
	l.log.Log(context.Background(), slog.LevelInfo, fmt.Sprint(values...))
}
func (l frameworkLogger) Infoln(values ...any) {
	l.log.Log(context.Background(), slog.LevelInfo, strings.TrimSuffix(fmt.Sprintln(values...), "\n"))
}
func (l frameworkLogger) Infof(format string, values ...any) {
	l.log.Log(context.Background(), slog.LevelInfo, fmt.Sprintf(format, values...))
}
func (l frameworkLogger) Warning(values ...any) {
	l.log.Log(context.Background(), slog.LevelWarn, fmt.Sprint(values...))
}
func (l frameworkLogger) Warningln(values ...any) {
	l.log.Log(context.Background(), slog.LevelWarn, strings.TrimSuffix(fmt.Sprintln(values...), "\n"))
}
func (l frameworkLogger) Warningf(format string, values ...any) {
	l.log.Log(context.Background(), slog.LevelWarn, fmt.Sprintf(format, values...))
}
func (l frameworkLogger) Error(values ...any) {
	l.log.Log(context.Background(), slog.LevelError, fmt.Sprint(values...))
}
func (l frameworkLogger) Errorln(values ...any) {
	l.log.Log(context.Background(), slog.LevelError, strings.TrimSuffix(fmt.Sprintln(values...), "\n"))
}
func (l frameworkLogger) Errorf(format string, values ...any) {
	l.log.Log(context.Background(), slog.LevelError, fmt.Sprintf(format, values...))
}
func (l frameworkLogger) Fatal(values ...any) {
	l.log.Log(context.Background(), slog.LevelError, fmt.Sprint(values...))
}
func (l frameworkLogger) Fatalln(values ...any) {
	l.log.Log(context.Background(), slog.LevelError, strings.TrimSuffix(fmt.Sprintln(values...), "\n"))
}
func (l frameworkLogger) Fatalf(format string, values ...any) {
	l.log.Log(context.Background(), slog.LevelError, fmt.Sprintf(format, values...))
}
