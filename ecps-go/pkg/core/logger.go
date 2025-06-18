package core

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// LogLevel represents the severity level of a log message.
type LogLevel int

const (
	// DebugLevel logs detailed information for debugging.
	DebugLevel LogLevel = iota
	// InfoLevel logs general operational information.
	InfoLevel
	// WarnLevel logs potentially harmful situations.
	WarnLevel
	// ErrorLevel logs error events that might still allow the application to continue.
	ErrorLevel
	// FatalLevel logs severe error events that will lead the application to abort.
	FatalLevel
)

func (l LogLevel) String() string {
	switch l {
	case DebugLevel:
		return "DEBUG"
	case InfoLevel:
		return "INFO"
	case WarnLevel:
		return "WARN"
	case ErrorLevel:
		return "ERROR"
	case FatalLevel:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger is the interface for logging within the ECPS Go SDK.
type Logger interface {
	// Debug logs a message at debug level.
	Debug(format string, args ...interface{})
	// Info logs a message at info level.
	Info(format string, args ...interface{})
	// Warn logs a message at warn level.
	Warn(format string, args ...interface{})
	// Error logs a message at error level.
	Error(format string, args ...interface{})
	// Fatal logs a message at fatal level and exits.
	Fatal(format string, args ...interface{})
	// WithField adds a field to the logger.
	WithField(key string, value interface{}) Logger
	// WithFields adds multiple fields to the logger.
	WithFields(fields map[string]interface{}) Logger
	// WithError adds an error to the logger.
	WithError(err error) Logger
}

// DefaultLogger is a simple logger implementation.
type DefaultLogger struct {
	level  LogLevel
	fields map[string]interface{}
	logger *log.Logger
}

// NewDefaultLogger creates a new default logger.
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		level:  InfoLevel,
		fields: make(map[string]interface{}),
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// SetLevel sets the log level.
func (l *DefaultLogger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a message at debug level.
func (l *DefaultLogger) Debug(format string, args ...interface{}) {
	if l.level <= DebugLevel {
		l.log(DebugLevel, format, args...)
	}
}

// Info logs a message at info level.
func (l *DefaultLogger) Info(format string, args ...interface{}) {
	if l.level <= InfoLevel {
		l.log(InfoLevel, format, args...)
	}
}

// Warn logs a message at warn level.
func (l *DefaultLogger) Warn(format string, args ...interface{}) {
	if l.level <= WarnLevel {
		l.log(WarnLevel, format, args...)
	}
}

// Error logs a message at error level.
func (l *DefaultLogger) Error(format string, args ...interface{}) {
	if l.level <= ErrorLevel {
		l.log(ErrorLevel, format, args...)
	}
}

// Fatal logs a message at fatal level and exits.
func (l *DefaultLogger) Fatal(format string, args ...interface{}) {
	if l.level <= FatalLevel {
		l.log(FatalLevel, format, args...)
		os.Exit(1)
	}
}

// WithField adds a field to the logger.
func (l *DefaultLogger) WithField(key string, value interface{}) Logger {
	newLogger := &DefaultLogger{
		level:  l.level,
		fields: make(map[string]interface{}),
		logger: l.logger,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new field
	newLogger.fields[key] = value
	return newLogger
}

// WithFields adds multiple fields to the logger.
func (l *DefaultLogger) WithFields(fields map[string]interface{}) Logger {
	newLogger := &DefaultLogger{
		level:  l.level,
		fields: make(map[string]interface{}),
		logger: l.logger,
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}

	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}
	return newLogger
}

// WithError adds an error to the logger.
func (l *DefaultLogger) WithError(err error) Logger {
	return l.WithField("error", err.Error())
}

// log writes a log message with the given level and fields.
func (l *DefaultLogger) log(level LogLevel, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	
	var fieldsStr string
	if len(l.fields) > 0 {
		var parts []string
		for k, v := range l.fields {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		fieldsStr = " [" + strings.Join(parts, ", ") + "]"
	}
	
	l.logger.Printf("[%s]%s %s", level, fieldsStr, message)
}