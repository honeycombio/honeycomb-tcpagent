package logging

import "github.com/Sirupsen/logrus"

type Logger struct {
	wrappedLogger *logrus.Entry
	level         logrus.Level
}

func NewLogger(fields logrus.Fields) *Logger {
	l := &Logger{
		wrappedLogger: logrus.WithFields(fields),
	}
	l.level = logrus.GetLevel()
	return l
}

func (l *Logger) WithFields(fields logrus.Fields) *Logger {
	return &Logger{
		wrappedLogger: l.wrappedLogger.WithFields(fields),
		level:         l.level,
	}
}

func (l *Logger) Debug(message string, fields logrus.Fields) {
	if l.level < logrus.DebugLevel {
		return
	}
	l.wrappedLogger.WithFields(fields).Debug(message)
}

func (l *Logger) Info(message string, fields logrus.Fields) {
	if l.level < logrus.InfoLevel {
		return
	}
	l.wrappedLogger.WithFields(fields).Info(message)
}

func (l *Logger) Warn(message string, fields logrus.Fields) {
	if l.level < logrus.WarnLevel {
		return
	}
	l.wrappedLogger.WithFields(fields).Warn(message)
}

func (l *Logger) Error(message string, fields logrus.Fields) {
	if l.level < logrus.ErrorLevel {
		return
	}
	l.wrappedLogger.WithFields(fields).Error(message)
}
