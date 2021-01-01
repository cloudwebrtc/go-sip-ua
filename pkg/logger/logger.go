package logger

import (
	"fmt"
	"os"

	"github.com/rs/zerolog"
)

var logger zerolog.Logger

const (
	timeFormat = "2006-01-02 15:04:05.999"
)

func Init(level string) {
	l := zerolog.GlobalLevel()
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	}
	zerolog.TimeFieldFormat = timeFormat
	output := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: timeFormat}
	logger = zerolog.New(output).Level(l).With().Timestamp().Logger()
}

func Info(v ...interface{}) {
	logger.Info().Msg(fmt.Sprint(v...))
}

func Infof(format string, v ...interface{}) {
	logger.Info().Msgf(format, v...)
}

func Debug(v ...interface{}) {
	logger.Debug().Msg(fmt.Sprint(v...))
}

func Debugf(format string, v ...interface{}) {
	logger.Debug().Msgf(format, v...)
}

func Warn(v ...interface{}) {
	logger.Warn().Msg(fmt.Sprint(v...))
}

func Warnf(format string, v ...interface{}) {
	logger.Warn().Msgf(format, v...)
}

func Error(v ...interface{}) {
	logger.Error().Msg(fmt.Sprint(v...))
}

func Errorf(format string, v ...interface{}) {
	logger.Error().Msgf(format, v...)
}

func Panic(v ...interface{}) {
	logger.Panic().Msg(fmt.Sprint(v...))
}

func Panicf(format string, v ...interface{}) {
	logger.Panic().Msgf(format, v...)
}
