package main

import "fmt"

const (
	ExitCodeSuccess       = 0
	ExitCodeFindingsFound = 1
	ExitCodeError         = 2
)

type CLIError struct {
	Code    int
	Message string
}

func (e *CLIError) Error() string {
	return e.Message
}

func NewCLIError(code int, message string) *CLIError {
	return &CLIError{Code: code, Message: message}
}

func NewCLIErrorf(code int, format string, args ...interface{}) *CLIError {
	return &CLIError{Code: code, Message: fmt.Sprintf(format, args...)}
}
