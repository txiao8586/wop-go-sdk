package config

import "fmt"

// Error 表示配置加载/校验错误（调用方应映射为 wop.CodeConfiguration）。
type Error struct {
	Message string
}

func (e *Error) Error() string { return e.Message }

func configErr(format string, args ...any) *Error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}
