package config

import "fmt"

// Error 表示配置加载/校验错误（调用方应映射为 wop.CodeConfiguration）。
type Error struct {
	Message string
}

// Error 返回配置错误消息（商户可读，映射 wop.CodeConfiguration）。
func (e *Error) Error() string { return e.Message }

// configErr 构造配置错误（格式化消息）。
func configErr(format string, args ...any) *Error {
	return &Error{Message: fmt.Sprintf(format, args...)}
}
