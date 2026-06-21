package goauth

import (
	"errors"
	"strings"
)

var ErrNoDatabase = errors.New("go-auth: no database pool or DSN provided")

func SplitSQL(sql string) []string {
	statements := strings.Split(sql, ";")
	result := make([]string, 0, len(statements))
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}
