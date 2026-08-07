package goauth

import (
	"errors"
	"strings"
)

var ErrNoDatabase = errors.New("go-auth: no database pool or DSN provided")

func SplitSQL(sql string) []string {
	var statements []string
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if inQuote {
			b.WriteByte(c)
			if c == '\'' && i+1 < len(sql) && sql[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			if c == '\'' {
				inQuote = false
			}
			continue
		}
		if c == '\'' {
			inQuote = true
			b.WriteByte(c)
			continue
		}
		if c == ';' {
			trimmed := strings.TrimSpace(b.String())
			if trimmed != "" && !strings.HasPrefix(trimmed, "--") {
				statements = append(statements, trimmed)
			}
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	trimmed := strings.TrimSpace(b.String())
	if trimmed != "" && !strings.HasPrefix(trimmed, "--") {
		statements = append(statements, trimmed)
	}
	return statements
}
