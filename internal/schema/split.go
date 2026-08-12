// Package schema holds the embedded SQL schemas and the SQL statement
// splitter used by the CLI migrate command.
package schema

import "strings"

// SplitSQL splits a semicolon-delimited SQL script into individual
// statements. Single-quoted strings are respected (a semicolon inside a
// quoted string does not split), and lines starting with -- are dropped.
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
