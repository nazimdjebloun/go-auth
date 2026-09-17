// Package schema holds the embedded SQL schemas and the SQL statement
// splitter used by the CLI migrate command.
package schema

import "strings"

// SplitSQL splits a semicolon-delimited SQL script into individual
// statements. Single-quoted strings are respected (a semicolon inside a
// quoted string does not split), and `--` comments are stripped lexically —
// only when not inside a quoted string — so SQL following a comment on the
// same segment is preserved and a semicolon inside a comment can never be
// mistaken for a statement boundary. (An earlier version discarded any
// segment that started with `--`, silently dropping real DDL that followed
// the comment — see the regression tests.)
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
		if c == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			// Comment runs to end of line; drop it without terminating the
			// current statement.
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			// Preserve the newline as a token boundary (SELECT--comment\n1
			// must not become SELECT1).
			b.WriteByte('\n')
			continue
		}
		if c == ';' {
			trimmed := strings.TrimSpace(b.String())
			if trimmed != "" {
				statements = append(statements, trimmed)
			}
			b.Reset()
			continue
		}
		b.WriteByte(c)
	}
	trimmed := strings.TrimSpace(b.String())
	if trimmed != "" {
		statements = append(statements, trimmed)
	}
	return statements
}
