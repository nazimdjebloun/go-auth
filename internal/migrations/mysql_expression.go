package migrations

import (
	"fmt"
	"strings"
)

func mysqlCheckExpression(check string) (string, error) {
	sql, err := mysqlMetadataSQL(check)
	if err != nil {
		return "", err
	}
	return parseExpression(sql, true)
}

// CHECK_CLAUSE and expression defaults escape printed SQL's quotes and
// backslashes once more for metadata storage. Decode that layer first.
func mysqlMetadataSQL(value string) (string, error) {
	var sql strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' {
			i++
			if i == len(value) || (value[i] != '\\' && value[i] != '\'') {
				return "", fmt.Errorf("unsupported MySQL expression metadata escape")
			}
		}
		sql.WriteByte(value[i])
	}
	return sql.String(), nil
}

// Convert MySQL backslash escapes to literal values and SQL-standard quoting.
// The common expression tokenizer can then preserve literal case and contents.
func mysqlLiterals(sql string) (string, error) {
	var normalized strings.Builder
	for i := 0; i < len(sql); i++ {
		if sql[i] != '\'' {
			normalized.WriteByte(sql[i])
			continue
		}
		var literal strings.Builder
		closed := false
		for i++; i < len(sql); i++ {
			switch sql[i] {
			case '\\':
				i++
				if i == len(sql) {
					return "", fmt.Errorf("unfinished MySQL string escape")
				}
				switch sql[i] {
				case '\\', '\'', '"':
					literal.WriteByte(sql[i])
				case '0':
					literal.WriteByte(0)
				case 'b':
					literal.WriteByte('\b')
				case 'n':
					literal.WriteByte('\n')
				case 'r':
					literal.WriteByte('\r')
				case 't':
					literal.WriteByte('\t')
				case 'Z':
					literal.WriteByte(26)
				default:
					return "", fmt.Errorf("unsupported MySQL string escape")
				}
			case '\'':
				if i+1 < len(sql) && sql[i+1] == '\'' {
					literal.WriteByte('\'')
					i++
					continue
				}
				closed = true
			default:
				literal.WriteByte(sql[i])
			}
			if closed {
				break
			}
		}
		if !closed {
			return "", fmt.Errorf("unterminated MySQL string literal")
		}
		normalized.WriteByte('\'')
		normalized.WriteString(strings.ReplaceAll(literal.String(), "'", "''"))
		normalized.WriteByte('\'')
	}
	return normalized.String(), nil
}
