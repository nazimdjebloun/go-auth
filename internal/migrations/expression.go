package migrations

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// Normalization preserves boolean precedence and literal case. Removing all
// parentheses would incorrectly accept different CHECK constraints.
func expression(sql string) (string, error) {
	tokens, err := tokenize(sql)
	if err != nil {
		return "", err
	}
	p := expressionParser{tokens: tokens}
	value, err := p.parse(0)
	if err != nil {
		return "", err
	}
	if p.pos != len(p.tokens) {
		return "", fmt.Errorf("unsupported verification expression near %q", p.tokens[p.pos])
	}
	return value, nil
}

func tokenize(sql string) ([]string, error) {
	tokens := []string{}
	for i := 0; i < len(sql); {
		c := sql[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if c == '-' && i+1 < len(sql) && sql[i+1] == '-' {
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			start, quote := i, c
			i++
			closed := false
			for i < len(sql) {
				if sql[i] == quote {
					if i+1 < len(sql) && sql[i+1] == quote {
						i += 2
						continue
					}
					i++
					closed = true
					break
				}
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated quoted verification token")
			}
			value := sql[start:i]
			if quote != '\'' {
				value = strings.ToLower(value[1 : len(value)-1])
			}
			tokens = append(tokens, value)
			continue
		}
		if strings.ContainsRune("(),[]=<>!;:", rune(c)) {
			end := i + 1
			if end < len(sql) {
				switch sql[i : end+1] {
				case "<=", ">=", "<>", "!=", "::":
					end++
				}
			}
			tokens = append(tokens, sql[i:end])
			i = end
			continue
		}
		start := i
		for i < len(sql) && !unicode.IsSpace(rune(sql[i])) && !strings.ContainsRune("(),[]=<>!;:'\"`", rune(sql[i])) {
			i++
		}
		if start == i {
			return nil, fmt.Errorf("unsupported verification token")
		}
		token := strings.ToLower(sql[start:i])
		if token == "_utf8mb4" || token == "_utf8mb3" {
			continue // MySQL's explicit introducer for string literals.
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

type expressionParser struct {
	tokens []string
	pos    int
}

func (p *expressionParser) take(token string) bool {
	if p.pos < len(p.tokens) && p.tokens[p.pos] == token {
		p.pos++
		return true
	}
	return false
}

func (p *expressionParser) parse(minimum int) (string, error) {
	left, err := p.atom()
	if err != nil {
		return "", err
	}
	for p.pos < len(p.tokens) {
		op := p.tokens[p.pos]
		precedence := 0
		switch op {
		case "or":
			precedence = 1
		case "and":
			precedence = 2
		case "=", ">", "<", ">=", "<=", "!=", "<>", "is", "in":
			precedence = 3
		}
		if precedence == 0 || precedence < minimum {
			break
		}
		p.pos++
		if op == "is" {
			negated := p.take("not")
			if !p.take("null") {
				return "", fmt.Errorf("only IS [NOT] NULL is supported")
			}
			left = fmt.Sprintf("isnull(%s,%t)", left, negated)
			continue
		}
		if op == "in" {
			if !p.take("(") {
				return "", fmt.Errorf("IN requires a value list")
			}
			items, err := p.list(")")
			if err != nil {
				return "", err
			}
			left = "in(" + left + "," + strings.Join(items, ",") + ")"
			continue
		}
		right, err := p.parse(precedence + 1)
		if err != nil {
			return "", err
		}
		if op == "=" && strings.HasPrefix(right, "any(array(") && strings.HasSuffix(right, "))") {
			left = "in(" + left + "," + right[len("any(array("):len(right)-2] + ")"
			continue
		}
		if op == "<>" {
			op = "!="
		}
		left = op + "(" + left + "," + right + ")"
	}
	return left, nil
}

func (p *expressionParser) atom() (string, error) {
	if p.pos == len(p.tokens) {
		return "", fmt.Errorf("missing verification expression")
	}
	if p.take("not") {
		value, err := p.parse(3)
		return "not(" + value + ")", err
	}
	var value string
	if p.take("(") {
		var err error
		value, err = p.parse(0)
		if err != nil {
			return "", err
		}
		if !p.take(")") {
			return "", fmt.Errorf("unclosed verification expression")
		}
	} else {
		value = p.tokens[p.pos]
		p.pos++
		if value == "array" && p.take("[") {
			items, err := p.list("]")
			if err != nil {
				return "", err
			}
			value = "array(" + strings.Join(items, ",") + ")"
		} else if p.take("(") {
			items, err := p.list(")")
			if err != nil {
				return "", err
			}
			value += "(" + strings.Join(items, ",") + ")"
		}
	}
	// PostgreSQL inserts type-preserving casts when deparsing defaults/checks.
	for p.take("::") {
		if p.pos == len(p.tokens) {
			return "", fmt.Errorf("missing cast type")
		}
		typ := p.tokens[p.pos]
		p.pos++
		switch typ {
		case "text", "jsonb", "boolean":
		case "bigint", "integer", "smallint":
			if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
				if number, err := strconv.ParseInt(value[1:len(value)-1], 10, 64); err == nil {
					value = strconv.FormatInt(number, 10)
				}
			}
		case "character":
			if !p.take("varying") {
				return "", fmt.Errorf("unsupported cast type")
			}
		default:
			return "", fmt.Errorf("unsupported cast type %q", typ)
		}
		if p.take("[") && !p.take("]") {
			return "", fmt.Errorf("unsupported array cast")
		}
	}
	return value, nil
}

func (p *expressionParser) list(end string) ([]string, error) {
	items := []string{}
	if p.take(end) {
		return items, nil
	}
	for {
		value, err := p.parse(0)
		if err != nil {
			return nil, err
		}
		items = append(items, value)
		if p.take(end) {
			return items, nil
		}
		if !p.take(",") {
			return nil, fmt.Errorf("unclosed verification value list")
		}
	}
}
