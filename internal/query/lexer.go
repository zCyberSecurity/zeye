package query

import (
	"fmt"
	"strings"
	"unicode"
)

// Tokenize converts a FOFA-like query string into a token slice.
func Tokenize(input string) ([]Token, error) {
	l := &lexer{input: input, pos: 0}
	return l.tokenize()
}

type lexer struct {
	input string
	pos   int
}

func (l *lexer) tokenize() ([]Token, error) {
	var tokens []Token
	for {
		l.skipWhitespace()
		if l.pos >= len(l.input) {
			tokens = append(tokens, Token{Type: TOKEN_EOF, Pos: l.pos})
			break
		}

		tok, err := l.next()
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, tok)
		if tok.Type == TOKEN_EOF {
			break
		}
	}
	return tokens, nil
}

func (l *lexer) skipWhitespace() {
	for l.pos < len(l.input) && unicode.IsSpace(rune(l.input[l.pos])) {
		l.pos++
	}
}

func (l *lexer) peek() byte {
	if l.pos >= len(l.input) {
		return 0
	}
	return l.input[l.pos]
}

func (l *lexer) peekAt(offset int) byte {
	p := l.pos + offset
	if p >= len(l.input) {
		return 0
	}
	return l.input[p]
}

func (l *lexer) consume() byte {
	ch := l.input[l.pos]
	l.pos++
	return ch
}

func (l *lexer) next() (Token, error) {
	start := l.pos
	ch := l.peek()

	switch {
	case ch == '(':
		l.consume()
		return Token{Type: TOKEN_LPAREN, Value: "(", Pos: start}, nil

	case ch == ')':
		l.consume()
		return Token{Type: TOKEN_RPAREN, Value: ")", Pos: start}, nil

	case ch == '&' && l.peekAt(1) == '&':
		l.pos += 2
		return Token{Type: TOKEN_AND, Value: "&&", Pos: start}, nil

	case ch == '|' && l.peekAt(1) == '|':
		l.pos += 2
		return Token{Type: TOKEN_OR, Value: "||", Pos: start}, nil

	case ch == '!' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_NEQ, Value: "!=", Pos: start}, nil

	case ch == '!':
		l.consume()
		return Token{Type: TOKEN_NOT, Value: "!", Pos: start}, nil

	case ch == '*' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_CONTAINS, Value: "*=", Pos: start}, nil

	case ch == '^' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_PREFIX, Value: "^=", Pos: start}, nil

	case ch == '$' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_SUFFIX, Value: "$=", Pos: start}, nil

	case ch == '~' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_REGEX, Value: "~=", Pos: start}, nil

	case ch == '>' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_GE, Value: ">=", Pos: start}, nil

	case ch == '>':
		l.consume()
		return Token{Type: TOKEN_GT, Value: ">", Pos: start}, nil

	case ch == '<' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_LE, Value: "<=", Pos: start}, nil

	case ch == '<':
		l.consume()
		return Token{Type: TOKEN_LT, Value: "<", Pos: start}, nil

	case ch == '=' && l.peekAt(1) == '=':
		l.pos += 2
		return Token{Type: TOKEN_EXACT, Value: "==", Pos: start}, nil

	case ch == '=':
		l.consume()
		return Token{Type: TOKEN_EQ, Value: "=", Pos: start}, nil

	case ch == '"':
		return l.lexString(start)

	case isIdentStart(ch):
		return l.lexIdent(start)

	case isDigit(ch) || (ch == '-' && isDigit(l.peekAt(1))):
		return l.lexNumber(start)

	default:
		l.consume()
		return Token{Type: TOKEN_ILLEGAL, Value: string(ch), Pos: start}, nil
	}
}

func (l *lexer) lexString(start int) (Token, error) {
	l.consume() // consume opening "
	var sb strings.Builder
	for l.pos < len(l.input) {
		ch := l.consume()
		if ch == '"' {
			return Token{Type: TOKEN_STRING, Value: sb.String(), Pos: start}, nil
		}
		if ch == '\\' && l.pos < len(l.input) {
			next := l.consume()
			switch next {
			case '"':
				sb.WriteByte('"')
			case '\\':
				sb.WriteByte('\\')
			case 'n':
				sb.WriteByte('\n')
			default:
				sb.WriteByte('\\')
				sb.WriteByte(next)
			}
			continue
		}
		sb.WriteByte(ch)
	}
	return Token{}, fmt.Errorf("unterminated string at position %d", start)
}

func (l *lexer) lexIdent(start int) (Token, error) {
	var sb strings.Builder
	for l.pos < len(l.input) && isIdentChar(l.peek()) {
		sb.WriteByte(l.consume())
	}
	return Token{Type: TOKEN_IDENT, Value: sb.String(), Pos: start}, nil
}

func (l *lexer) lexNumber(start int) (Token, error) {
	var sb strings.Builder
	if l.peek() == '-' {
		sb.WriteByte(l.consume())
	}
	for l.pos < len(l.input) && isDigit(l.peek()) {
		sb.WriteByte(l.consume())
	}
	return Token{Type: TOKEN_NUMBER, Value: sb.String(), Pos: start}, nil
}

func isIdentStart(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_'
}

func isIdentChar(ch byte) bool {
	return isIdentStart(ch) || isDigit(ch) || ch == '.'
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}
