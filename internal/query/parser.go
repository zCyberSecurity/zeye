package query

import "fmt"

// Parse converts a FOFA-like query expression into an AST.
func Parse(input string) (Node, error) {
	tokens, err := Tokenize(input)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens, pos: 0}
	node, err := p.parseExpr()
	if err != nil {
		return nil, err
	}
	if p.current().Type != TOKEN_EOF {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.current().Value, p.current().Pos)
	}
	return node, nil
}

type parser struct {
	tokens []Token
	pos    int
}

func (p *parser) current() Token {
	if p.pos >= len(p.tokens) {
		return Token{Type: TOKEN_EOF}
	}
	return p.tokens[p.pos]
}

func (p *parser) consume() Token {
	tok := p.current()
	p.pos++
	return tok
}

func (p *parser) expect(t TokenType) (Token, error) {
	tok := p.current()
	if tok.Type != t {
		return tok, fmt.Errorf("expected token type %d but got %q at position %d", t, tok.Value, tok.Pos)
	}
	p.pos++
	return tok, nil
}

// Grammar (precedence, lowest to highest):
//
//	expr       = or_expr
//	or_expr    = and_expr { "||" and_expr }
//	and_expr   = not_expr { "&&" not_expr }
//	not_expr   = "!" not_expr | primary
//	primary    = "(" expr ")" | compare
//	compare    = IDENT op value
//	op         = "=" | "!=" | "*=" | "^=" | "$=" | "~=" | ">" | ">=" | "<" | "<="
//	value      = STRING | NUMBER
func (p *parser) parseExpr() (Node, error) {
	return p.parseOrExpr()
}

func (p *parser) parseOrExpr() (Node, error) {
	left, err := p.parseAndExpr()
	if err != nil {
		return nil, err
	}
	for p.current().Type == TOKEN_OR {
		p.consume()
		right, err := p.parseAndExpr()
		if err != nil {
			return nil, err
		}
		left = &BinaryNode{Op: "OR", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAndExpr() (Node, error) {
	left, err := p.parseNotExpr()
	if err != nil {
		return nil, err
	}
	for p.current().Type == TOKEN_AND {
		p.consume()
		right, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		left = &BinaryNode{Op: "AND", Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseNotExpr() (Node, error) {
	if p.current().Type == TOKEN_NOT {
		p.consume()
		operand, err := p.parseNotExpr()
		if err != nil {
			return nil, err
		}
		return &UnaryNode{Operand: operand}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	if p.current().Type == TOKEN_LPAREN {
		p.consume()
		node, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		if _, err := p.expect(TOKEN_RPAREN); err != nil {
			return nil, err
		}
		return node, nil
	}
	return p.parseCompare()
}

func (p *parser) parseCompare() (Node, error) {
	fieldTok, err := p.expect(TOKEN_IDENT)
	if err != nil {
		return nil, fmt.Errorf("expected field name: %w", err)
	}

	opTok := p.consume()
	op, err := tokenToOp(opTok)
	if err != nil {
		return nil, err
	}

	valueTok := p.consume()
	if valueTok.Type != TOKEN_STRING && valueTok.Type != TOKEN_NUMBER {
		return nil, fmt.Errorf("expected value (string or number) after operator, got %q at position %d", valueTok.Value, valueTok.Pos)
	}

	return &CompareNode{
		Field:    fieldTok.Value,
		Operator: op,
		Value:    valueTok.Value,
	}, nil
}

func tokenToOp(tok Token) (string, error) {
	switch tok.Type {
	case TOKEN_EQ:
		return "=", nil
	case TOKEN_NEQ:
		return "!=", nil
	case TOKEN_GT:
		return ">", nil
	case TOKEN_GE:
		return ">=", nil
	case TOKEN_LT:
		return "<", nil
	case TOKEN_LE:
		return "<=", nil
	case TOKEN_CONTAINS:
		return "*=", nil
	case TOKEN_PREFIX:
		return "^=", nil
	case TOKEN_SUFFIX:
		return "$=", nil
	case TOKEN_REGEX:
		return "~=", nil
	default:
		return "", fmt.Errorf("expected operator, got %q at position %d", tok.Value, tok.Pos)
	}
}
