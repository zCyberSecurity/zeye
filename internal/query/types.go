package query

// TokenType identifies the kind of token produced by the lexer.
type TokenType int

const (
	// Literals
	TOKEN_IDENT  TokenType = iota // field name: ip, port, title ...
	TOKEN_STRING                  // quoted string: "value"
	TOKEN_NUMBER                  // integer: 80

	// Comparison operators
	TOKEN_EQ       // =
	TOKEN_NEQ      // !=
	TOKEN_GT       // >
	TOKEN_GE       // >=
	TOKEN_LT       // <
	TOKEN_LE       // <=
	TOKEN_CONTAINS // *=   (contains)
	TOKEN_PREFIX   // ^=   (starts with)
	TOKEN_SUFFIX   // $=   (ends with)
	TOKEN_REGEX    // ~=   (regexp)

	// Logical operators
	TOKEN_AND // &&
	TOKEN_OR  // ||
	TOKEN_NOT // !

	// Grouping
	TOKEN_LPAREN // (
	TOKEN_RPAREN // )

	TOKEN_EOF
	TOKEN_ILLEGAL
)

// Token is a single lexical unit.
type Token struct {
	Type  TokenType
	Value string
	Pos   int
}

// TranslateResult holds the Elasticsearch Query DSL.
type TranslateResult struct {
	DSL map[string]interface{}
}
