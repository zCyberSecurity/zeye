package query

// Node is the common interface for all AST nodes.
type Node interface {
	nodeMarker()
}

// BinaryNode represents a logical AND or OR expression.
type BinaryNode struct {
	Op    string // "AND" | "OR"
	Left  Node
	Right Node
}

func (*BinaryNode) nodeMarker() {}

// UnaryNode represents a logical NOT expression.
type UnaryNode struct {
	Operand Node
}

func (*UnaryNode) nodeMarker() {}

// CompareNode represents a single field comparison.
type CompareNode struct {
	Field    string // "ip", "port", "title", "tls_subject" ...
	Operator string // "=", "!=", ">", ">=", "<", "<=", "*=", "^=", "$=", "~="
	Value    string // raw value string
}

func (*CompareNode) nodeMarker() {}
