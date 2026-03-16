"""
PRISM AST Normalizer — Language-Agnostic Node Type Mapping
============================================================
Maps language-specific Tree-sitter node type strings to the
unified NodeType enum. This is the key abstraction that makes
GraphCodeBERT language-agnostic.

Without normalization:
  Python "function_definition" and Java "method_declaration" are
  different tokens → model learns language-specific syntax patterns

With normalization:
  Both → NodeType.FUNCTION → model learns semantic vulnerability
  patterns independent of surface syntax

Design:
  Each language has a mapping dict: tree_sitter_type → NodeType
  A fallback heuristic handles unknown types by keyword matching.
  All mappings are complete for the target language's security-relevant
  constructs — exhaustive coverage of control flow and data flow nodes.
"""

from __future__ import annotations
from .models import NodeType, Language

# ---------------------------------------------------------------------------
# Per-language normalization tables
# ---------------------------------------------------------------------------

_PYTHON_MAP: dict[str, NodeType] = {
    # Functions
    "function_definition":       NodeType.FUNCTION,
    "async_function_definition": NodeType.FUNCTION,
    "lambda":                    NodeType.LAMBDA,
    # Classes
    "class_definition":          NodeType.CLASS,
    # Blocks
    "block":                     NodeType.BLOCK,
    "with_statement":            NodeType.WITH,
    # Assignments
    "assignment":                NodeType.ASSIGN,
    "augmented_assignment":      NodeType.AUGMENTED_ASSIGN,
    "named_expression":          NodeType.ASSIGN,     # walrus :=
    # Control flow
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "try_statement":             NodeType.TRY,
    "except_clause":             NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "raise_statement":           NodeType.RAISE,
    "assert_statement":          NodeType.ASSERT,
    "return_statement":          NodeType.RETURN,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "yield":                     NodeType.YIELD,
    "yield_from":                NodeType.YIELD,
    "await":                     NodeType.AWAIT,
    # Expressions
    "call":                      NodeType.CALL,
    "binary_operator":           NodeType.BINARY_OP,
    "unary_operator":            NodeType.UNARY_OP,
    "comparison_operator":       NodeType.COMPARE,
    "boolean_operator":          NodeType.BOOL_OP,
    "conditional_expression":    NodeType.CONDITIONAL,
    "subscript":                 NodeType.INDEX_ACCESS,
    "attribute":                 NodeType.MEMBER_ACCESS,
    "list_comprehension":        NodeType.COMPREHENSION,
    "set_comprehension":         NodeType.COMPREHENSION,
    "dictionary_comprehension":  NodeType.COMPREHENSION,
    "generator_expression":      NodeType.COMPREHENSION,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "string":                    NodeType.LITERAL,
    "integer":                   NodeType.LITERAL,
    "float":                     NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "none":                      NodeType.LITERAL,
    "concatenated_string":       NodeType.LITERAL,
    "parameter":                 NodeType.PARAM,
    "default_parameter":         NodeType.PARAM,
    "typed_parameter":           NodeType.PARAM,
    # Imports
    "import_statement":          NodeType.IMPORT,
    "import_from_statement":     NodeType.IMPORT,
    # Spreads
    "list_splat_pattern":        NodeType.SPREAD,
    "dictionary_splat_pattern":  NodeType.SPREAD,
    # Top
    "module":                    NodeType.PROGRAM,
    "expression_statement":      NodeType.BLOCK,
    "delete_statement":          NodeType.DELETE,
}

_JAVASCRIPT_MAP: dict[str, NodeType] = {
    # Functions
    "function_declaration":      NodeType.FUNCTION,
    "function_expression":       NodeType.FUNCTION,
    "arrow_function":            NodeType.FUNCTION,
    "generator_function":        NodeType.FUNCTION,
    "generator_function_declaration": NodeType.FUNCTION,
    "method_definition":         NodeType.FUNCTION,
    # Classes
    "class_declaration":         NodeType.CLASS,
    "class_expression":          NodeType.CLASS,
    # Blocks
    "statement_block":           NodeType.BLOCK,
    "with_statement":            NodeType.WITH,
    # Assignments
    "assignment_expression":     NodeType.ASSIGN,
    "augmented_assignment_expression": NodeType.AUGMENTED_ASSIGN,
    "variable_declaration":      NodeType.ASSIGN,
    "lexical_declaration":       NodeType.ASSIGN,
    # Control flow
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "for_in_statement":          NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "try_statement":             NodeType.TRY,
    "catch_clause":              NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "throw_statement":           NodeType.RAISE,
    "return_statement":          NodeType.RETURN,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "yield_expression":          NodeType.YIELD,
    "await_expression":          NodeType.AWAIT,
    # Expressions
    "call_expression":           NodeType.CALL,
    "new_expression":            NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "ternary_expression":        NodeType.CONDITIONAL,
    "subscript_expression":      NodeType.INDEX_ACCESS,
    "member_expression":         NodeType.MEMBER_ACCESS,
    "spread_element":            NodeType.SPREAD,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "string":                    NodeType.LITERAL,
    "template_string":           NodeType.LITERAL,
    "number":                    NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "null":                      NodeType.LITERAL,
    "undefined":                 NodeType.LITERAL,
    "formal_parameters":         NodeType.PARAM,
    "required_parameter":        NodeType.PARAM,
    "optional_parameter":        NodeType.PARAM,
    # Imports
    "import_statement":          NodeType.IMPORT,
    "import_declaration":        NodeType.IMPORT,
    "export_statement":          NodeType.MODULE,
    # Top
    "program":                   NodeType.PROGRAM,
}

_JAVA_MAP: dict[str, NodeType] = {
    # Functions
    "method_declaration":        NodeType.FUNCTION,
    "constructor_declaration":   NodeType.FUNCTION,
    "lambda_expression":         NodeType.LAMBDA,
    # Classes
    "class_declaration":         NodeType.CLASS,
    "interface_declaration":     NodeType.CLASS,
    "enum_declaration":          NodeType.CLASS,
    "annotation_type_declaration": NodeType.CLASS,
    # Blocks
    "block":                     NodeType.BLOCK,
    "synchronized_statement":    NodeType.BLOCK,
    # Assignments
    "assignment_expression":     NodeType.ASSIGN,
    "variable_declarator":       NodeType.ASSIGN,
    "local_variable_declaration":NodeType.ASSIGN,
    # Control flow
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "enhanced_for_statement":    NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "try_statement":             NodeType.TRY,
    "catch_clause":              NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "throw_statement":           NodeType.RAISE,
    "return_statement":          NodeType.RETURN,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "assert_statement":          NodeType.ASSERT,
    # Expressions
    "method_invocation":         NodeType.CALL,
    "object_creation_expression":NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "ternary_expression":        NodeType.CONDITIONAL,
    "array_access":              NodeType.INDEX_ACCESS,
    "field_access":              NodeType.MEMBER_ACCESS,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "string_literal":            NodeType.LITERAL,
    "integer_literal":           NodeType.LITERAL,
    "floating_point_literal":    NodeType.LITERAL,
    "boolean_type":              NodeType.LITERAL,
    "null_literal":              NodeType.LITERAL,
    "formal_parameter":          NodeType.PARAM,
    "spread_parameter":          NodeType.PARAM,
    # Imports
    "import_declaration":        NodeType.IMPORT,
    "package_declaration":       NodeType.MODULE,
    # Top
    "program":                   NodeType.PROGRAM,
    "class_body":                NodeType.BLOCK,
}

_RUST_MAP: dict[str, NodeType] = {
    # Functions
    "function_item":             NodeType.FUNCTION,
    "closure_expression":        NodeType.LAMBDA,
    # Classes / structs
    "struct_item":               NodeType.CLASS,
    "impl_item":                 NodeType.CLASS,
    "trait_item":                NodeType.CLASS,
    "enum_item":                 NodeType.CLASS,
    # Blocks
    "block":                     NodeType.BLOCK,
    "unsafe_block":              NodeType.BLOCK,
    # Assignments
    "let_declaration":           NodeType.ASSIGN,
    "assignment_expression":     NodeType.ASSIGN,
    # Control flow
    "if_expression":             NodeType.IF,
    "if_let_expression":         NodeType.IF,
    "for_expression":            NodeType.LOOP,
    "while_expression":          NodeType.LOOP,
    "while_let_expression":      NodeType.LOOP,
    "loop_expression":           NodeType.LOOP,
    "match_expression":          NodeType.IF,         # pattern matching
    "try_expression":            NodeType.TRY,        # ? operator
    "return_expression":         NodeType.RETURN,
    "break_expression":          NodeType.BREAK,
    "continue_expression":       NodeType.CONTINUE,
    "await_expression":          NodeType.AWAIT,
    "yield_expression":          NodeType.YIELD,
    # Expressions
    "call_expression":           NodeType.CALL,
    "method_call_expression":    NodeType.CALL,
    "macro_invocation":          NodeType.CALL,       # println! etc.
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "index_expression":          NodeType.INDEX_ACCESS,
    "field_expression":          NodeType.MEMBER_ACCESS,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "string_literal":            NodeType.LITERAL,
    "integer_literal":           NodeType.LITERAL,
    "float_literal":             NodeType.LITERAL,
    "boolean_literal":           NodeType.LITERAL,
    "parameter":                 NodeType.PARAM,
    "self_parameter":            NodeType.PARAM,
    # Imports
    "use_declaration":           NodeType.IMPORT,
    "mod_item":                  NodeType.MODULE,
    # Top
    "source_file":               NodeType.PROGRAM,
}

_GO_MAP: dict[str, NodeType] = {
    # Functions
    "function_declaration":      NodeType.FUNCTION,
    "method_declaration":        NodeType.FUNCTION,
    "func_literal":              NodeType.LAMBDA,
    # Blocks
    "block":                     NodeType.BLOCK,
    # Assignments
    "assignment_statement":      NodeType.ASSIGN,
    "short_var_declaration":     NodeType.ASSIGN,
    "var_declaration":           NodeType.ASSIGN,
    # Control flow
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "range_clause":              NodeType.LOOP,
    "switch_statement":          NodeType.IF,
    "type_switch_statement":     NodeType.IF,
    "select_statement":          NodeType.BLOCK,      # channel select
    "defer_statement":           NodeType.BLOCK,      # defer
    "go_statement":              NodeType.BLOCK,      # goroutine
    "return_statement":          NodeType.RETURN,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    # Expressions
    "call_expression":           NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "index_expression":          NodeType.INDEX_ACCESS,
    "selector_expression":       NodeType.MEMBER_ACCESS,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "interpreted_string_literal":NodeType.LITERAL,
    "raw_string_literal":        NodeType.LITERAL,
    "int_literal":               NodeType.LITERAL,
    "float_literal":             NodeType.LITERAL,
    "parameter_declaration":     NodeType.PARAM,
    "variadic_parameter_declaration": NodeType.PARAM,
    # Imports
    "import_declaration":        NodeType.IMPORT,
    "package_clause":            NodeType.MODULE,
    # Top
    "source_file":               NodeType.PROGRAM,
}

_C_MAP: dict[str, NodeType] = {
    # Functions
    "function_definition":       NodeType.FUNCTION,
    # Structs / types
    "struct_specifier":          NodeType.CLASS,
    "union_specifier":           NodeType.CLASS,
    "enum_specifier":            NodeType.CLASS,
    # Blocks
    "compound_statement":        NodeType.BLOCK,
    # Assignments
    "assignment_expression":     NodeType.ASSIGN,
    "init_declarator":           NodeType.ASSIGN,
    "declaration":               NodeType.ASSIGN,
    # Control flow
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "switch_statement":          NodeType.IF,
    "return_statement":          NodeType.RETURN,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "goto_statement":            NodeType.BREAK,      # treat as control flow
    # Expressions
    "call_expression":           NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "conditional_expression":    NodeType.CONDITIONAL,
    "subscript_expression":      NodeType.INDEX_ACCESS,
    "field_expression":          NodeType.MEMBER_ACCESS,
    "pointer_expression":        NodeType.UNARY_OP,
    # Atoms
    "identifier":                NodeType.IDENTIFIER,
    "string_literal":            NodeType.LITERAL,
    "number_literal":            NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "null":                      NodeType.LITERAL,
    "parameter_declaration":     NodeType.PARAM,
    # Includes
    "preproc_include":           NodeType.IMPORT,
    "preproc_def":               NodeType.ASSIGN,
    # Top
    "translation_unit":          NodeType.PROGRAM,
}

# C++ extends C
_CPP_MAP: dict[str, NodeType] = {
    **_C_MAP,
    "class_specifier":           NodeType.CLASS,
    "function_definition":       NodeType.FUNCTION,
    "lambda_expression":         NodeType.LAMBDA,
    "try_statement":             NodeType.TRY,
    "catch_clause":              NodeType.CATCH,
    "throw_expression":          NodeType.RAISE,
    "new_expression":            NodeType.CALL,
    "delete_expression":         NodeType.DELETE,
    "template_declaration":      NodeType.FUNCTION,
    "namespace_definition":      NodeType.MODULE,
    "using_declaration":         NodeType.IMPORT,
    "translation_unit":          NodeType.PROGRAM,
}

# Terraform HCL
_TERRAFORM_MAP: dict[str, NodeType] = {
    "config_file":               NodeType.PROGRAM,
    "body":                      NodeType.BLOCK,
    "block":                     NodeType.BLOCK,
    "resource_block":            NodeType.RESOURCE,
    "data_block":                NodeType.DATA_SOURCE,
    "variable_block":            NodeType.VARIABLE,
    "output_block":              NodeType.OUTPUT,
    "provider_block":            NodeType.PROVIDER,
    "locals_block":              NodeType.ASSIGN,
    "module_block":              NodeType.MODULE,
    "attribute":                 NodeType.ASSIGN,
    "object_expression":         NodeType.BLOCK,
    "tuple_expression":          NodeType.SEQUENCE,
    "function_call":             NodeType.CALL,
    "identifier":                NodeType.IDENTIFIER,
    "string_lit":                NodeType.LITERAL,
    "numeric_lit":               NodeType.LITERAL,
    "bool_lit":                  NodeType.LITERAL,
    "null_lit":                  NodeType.LITERAL,
    "template_expr":             NodeType.LITERAL,
    "conditional":               NodeType.CONDITIONAL,
    "binary_op":                 NodeType.BINARY_OP,
    "unary_op":                  NodeType.UNARY_OP,
    "index":                     NodeType.INDEX_ACCESS,
    "get_attr":                  NodeType.MEMBER_ACCESS,
    "for_expr":                  NodeType.COMPREHENSION,
}

# YAML (Kubernetes, Ansible, GitHub Actions)
_YAML_MAP: dict[str, NodeType] = {
    "stream":                    NodeType.PROGRAM,
    "document":                  NodeType.BLOCK,
    "block_mapping":             NodeType.MAPPING,
    "block_mapping_pair":        NodeType.ASSIGN,
    "block_sequence":            NodeType.SEQUENCE,
    "block_sequence_item":       NodeType.BLOCK,
    "flow_mapping":              NodeType.MAPPING,
    "flow_pair":                 NodeType.ASSIGN,
    "flow_sequence":             NodeType.SEQUENCE,
    "alias":                     NodeType.IDENTIFIER,
    "anchor":                    NodeType.IDENTIFIER,
    "tag":                       NodeType.IDENTIFIER,
    "plain_scalar":              NodeType.LITERAL,
    "single_quote_scalar":       NodeType.LITERAL,
    "double_quote_scalar":       NodeType.LITERAL,
    "block_scalar":              NodeType.LITERAL,
    "boolean_scalar":            NodeType.LITERAL,
    "null_scalar":               NodeType.LITERAL,
    "integer_scalar":            NodeType.LITERAL,
    "float_scalar":              NodeType.LITERAL,
}

# Dispatch table
_LANGUAGE_MAPS: dict[str, dict[str, NodeType]] = {
    "python":      _PYTHON_MAP,
    "javascript":  _JAVASCRIPT_MAP,
    "typescript":  _JAVASCRIPT_MAP,   # TS is a superset — share JS map
    "tsx":         _JAVASCRIPT_MAP,
    "java":        _JAVA_MAP,
    "rust":        _RUST_MAP,
    "go":          _GO_MAP,
    "c":           _C_MAP,
    "cpp":         _CPP_MAP,
    "terraform":   _TERRAFORM_MAP,
    "yaml":        _YAML_MAP,
}

# Keywords that hint at node type when exact match fails
_FALLBACK_KEYWORDS: list[tuple[list[str], NodeType]] = [
    (["function", "method", "func", "def", "lambda", "closure"],  NodeType.FUNCTION),
    (["class", "struct", "interface", "trait", "enum", "impl"],    NodeType.CLASS),
    (["call", "invoke", "application", "new"],                     NodeType.CALL),
    (["if", "when", "condition", "switch", "case", "match"],       NodeType.IF),
    (["for", "while", "loop", "each", "repeat", "iterate"],        NodeType.LOOP),
    (["assign", "declaration", "let", "var", "const", "define"],   NodeType.ASSIGN),
    (["return", "yield", "await"],                                  NodeType.RETURN),
    (["try", "except", "catch", "error", "panic", "recover"],      NodeType.TRY),
    (["import", "include", "require", "use", "from"],              NodeType.IMPORT),
    (["identifier", "name", "symbol"],                             NodeType.IDENTIFIER),
    (["string", "literal", "constant", "number", "bool", "null"], NodeType.LITERAL),
    (["parameter", "param", "argument", "arg"],                    NodeType.PARAM),
    (["block", "body", "scope"],                                   NodeType.BLOCK),
]


def normalize_node_type(ts_type: str, language: str) -> NodeType:
    """
    Map a Tree-sitter node type string to a unified NodeType.

    Strategy:
      1. Exact lookup in language-specific map
      2. Keyword heuristic on the ts_type string
      3. Fall back to NodeType.UNKNOWN (never crash)

    This function is called for every node in the AST — must be fast.
    """
    lang_map = _LANGUAGE_MAPS.get(language.lower(), {})

    # 1. Exact match
    if ts_type in lang_map:
        return lang_map[ts_type]

    # 2. Keyword heuristic
    ts_lower = ts_type.lower()
    for keywords, node_type in _FALLBACK_KEYWORDS:
        if any(kw in ts_lower for kw in keywords):
            return node_type

    return NodeType.UNKNOWN