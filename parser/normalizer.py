"""
PRISM AST Normalizer
====================
Maps raw Tree-sitter node types to the unified NodeType vocabulary.
One NormalizationMap per language; all maps registered in NORMALIZER_REGISTRY.

Design:
  - Each map is a plain dict (raw_type_str → NodeType), enabling O(1) lookup.
  - Unknown types fall back to NodeType.UNKNOWN (never crash).
  - Name / value extraction logic lives here (resolves CALL names, ASSIGN targets, etc.)
"""

from __future__ import annotations

import logging
from typing import Any

from .models import Language, NodeType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Language-specific raw → NodeType maps
# ---------------------------------------------------------------------------

_PYTHON_MAP: dict[str, NodeType] = {
    "module":                    NodeType.PROGRAM,
    "function_definition":       NodeType.FUNCTION,
    "async_function_definition": NodeType.FUNCTION,
    "class_definition":          NodeType.CLASS,
    "block":                     NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "assignment":                NodeType.ASSIGN,
    "augmented_assignment":      NodeType.AUGMENTED_ASSIGN,
    "return_statement":          NodeType.RETURN,
    "import_statement":          NodeType.IMPORT,
    "import_from_statement":     NodeType.IMPORT,
    "delete_statement":          NodeType.DELETE,
    "raise_statement":           NodeType.RAISE,
    "assert_statement":          NodeType.ASSERT,
    "if_statement":              NodeType.IF,
    "elif_clause":               NodeType.ELIF,
    "else_clause":               NodeType.ELSE,
    "for_statement":             NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "try_statement":             NodeType.TRY,
    "except_clause":             NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "with_statement":            NodeType.BLOCK,
    "call":                      NodeType.CALL,
    "binary_operator":           NodeType.BINARY_OP,
    "unary_operator":            NodeType.UNARY_OP,
    "comparison_operator":       NodeType.COMPARISON,
    "boolean_operator":          NodeType.LOGICAL_OP,
    "conditional_expression":    NodeType.TERNARY,
    "await":                     NodeType.AWAIT,
    "yield":                     NodeType.YIELD,
    "yield_from":                NodeType.YIELD,
    "lambda":                    NodeType.LAMBDA,
    "identifier":                NodeType.IDENTIFIER,
    "integer":                   NodeType.LITERAL,
    "float":                     NodeType.LITERAL,
    "string":                    NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "none":                      NodeType.LITERAL,
    "concatenated_string":       NodeType.LITERAL,
    "attribute":                 NodeType.ATTRIBUTE,
    "subscript":                 NodeType.SUBSCRIPT,
    "list":                      NodeType.ARRAY,
    "tuple":                     NodeType.TUPLE,
    "set":                       NodeType.SET,
    "dictionary":                NodeType.DICT,
    "pair":                      NodeType.PAIR,
    "type":                      NodeType.TYPE_ANNOTATION,
    "parameters":                NodeType.PARAMETER,
    "default_parameter":         NodeType.DEFAULT_VALUE,
    "typed_parameter":           NodeType.PARAMETER,
    "argument_list":             NodeType.ARGUMENT,
    "keyword_argument":          NodeType.KEYWORD_ARGUMENT,
    "decorated_definition":      NodeType.DECORATOR,
    "decorator":                 NodeType.DECORATOR,
    "comment":                   NodeType.COMMENT,
    "string_content":            NodeType.DOCSTRING,
    "starred":                   NodeType.SPREAD,
}

_JAVA_MAP: dict[str, NodeType] = {
    "program":                   NodeType.PROGRAM,
    "class_declaration":         NodeType.CLASS,
    "interface_declaration":     NodeType.INTERFACE,
    "enum_declaration":          NodeType.ENUM,
    "method_declaration":        NodeType.FUNCTION,
    "constructor_declaration":   NodeType.FUNCTION,
    "block":                     NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "assignment_expression":     NodeType.ASSIGN,
    "variable_declarator":       NodeType.ASSIGN,
    "return_statement":          NodeType.RETURN,
    "import_declaration":        NodeType.IMPORT,
    "throw_statement":           NodeType.RAISE,
    "assert_statement":          NodeType.ASSERT,
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "enhanced_for_statement":    NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "switch_expression":         NodeType.SWITCH,
    "switch_label":              NodeType.CASE,
    "try_statement":             NodeType.TRY,
    "catch_clause":              NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "method_invocation":         NodeType.CALL,
    "object_creation_expression": NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "ternary_expression":        NodeType.TERNARY,
    "identifier":                NodeType.IDENTIFIER,
    "decimal_integer_literal":   NodeType.LITERAL,
    "decimal_floating_point_literal": NodeType.LITERAL,
    "string_literal":            NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "null_literal":              NodeType.LITERAL,
    "field_access":              NodeType.ATTRIBUTE,
    "array_access":              NodeType.SUBSCRIPT,
    "array_initializer":         NodeType.ARRAY,
    "type_identifier":           NodeType.TYPE_ANNOTATION,
    "generic_type":              NodeType.GENERIC,
    "formal_parameters":         NodeType.PARAMETER,
    "formal_parameter":          NodeType.PARAMETER,
    "argument_list":             NodeType.ARGUMENT,
    "annotation":                NodeType.ANNOTATION,
    "line_comment":              NodeType.COMMENT,
    "block_comment":             NodeType.COMMENT,
}

_JAVASCRIPT_MAP: dict[str, NodeType] = {
    "program":                   NodeType.PROGRAM,
    "function_declaration":      NodeType.FUNCTION,
    "function_expression":       NodeType.FUNCTION,
    "arrow_function":            NodeType.FUNCTION,
    "generator_function":        NodeType.FUNCTION,
    "class_declaration":         NodeType.CLASS,
    "statement_block":           NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "assignment_expression":     NodeType.ASSIGN,
    "variable_declarator":       NodeType.ASSIGN,
    "return_statement":          NodeType.RETURN,
    "import_statement":          NodeType.IMPORT,
    "throw_statement":           NodeType.RAISE,
    "if_statement":              NodeType.IF,
    "else_clause":               NodeType.ELSE,
    "for_statement":             NodeType.LOOP,
    "for_in_statement":          NodeType.LOOP,
    "for_of_statement":          NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "switch_statement":          NodeType.SWITCH,
    "switch_case":               NodeType.CASE,
    "try_statement":             NodeType.TRY,
    "catch_clause":              NodeType.CATCH,
    "finally_clause":            NodeType.FINALLY,
    "call_expression":           NodeType.CALL,
    "new_expression":            NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "ternary_expression":        NodeType.TERNARY,
    "await_expression":          NodeType.AWAIT,
    "yield_expression":          NodeType.YIELD,
    "arrow_function":            NodeType.LAMBDA,
    "identifier":                NodeType.IDENTIFIER,
    "number":                    NodeType.LITERAL,
    "string":                    NodeType.LITERAL,
    "template_string":           NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "null":                      NodeType.LITERAL,
    "undefined":                 NodeType.LITERAL,
    "member_expression":         NodeType.ATTRIBUTE,
    "subscript_expression":      NodeType.SUBSCRIPT,
    "array":                     NodeType.ARRAY,
    "object":                    NodeType.DICT,
    "pair":                      NodeType.PAIR,
    "spread_element":            NodeType.SPREAD,
    "formal_parameters":         NodeType.PARAMETER,
    "arguments":                 NodeType.ARGUMENT,
    "decorator":                 NodeType.DECORATOR,
    "comment":                   NodeType.COMMENT,
}

_RUST_MAP: dict[str, NodeType] = {
    "source_file":               NodeType.PROGRAM,
    "function_item":             NodeType.FUNCTION,
    "closure_expression":        NodeType.LAMBDA,
    "struct_item":               NodeType.CLASS,
    "impl_item":                 NodeType.CLASS,
    "trait_item":                NodeType.INTERFACE,
    "enum_item":                 NodeType.ENUM,
    "mod_item":                  NodeType.MODULE,
    "block":                     NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "assignment_expression":     NodeType.ASSIGN,
    "let_declaration":           NodeType.ASSIGN,
    "return_expression":         NodeType.RETURN,
    "use_declaration":           NodeType.IMPORT,
    "break_expression":          NodeType.BREAK,
    "continue_expression":       NodeType.CONTINUE,
    "if_expression":             NodeType.IF,
    "else_clause":               NodeType.ELSE,
    "loop_expression":           NodeType.LOOP,
    "for_expression":            NodeType.LOOP,
    "while_expression":          NodeType.LOOP,
    "match_expression":          NodeType.SWITCH,
    "match_arm":                 NodeType.CASE,
    "call_expression":           NodeType.CALL,
    "method_call_expression":    NodeType.CALL,
    "macro_invocation":          NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "await_expression":          NodeType.AWAIT,
    "identifier":                NodeType.IDENTIFIER,
    "integer_literal":           NodeType.LITERAL,
    "float_literal":             NodeType.LITERAL,
    "string_literal":            NodeType.LITERAL,
    "boolean_literal":           NodeType.LITERAL,
    "char_literal":              NodeType.LITERAL,
    "field_expression":          NodeType.ATTRIBUTE,
    "index_expression":          NodeType.SUBSCRIPT,
    "array_expression":          NodeType.ARRAY,
    "tuple_expression":          NodeType.TUPLE,
    "struct_expression":         NodeType.DICT,
    "type_identifier":           NodeType.TYPE_ANNOTATION,
    "generic_type":              NodeType.GENERIC,
    "parameters":                NodeType.PARAMETER,
    "arguments":                 NodeType.ARGUMENT,
    "attribute_item":            NodeType.ANNOTATION,
    "line_comment":              NodeType.COMMENT,
    "block_comment":             NodeType.COMMENT,
    "unsafe":                    NodeType.BLOCK,
}

_GO_MAP: dict[str, NodeType] = {
    "source_file":               NodeType.PROGRAM,
    "function_declaration":      NodeType.FUNCTION,
    "method_declaration":        NodeType.FUNCTION,
    "func_literal":              NodeType.LAMBDA,
    "type_declaration":          NodeType.CLASS,
    "interface_type":            NodeType.INTERFACE,
    "block":                     NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "assignment_statement":      NodeType.ASSIGN,
    "short_var_declaration":     NodeType.ASSIGN,
    "var_declaration":           NodeType.ASSIGN,
    "return_statement":          NodeType.RETURN,
    "import_declaration":        NodeType.IMPORT,
    "go_statement":              NodeType.EXPRESSION_STATEMENT,
    "defer_statement":           NodeType.EXPRESSION_STATEMENT,
    "if_statement":              NodeType.IF,
    "for_statement":             NodeType.LOOP,
    "range_clause":              NodeType.LOOP,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "switch_statement":          NodeType.SWITCH,
    "type_switch_statement":     NodeType.SWITCH,
    "expression_case":           NodeType.CASE,
    "select_statement":          NodeType.SWITCH,
    "call_expression":           NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "identifier":                NodeType.IDENTIFIER,
    "int_literal":               NodeType.LITERAL,
    "float_literal":             NodeType.LITERAL,
    "interpreted_string_literal": NodeType.LITERAL,
    "raw_string_literal":        NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "nil":                       NodeType.LITERAL,
    "selector_expression":       NodeType.ATTRIBUTE,
    "index_expression":          NodeType.SUBSCRIPT,
    "composite_literal":         NodeType.DICT,
    "slice_expression":          NodeType.ARRAY,
    "type_identifier":           NodeType.TYPE_ANNOTATION,
    "parameter_declaration":     NodeType.PARAMETER,
    "argument_list":             NodeType.ARGUMENT,
    "comment":                   NodeType.COMMENT,
}

_HCL_MAP: dict[str, NodeType] = {
    "config_file":               NodeType.PROGRAM,
    "body":                      NodeType.BLOCK,
    "block":                     NodeType.BLOCK,
    "attribute":                 NodeType.CONFIG_KEY,
    "expression":                NodeType.CONFIG_VALUE,
    "resource":                  NodeType.RESOURCE,
    "provider":                  NodeType.PROVIDER,
    "variable":                  NodeType.VARIABLE,
    "output":                    NodeType.OUTPUT,
    "data":                      NodeType.DATA_SOURCE,
    "module":                    NodeType.MODULE_CALL,
    "identifier":                NodeType.IDENTIFIER,
    "string_lit":                NodeType.LITERAL,
    "numeric_lit":               NodeType.LITERAL,
    "bool_lit":                  NodeType.LITERAL,
    "null_lit":                  NodeType.LITERAL,
    "template_expr":             NodeType.LITERAL,
    "function_call":             NodeType.CALL,
    "object":                    NodeType.DICT,
    "object_elem":               NodeType.PAIR,
    "tuple":                     NodeType.ARRAY,
    "for_expr":                  NodeType.LOOP,
    "conditional":               NodeType.TERNARY,
    "comment":                   NodeType.COMMENT,
}

_YAML_MAP: dict[str, NodeType] = {
    "stream":                    NodeType.PROGRAM,
    "document":                  NodeType.MODULE,
    "block_mapping":             NodeType.DICT,
    "block_mapping_pair":        NodeType.PAIR,
    "block_sequence":            NodeType.ARRAY,
    "block_sequence_item":       NodeType.ARRAY,
    "flow_mapping":              NodeType.DICT,
    "flow_pair":                 NodeType.PAIR,
    "flow_sequence":             NodeType.ARRAY,
    "plain_scalar":              NodeType.LITERAL,
    "single_quote_scalar":       NodeType.LITERAL,
    "double_quote_scalar":       NodeType.LITERAL,
    "block_scalar":              NodeType.LITERAL,
    "alias":                     NodeType.IDENTIFIER,
    "anchor":                    NodeType.IDENTIFIER,
    "tag":                       NodeType.TYPE_ANNOTATION,
    "comment":                   NodeType.COMMENT,
}

# Shared C/C++ map (basic — CodeQL handles these languages primarily)
_C_MAP: dict[str, NodeType] = {
    "translation_unit":          NodeType.PROGRAM,
    "function_definition":       NodeType.FUNCTION,
    "declaration":               NodeType.ASSIGN,
    "compound_statement":        NodeType.BLOCK,
    "expression_statement":      NodeType.EXPRESSION_STATEMENT,
    "return_statement":          NodeType.RETURN,
    "if_statement":              NodeType.IF,
    "else_clause":               NodeType.ELSE,
    "for_statement":             NodeType.LOOP,
    "while_statement":           NodeType.LOOP,
    "do_statement":              NodeType.LOOP,
    "break_statement":           NodeType.BREAK,
    "continue_statement":        NodeType.CONTINUE,
    "switch_statement":          NodeType.SWITCH,
    "case_statement":            NodeType.CASE,
    "call_expression":           NodeType.CALL,
    "binary_expression":         NodeType.BINARY_OP,
    "unary_expression":          NodeType.UNARY_OP,
    "conditional_expression":    NodeType.TERNARY,
    "identifier":                NodeType.IDENTIFIER,
    "number_literal":            NodeType.LITERAL,
    "string_literal":            NodeType.LITERAL,
    "true":                      NodeType.LITERAL,
    "false":                     NodeType.LITERAL,
    "null":                      NodeType.LITERAL,
    "field_expression":          NodeType.ATTRIBUTE,
    "subscript_expression":      NodeType.SUBSCRIPT,
    "initializer_list":          NodeType.ARRAY,
    "parameter_declaration":     NodeType.PARAMETER,
    "argument_list":             NodeType.ARGUMENT,
    "comment":                   NodeType.COMMENT,
    "preproc_include":           NodeType.IMPORT,
    "preproc_def":               NodeType.ASSIGN,
}

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

NORMALIZER_REGISTRY: dict[Language, dict[str, NodeType]] = {
    Language.PYTHON:        _PYTHON_MAP,
    Language.JAVA:          _JAVA_MAP,
    Language.JAVASCRIPT:    _JAVASCRIPT_MAP,
    Language.TYPESCRIPT:    _JAVASCRIPT_MAP,   # TSX/TS share JS structure mostly
    Language.TSX:           _JAVASCRIPT_MAP,
    Language.RUST:          _RUST_MAP,
    Language.GO:            _GO_MAP,
    Language.TERRAFORM_HCL: _HCL_MAP,
    Language.YAML:          _YAML_MAP,
    Language.C:             _C_MAP,
    Language.CPP:           _C_MAP,
    Language.UNKNOWN:       {},
}


class ASTNormalizer:
    """
    Converts raw Tree-sitter node types to the unified NodeType enum,
    and extracts name / value / qualified_name from node text.
    """

    def normalize_type(self, raw_type: str, language: Language) -> NodeType:
        mapping = NORMALIZER_REGISTRY.get(language, {})
        return mapping.get(raw_type, NodeType.UNKNOWN)

    def extract_name(
        self,
        raw_type: str,
        node_text: str,
        normalized_type: NodeType,
        language: Language,
        children_texts: list[str],
    ) -> str | None:
        """
        Extract the semantic name from a node.
        E.g. for a CALL node → function name; FUNCTION → function name.
        """
        match normalized_type:
            case NodeType.FUNCTION:
                return _extract_function_name(raw_type, node_text, language, children_texts)
            case NodeType.CLASS:
                return _extract_class_name(raw_type, node_text, language, children_texts)
            case NodeType.CALL:
                return _extract_call_name(raw_type, node_text, language, children_texts)
            case NodeType.IDENTIFIER:
                return node_text.strip()
            case NodeType.ASSIGN | NodeType.AUGMENTED_ASSIGN:
                return _extract_assign_target(node_text, language)
            case NodeType.IMPORT:
                return node_text.strip()
            case NodeType.ATTRIBUTE:
                return node_text.strip()
            case NodeType.RESOURCE | NodeType.PROVIDER | NodeType.VARIABLE:
                return _extract_hcl_block_name(node_text)
            case NodeType.CONFIG_KEY:
                return node_text.split("=")[0].strip().strip('"')
            case _:
                return None

    def extract_value(
        self,
        normalized_type: NodeType,
        node_text: str,
    ) -> str | None:
        """Extract literal value or raw text snippet."""
        if normalized_type == NodeType.LITERAL:
            return node_text.strip()
        if normalized_type == NodeType.CONFIG_VALUE:
            parts = node_text.split("=", 1)
            return parts[1].strip() if len(parts) > 1 else node_text.strip()
        return None


# ---------------------------------------------------------------------------
# Name extraction helpers
# ---------------------------------------------------------------------------

def _extract_function_name(
    raw_type: str,
    node_text: str,
    language: Language,
    children_texts: list[str],
) -> str | None:
    """Best-effort function name extraction from raw text."""
    import re
    patterns: list[str] = {
        Language.PYTHON:     [r"def\s+(\w+)\s*\(", r"async\s+def\s+(\w+)\s*\("],
        Language.JAVA:       [r"(?:public|private|protected|static|\s)+\s+\w+\s+(\w+)\s*\("],
        Language.JAVASCRIPT: [r"function\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*="],
        Language.TYPESCRIPT: [r"function\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*="],
        Language.TSX:        [r"function\s+(\w+)\s*\(", r"(?:const|let|var)\s+(\w+)\s*="],
        Language.RUST:       [r"fn\s+(\w+)\s*[<\(]"],
        Language.GO:         [r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\("],
        Language.C:          [r"\b(\w+)\s*\([^)]*\)\s*\{"],
        Language.CPP:        [r"(?:\w+::)?(\w+)\s*\([^)]*\)\s*(?:const)?\s*\{"],
    }.get(language, [])

    for pattern in patterns:
        m = re.search(pattern, node_text, re.DOTALL)
        if m:
            return m.group(1)

    # Fallback: first identifier-like child
    if children_texts:
        return children_texts[0].strip() if children_texts[0].strip().isidentifier() else None
    return None


def _extract_class_name(
    raw_type: str,
    node_text: str,
    language: Language,
    children_texts: list[str],
) -> str | None:
    import re
    patterns: list[str] = {
        Language.PYTHON:     [r"class\s+(\w+)"],
        Language.JAVA:       [r"(?:class|interface|enum)\s+(\w+)"],
        Language.JAVASCRIPT: [r"class\s+(\w+)"],
        Language.RUST:       [r"(?:struct|impl|trait|enum)\s+(\w+)"],
        Language.GO:         [r"type\s+(\w+)"],
    }.get(language, [])

    for pattern in patterns:
        m = re.search(pattern, node_text)
        if m:
            return m.group(1)
    return None


def _extract_call_name(
    raw_type: str,
    node_text: str,
    language: Language,
    children_texts: list[str],
) -> str | None:
    """
    Extract the callee name from a call expression.
    Preserves dotted names (e.g. os.system, cursor.execute) for sink matching.
    """
    import re
    # Grab everything before the first '(' 
    m = re.match(r"^([\w.]+)\s*\(", node_text.strip())
    if m:
        return m.group(1)
    # For method calls: obj.method(...)
    m = re.match(r"^([\w.]+)", node_text.strip())
    if m:
        candidate = m.group(1)
        if "." in candidate or candidate.isidentifier():
            return candidate
    return None


def _extract_assign_target(node_text: str, language: Language) -> str | None:
    import re
    # "x = ..." → "x"; "x: int = ..." → "x"
    m = re.match(r"^\s*([\w.]+)\s*(?::\s*\w+\s*)?(?:\+|-|\*|/|%|&|\||\^|<<|>>)?=", node_text)
    if m:
        return m.group(1)
    return None


def _extract_hcl_block_name(node_text: str) -> str | None:
    """Extract Terraform resource / provider name from block header text."""
    import re
    # resource "aws_instance" "web" { → aws_instance.web
    m = re.match(r'(?:resource|provider|variable|data|module)\s+"([^"]+)"\s*(?:"([^"]+)")?', node_text)
    if m:
        parts = [p for p in m.groups() if p]
        return ".".join(parts)
    return None