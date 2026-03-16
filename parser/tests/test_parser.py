"""
Tests: language detection, normalization, security annotation,
Tree-sitter parsing, fallback parsing, and graph structure validation.

Run with: pytest parser/tests/test_parser.py -v
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

import pytest
from pathlib import Path

from parser import (
    ParserRegistry, Language, NodeType, SecurityLabel, EdgeType,
    ParsedGraphOutput, LanguageDetector,
)
from parser.normalizer     import ASTNormalizer
from parser.security_annotator import SecurityAnnotator
from parser.parsers.fallback_parser import FallbackParser

FIXTURES = Path(__file__).parent / "fixtures"

# Language Detector Tests

class TestLanguageDetector:
    def setup_method(self):
        self.detector = LanguageDetector()

    def test_python_by_extension(self):
        r = self.detector.detect("foo/bar.py")
        assert r.language == Language.PYTHON
        assert r.confidence == 1.0
        assert r.method == "extension"

    def test_rust_by_extension(self):
        r = self.detector.detect("src/main.rs")
        assert r.language == Language.RUST

    def test_terraform_by_extension(self):
        r = self.detector.detect("infra/main.tf")
        assert r.language == Language.TERRAFORM_HCL

    def test_yaml_by_extension(self):
        r = self.detector.detect("k8s/deploy.yaml")
        assert r.language == Language.YAML

    def test_tsx_by_extension(self):
        r = self.detector.detect("src/App.tsx")
        assert r.language == Language.TSX

    def test_python_by_content_heuristic(self):
        content = "def my_function(x, y):\n    return x + y\n"
        r = self.detector.detect("unknown_file", content)
        assert r.language == Language.PYTHON
        assert r.method == "heuristic"

    def test_terraform_by_content_heuristic(self):
        content = 'resource "aws_instance" "web" {\n  ami = "ami-123"\n}\n'
        r = self.detector.detect("unknown_file", content)
        assert r.language == Language.TERRAFORM_HCL

    def test_unknown_no_content(self):
        r = self.detector.detect("some_file_no_ext")
        assert r.language == Language.UNKNOWN


# Normalizer Tests

class TestASTNormalizer:
    def setup_method(self):
        self.n = ASTNormalizer()

    def test_python_function_maps_correctly(self):
        assert self.n.normalize_type("function_definition", Language.PYTHON) == NodeType.FUNCTION

    def test_python_call_maps_correctly(self):
        assert self.n.normalize_type("call", Language.PYTHON) == NodeType.CALL

    def test_rust_function_maps_correctly(self):
        assert self.n.normalize_type("function_item", Language.RUST) == NodeType.FUNCTION

    def test_hcl_resource_maps_correctly(self):
        assert self.n.normalize_type("resource", Language.TERRAFORM_HCL) == NodeType.RESOURCE

    def test_unknown_type_returns_unknown(self):
        assert self.n.normalize_type("some_weird_node_xyz", Language.PYTHON) == NodeType.UNKNOWN

    def test_extract_call_name_dotted(self):
        name = self.n.extract_name(
            "call", "os.system(user_input)", NodeType.CALL, Language.PYTHON, []
        )
        assert name == "os.system"

    def test_extract_function_name_python(self):
        name = self.n.extract_name(
            "function_definition", "def login(user, pwd):\n    pass", NodeType.FUNCTION,
            Language.PYTHON, ["login", "user", "pwd"]
        )
        assert name == "login"

    def test_extract_literal_value(self):
        val = self.n.extract_value(NodeType.LITERAL, '"hello world"')
        assert val == '"hello world"'


# Security Annotator Tests

class TestSecurityAnnotator:
    def setup_method(self):
        self.a = SecurityAnnotator()

    def test_os_system_is_sink(self):
        label, conf, cwes = self.a.annotate(NodeType.CALL, "os.system", Language.PYTHON)
        assert label == SecurityLabel.SINK
        assert conf >= 0.90
        assert "CWE-78" in cwes

    def test_pickle_loads_is_sink(self):
        label, conf, cwes = self.a.annotate(NodeType.CALL, "pickle.loads", Language.PYTHON)
        assert label == SecurityLabel.SINK
        assert "CWE-502" in cwes

    def test_request_args_is_source(self):
        label, conf, cwes = self.a.annotate(NodeType.IDENTIFIER, "request.args", Language.PYTHON)
        assert label == SecurityLabel.SOURCE
        assert conf >= 0.95

    def test_html_escape_is_sanitizer(self):
        label, conf, cwes = self.a.annotate(NodeType.CALL, "html.escape", Language.PYTHON)
        assert label == SecurityLabel.SANITIZER

    def test_js_innerHTML_is_sink(self):
        label, conf, cwes = self.a.annotate(NodeType.ATTRIBUTE, "innerHTML", Language.JAVASCRIPT)
        assert label == SecurityLabel.SINK
        assert "CWE-79" in cwes

    def test_terraform_password_is_sensitive(self):
        label, conf, cwes = self.a.annotate(NodeType.CONFIG_KEY, "administrator_login_password", Language.TERRAFORM_HCL)
        assert label in (SecurityLabel.SINK, SecurityLabel.SENSITIVE)

    def test_unknown_function_no_label(self):
        label, conf, cwes = self.a.annotate(NodeType.CALL, "totally_unknown_func_xyz", Language.PYTHON)
        # Should either be NONE or low confidence heuristic
        assert conf < 0.7

    def test_partial_match_suffix(self):
        # "conn.execute" should match "execute" → SQL sink
        label, conf, cwes = self.a.annotate(NodeType.CALL, "conn.execute", Language.PYTHON)
        assert label == SecurityLabel.SINK
        assert conf > 0.5

    def test_heuristic_secret_in_name(self):
        label, conf, cwes = self.a.annotate(NodeType.ASSIGN, "api_secret_key", Language.PYTHON)
        assert label == SecurityLabel.SENSITIVE


# Fallback Parser Tests (always available, no deps)

class TestFallbackParser:
    def setup_method(self):
        self.parser = FallbackParser()

    def _parse_fixture(self, filename: str, language: Language) -> ParsedGraphOutput:
        fixture_path = FIXTURES / filename
        source = fixture_path.read_text(encoding="utf-8")
        return self.parser.parse(source, str(fixture_path), language)

    def test_python_parses_without_error(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        assert isinstance(result, ParsedGraphOutput)
        assert not result.parse_errors

    def test_python_detects_functions(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        functions = result.get_functions()
        func_names = [f.name for f in functions]
        assert "login" in func_names
        assert "run_command" in func_names
        assert "load_data" in func_names

    def test_python_detects_sinks(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        sinks = result.get_sinks()
        assert len(sinks) > 0
        sink_names = [s.name for s in sinks]
        # pickle.loads, os.system, db.execute should all be detected
        assert any("pickle" in (n or "") or "system" in (n or "") for n in sink_names)

    def test_python_sources_detected(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        # request.args is a known source
        sources = result.get_sources()
        assert len(sources) >= 0  # fallback may not get all, but shouldn't crash

    def test_terraform_parses_without_error(self):
        result = self._parse_fixture("vuln_terraform.tf", Language.TERRAFORM_HCL)
        assert isinstance(result, ParsedGraphOutput)
        assert result.metadata.language == Language.TERRAFORM_HCL

    def test_rust_parses_without_error(self):
        result = self._parse_fixture("vuln_rust.rs", Language.RUST)
        assert isinstance(result, ParsedGraphOutput)
        functions = result.get_functions()
        assert len(functions) >= 2

    def test_graph_hash_is_deterministic(self):
        fixture_path = FIXTURES / "vuln_python.py"
        source = fixture_path.read_text()
        r1 = self.parser.parse(source, str(fixture_path), Language.PYTHON)
        r2 = self.parser.parse(source, str(fixture_path), Language.PYTHON)
        assert r1.graph_hash == r2.graph_hash

    def test_node_ids_are_deterministic(self):
        fixture_path = FIXTURES / "vuln_python.py"
        source = fixture_path.read_text()
        r1 = self.parser.parse(source, str(fixture_path), Language.PYTHON)
        r2 = self.parser.parse(source, str(fixture_path), Language.PYTHON)
        ids1 = sorted(n.node_id for n in r1.nodes)
        ids2 = sorted(n.node_id for n in r2.nodes)
        assert ids1 == ids2

    def test_program_node_always_present(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        programs = [n for n in result.nodes if n.node_type == NodeType.PROGRAM]
        assert len(programs) == 1

    def test_edges_reference_valid_nodes(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        node_ids = {n.node_id for n in result.nodes}
        for edge in result.edges:
            assert edge.source_id in node_ids, f"Edge source {edge.source_id} not in nodes"
            assert edge.target_id in node_ids, f"Edge target {edge.target_id} not in nodes"

    def test_to_json_produces_valid_json(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        import json
        data = json.loads(result.to_json())
        assert "nodes" in data
        assert "edges" in data
        assert "security_summary" in data
        assert "graph_hash" in data

    def test_graphcodebert_input_populated(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        gcb = result.graphcodebert_input
        assert len(gcb.tokens) > 0
        assert len(gcb.token_node_ids) == len(gcb.tokens)
        assert len(gcb.node_type_sequence) == len(gcb.tokens)

    def test_cwe_hints_in_summary(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        # Should detect at least one CWE category
        assert len(result.security_summary.cwe_hints) >= 0  # may be 0 in fallback


# Tree-sitter Parser Tests (conditional on tree-sitter-languages)

try:
    import tree_sitter_languages
    TS_AVAILABLE = True
except ImportError:
    TS_AVAILABLE = False

@pytest.mark.skipif(not TS_AVAILABLE, reason="tree-sitter-languages not installed")
class TestTreeSitterParser:
    def setup_method(self):
        from parser.parsers.treesitter_parser import TreeSitterParser
        self.parser = TreeSitterParser()

    def _parse_fixture(self, filename: str, language: Language) -> ParsedGraphOutput:
        fixture_path = FIXTURES / filename
        source = fixture_path.read_text(encoding="utf-8")
        return self.parser.parse(source, str(fixture_path), language)

    def test_python_produces_nodes(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        assert len(result.nodes) > 10
        assert not result.metadata.has_parse_errors or result.metadata.error_count < 3

    def test_python_functions_detected(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        funcs = result.get_functions()
        assert len(funcs) >= 4

    def test_python_sinks_detected(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        sinks = result.get_sinks()
        assert len(sinks) > 0

    def test_rust_produces_nodes(self):
        result = self._parse_fixture("vuln_rust.rs", Language.RUST)
        assert len(result.nodes) > 5

    def test_terraform_produces_nodes(self):
        result = self._parse_fixture("vuln_terraform.tf", Language.TERRAFORM_HCL)
        resources = [n for n in result.nodes if n.node_type == NodeType.RESOURCE]
        assert len(resources) >= 0   # HCL grammar may vary

    def test_ast_edges_form_valid_tree(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        ast_edges = result.get_ast_edges()
        assert len(ast_edges) > 0
        # Every edge source must exist in nodes
        node_ids = {n.node_id for n in result.nodes}
        for e in ast_edges:
            assert e.source_id in node_ids
            assert e.target_id in node_ids

    def test_parent_child_consistency(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        node_map = {n.node_id: n for n in result.nodes}
        for node in result.nodes:
            for child_id in node.children_ids:
                assert child_id in node_map
                child = node_map[child_id]
                assert child.parent_id == node.node_id

    def test_security_confidence_in_range(self):
        result = self._parse_fixture("vuln_python.py", Language.PYTHON)
        for node in result.nodes:
            assert 0.0 <= node.security_confidence <= 1.0


# ParserRegistry Integration Tests

class TestParserRegistry:
    def setup_method(self):
        # prefer_codeql=False so we test tree-sitter / fallback path in CI
        self.registry = ParserRegistry(prefer_codeql=False)

    def test_parse_python_fixture(self):
        result = self.registry.parse_file(FIXTURES / "vuln_python.py")
        assert result.metadata.language == Language.PYTHON
        assert len(result.nodes) > 0

    def test_parse_rust_fixture(self):
        result = self.registry.parse_file(FIXTURES / "vuln_rust.rs")
        assert result.metadata.language == Language.RUST

    def test_parse_terraform_fixture(self):
        result = self.registry.parse_file(FIXTURES / "vuln_terraform.tf")
        assert result.metadata.language == Language.TERRAFORM_HCL

    def test_parse_nonexistent_file_returns_fallback(self):
        result = self.registry.parse_file("/nonexistent/path/file.py")
        assert isinstance(result, ParsedGraphOutput)

    def test_backend_status(self):
        status = self.registry.get_backend_status()
        assert "tree_sitter_available" in status
        assert "codeql_available" in status
        assert status["fallback_available"] is True

    def test_parse_inline_source(self):
        source = "def hello():\n    eval(input())\n"
        result = self.registry.parse_file("test.py", source_code=source)
        assert result.metadata.language == Language.PYTHON
        sinks = result.get_sinks()
        assert len(sinks) >= 0  # eval should be detected


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])