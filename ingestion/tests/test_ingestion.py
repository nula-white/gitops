"""
PRISM Ingestion Layer Tests
============================
Tests every security guarantee of the ingestion pipeline.
All tests run without network access or real credentials.

Tests are organized by component:
  1. SecureString — memory zeroing
  2. Provider strategies — correct auth headers per host
  3. Request validation — SSRF, injection, malformed inputs
  4. Integrity verifier — commit pinning, symlink escape, manifest
  5. Sandbox delivery — file copy, permissions, manifest write
  6. Pipeline integration — full end-to-end with mocked Git client
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
os.environ["PRISM_ENV"] = "test"

# ── Imports ───────────────────────────────────────────────────────────────────
from ..credential_provider import (
    EnvCredentialProvider, SecureString,
)
from ..integrity_verifier  import IntegrityVerifier
from ..models              import (
    AuthMethod, FileEntry, GitProvider, IngestionRequest,
    IngestionStatus, RepoManifest,
)
from ..pipeline            import run_ingestion
from ..validators          import check_ssrf as _check_ssrf, is_safe_ref as _is_safe_ref, validate_request as _validate_request
from ..providers           import (
    AzureDevOpsStrategy, BitbucketStrategy, GenericStrategy,
    GitHubStrategy, GitLabStrategy, ProviderRegistry,
)
from ..sandbox_delivery    import SandboxDelivery

passed = 0
failed = 0

def check(name: str, condition: bool, detail: str = "") -> None:
    global passed, failed
    if condition:
        print(f"  ✓ {name}")
        passed += 1
    else:
        msg = f"  ✗ FAIL: {name}"
        if detail:
            msg += f"\n         {detail}"
        print(msg)
        failed += 1


# 1. SecureString — credential memory management
print("\n=== 1. SecureString — Credential Memory Management ===")

# Test: basic get and zero
s = SecureString("ghp_testtoken123")
check("SecureString.get() returns value", s.get() == "ghp_testtoken123")
s.zero()
check("SecureString.is_valid False after zero", not s.is_valid)
try:
    s.get()
    check("get() raises after zero", False, "Should have raised CredentialExpiredError")
except Exception:
    check("get() raises after zero", True)

# Test: context manager zeroes automatically
with SecureString("ghp_another") as cred:
    val = cred.get()
    check("Context manager: get() works inside block", val == "ghp_another")
check("Context manager: zeroed after exit", not cred.is_valid)

# Test: repr/str never expose the value
s2 = SecureString("super_secret_token_xyz")
check("repr does not expose value", "super_secret_token_xyz" not in repr(s2))
check("str does not expose value",  "super_secret_token_xyz" not in str(s2))
check("repr returns [REDACTED]", "[REDACTED]" in repr(s2))
s2.zero()

# Test: zero overwrites buffer bytes
s3 = SecureString("password123")
s3.zero()
check("Buffer zeroed after zero()", all(b == 0 for b in s3._buf))


# 2. Provider Strategies — correct auth headers
print("\n=== 2. Provider Strategies — Auth Header Construction ===")

token = "test_token_abc123"

# GitHub
gh = GitHubStrategy()
check("GitHub matches github.com", gh.matches("https://github.com/org/repo"))
check("GitHub does not match gitlab", not gh.matches("https://gitlab.com/org/repo"))
auth = gh.build_auth_header(token)
check("GitHub uses Bearer scheme",  auth.value == f"Bearer {token}")
check("GitHub username is x-access-token", auth.username == "x-access-token")
check("GitHub password is raw token", auth.password == token)

# GitLab
gl = GitLabStrategy()
check("GitLab matches gitlab.com", gl.matches("https://gitlab.com/org/repo"))
check("GitLab matches self-hosted", gl.matches("https://gitlab.mycompany.com/org/repo"))
auth = gl.build_auth_header(token)
check("GitLab uses Bearer scheme", auth.value == f"Bearer {token}")
check("GitLab username is oauth2", auth.username == "oauth2")

# Bitbucket
bb = BitbucketStrategy()
check("Bitbucket matches bitbucket.org", bb.matches("https://bitbucket.org/org/repo"))
auth = bb.build_auth_header(token)
check("Bitbucket uses x-token-auth username", auth.username == "x-token-auth")

# Azure DevOps
ado = AzureDevOpsStrategy()
check("ADO matches dev.azure.com", ado.matches("https://dev.azure.com/org/repo"))
check("ADO matches visualstudio.com", ado.matches("https://myorg.visualstudio.com/repo"))
auth = ado.build_auth_header(token)
import base64
expected = "Basic " + base64.b64encode(f":{token}".encode()).decode()
check("ADO uses empty-username Basic auth", auth.value == expected)
check("ADO username is empty string", auth.username == "")

# Generic
gen = GenericStrategy()
check("Generic matches any URL", gen.matches("https://gitea.myserver.io/org/repo"))
auth = gen.build_auth_header(token)
check("Generic uses token scheme", auth.value == f"token {token}")

# Registry detection
registry = ProviderRegistry()
check("Registry selects GitHub for github.com",
    registry.get_strategy("https://github.com/o/r").provider_type() == GitProvider.GITHUB)
check("Registry selects GitLab for gitlab.com",
    registry.get_strategy("https://gitlab.com/o/r").provider_type() == GitProvider.GITLAB)
check("Registry selects ADO for dev.azure.com",
    registry.get_strategy("https://dev.azure.com/o/r").provider_type() == GitProvider.AZURE_DEVOPS)
check("Registry selects Generic for unknown host",
    registry.get_strategy("https://custom.git.host/o/r").provider_type() == GitProvider.GENERIC)

# URL normalization — strips embedded credentials
gh_norm = gh.normalize_url("https://github.com/org/repo")
check("normalize_url: clean URL unchanged", "github.com/org/repo" in gh_norm)
try:
    gh.normalize_url("git://github.com/org/repo")
    check("normalize_url rejects git:// scheme", False)
except ValueError:
    check("normalize_url rejects git:// scheme", True)
try:
    gh.normalize_url("ssh://git@github.com/org/repo")
    check("normalize_url rejects ssh:// scheme", False)
except ValueError:
    check("normalize_url rejects ssh:// scheme", True)


# 3. Request Validation — SSRF, injection, malformed input
print("\n=== 3. Request Validation — SSRF & Input Safety ===")

def make_request(**kwargs) -> IngestionRequest:
    defaults = dict(
        repo_url="https://github.com/org/repo",
        provider=GitProvider.GITHUB,
        branch="main",
        credential_ref="github/org/repo",
        session_id="test_session",
    )
    defaults.update(kwargs)
    return IngestionRequest(**defaults)

# Valid request
check("Valid request passes", _validate_request(make_request()) is None)

# SSRF checks
check("SSRF: localhost blocked",
    _check_ssrf("localhost") is not None)
check("SSRF: 127.0.0.1 blocked",
    _check_ssrf("127.0.0.1") is not None)
check("SSRF: 10.0.0.1 blocked (private)",
    _check_ssrf("10.0.0.1") is not None)
check("SSRF: 192.168.1.1 blocked (private)",
    _check_ssrf("192.168.1.1") is not None)
check("SSRF: 172.16.0.1 blocked (private)",
    _check_ssrf("172.16.0.1") is not None)
check("SSRF: 169.254.169.254 blocked (AWS metadata)",
    _check_ssrf("169.254.169.254") is not None)
check("SSRF: ::1 blocked (IPv6 loopback)",
    _check_ssrf("::1") is not None)
check("SSRF: github.com allowed",
    _check_ssrf("github.com") is None)
check("SSRF: 8.8.8.8 allowed (public IP)",
    _check_ssrf("8.8.8.8") is None)

# Embedded credentials in URL
err = _validate_request(make_request(repo_url="https://user:token@github.com/org/repo"))
check("Embedded credentials in URL rejected", err is not None)
check("Embedded creds error mentions credential_ref",
    err is not None and "credential_ref" in err)

# HTTP scheme rejected
err = _validate_request(make_request(repo_url="http://github.com/org/repo"))
check("HTTP (non-TLS) URL rejected", err is not None)

# SSH URL rejected
err = _validate_request(make_request(repo_url="git@github.com:org/repo.git"))
check("SSH URL rejected", err is not None)

# Branch injection attempts
check("Branch with semicolon rejected",       not _is_safe_ref("main;evil"))
check("Branch with backtick rejected",        not _is_safe_ref("main`id`"))
check("Branch with dollar sign rejected",     not _is_safe_ref("main$(evil)"))
check("Branch with pipe rejected",            not _is_safe_ref("main|evil"))
check("Valid branch name accepted",           _is_safe_ref("feature/my-branch_v2.0"))
check("Branch with slash accepted",          _is_safe_ref("refs/heads/main"))

# Commit SHA validation
err = _validate_request(make_request(commit_sha="abc1234"))
check("Short (7-char) commit SHA accepted", err is None)
err = _validate_request(make_request(commit_sha="abc12"))  # too short
check("5-char commit SHA rejected", err is not None)
err = _validate_request(make_request(commit_sha="xyz!@#$"))  # non-hex
check("Non-hex commit SHA rejected", err is not None)
err = _validate_request(make_request(commit_sha="a" * 40))  # full SHA
check("40-char commit SHA accepted", err is None)

# Missing credential ref
err = _validate_request(make_request(credential_ref=""))
check("Empty credential_ref rejected", err is not None)

# URL too long
err = _validate_request(make_request(repo_url="https://github.com/" + "a" * 500))
check("Oversized URL rejected", err is not None)


# 4. Integrity Verifier — symlink escape, commit pinning, manifest
print("\n=== 4. Integrity Verifier — Commit Pinning & Symlink Safety ===")

verifier = IntegrityVerifier()

# Setup: create a temp repo with real files
with tempfile.TemporaryDirectory() as tmpdir:
    # Create some source files
    (Path(tmpdir) / "src").mkdir()
    (Path(tmpdir) / "src" / "main.py").write_text("def hello(): pass\n")
    (Path(tmpdir) / "src" / "utils.py").write_text("import os\n")
    (Path(tmpdir) / "README.md").write_text("# Test repo\n")
    (Path(tmpdir) / ".git").mkdir()
    (Path(tmpdir) / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    refs_dir = Path(tmpdir) / ".git" / "refs" / "heads"
    refs_dir.mkdir(parents=True)
    fake_commit = "a" * 40
    (refs_dir / "main").write_text(fake_commit + "\n")

    req = make_request(session_id="test_verify")
    result = verifier.verify(tmpdir, fake_commit, req)

    check("Verification passes for clean repo", result.passed)
    check("Manifest is created", result.manifest is not None)
    check("Manifest is sealed", result.manifest._sealed)
    check("repo_hash is 64-char hex",
        len(result.manifest.repo_hash) == 64 and
        all(c in "0123456789abcdef" for c in result.manifest.repo_hash))
    check("Files in manifest",
        any("main.py" in f.relative_path for f in result.manifest.files))
    check(".git directory excluded from manifest",
        not any(".git" in f.relative_path for f in result.manifest.files))
    check("Each file has SHA-256 hash",
        all(len(f.sha256) == 64 for f in result.manifest.files))

    # Test determinism — same repo should produce same repo_hash
    result2 = verifier.verify(tmpdir, fake_commit, req)
    check("repo_hash is deterministic",
        result.manifest.repo_hash == result2.manifest.repo_hash)

# Test: commit pinning mismatch
with tempfile.TemporaryDirectory() as tmpdir:
    (Path(tmpdir) / "file.py").write_text("x=1\n")
    (Path(tmpdir) / ".git").mkdir()
    (Path(tmpdir) / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    refs_dir = Path(tmpdir) / ".git" / "refs" / "heads"
    refs_dir.mkdir(parents=True)
    (refs_dir / "main").write_text("b" * 40 + "\n")

    req_pinned = make_request(commit_sha="a" * 40, session_id="pin_test")
    result = verifier.verify(tmpdir, "b" * 40, req_pinned)
    check("Commit mismatch causes verification failure", not result.passed)
    check("Error message mentions tampering",
        result.error is not None and "tamper" in result.error.lower())

# Test: symlink escape detection
with tempfile.TemporaryDirectory() as tmpdir:
    # Create a safe file
    (Path(tmpdir) / "safe.py").write_text("x=1\n")
    # Create a malicious symlink pointing outside the repo
    evil_link = Path(tmpdir) / "evil_link.py"
    try:
        evil_link.symlink_to("/etc/passwd")
        escape = verifier._check_symlink_escape(evil_link, Path(tmpdir))
        check("Symlink to /etc/passwd detected as escape", escape is not None)
        check("Escaped path is reported", "/etc/passwd" in (escape or ""))
    except OSError:
        check("Symlink escape test skipped (OS restriction)", True)

# Test: safe internal symlink is allowed
with tempfile.TemporaryDirectory() as tmpdir:
    target = Path(tmpdir) / "real_file.py"
    target.write_text("x=1\n")
    safe_link = Path(tmpdir) / "link.py"
    try:
        safe_link.symlink_to(target)
        escape = verifier._check_symlink_escape(safe_link, Path(tmpdir))
        check("Internal symlink not flagged as escape", escape is None)
    except OSError:
        check("Internal symlink test skipped", True)

# Test: repo_hash changes when file content changes
with tempfile.TemporaryDirectory() as tmpdir:
    (Path(tmpdir) / "main.py").write_text("def a(): pass\n")
    r1 = verifier.verify(tmpdir, "a"*40, make_request(session_id="s1"))

    (Path(tmpdir) / "main.py").write_text("def a(): eval(input())\n")  # modified
    r2 = verifier.verify(tmpdir, "a"*40, make_request(session_id="s2"))

    check("repo_hash changes when file content changes",
        r1.manifest.repo_hash != r2.manifest.repo_hash)


# 5. Sandbox Delivery — file permissions, copy integrity
print("\n=== 5. Sandbox Delivery — File Permissions & Integrity ===")

delivery = SandboxDelivery()

with tempfile.TemporaryDirectory() as src_dir, \
     tempfile.TemporaryDirectory() as dst_dir:

    # Create source files
    src = Path(src_dir)
    (src / "app.py").write_text("def main(): pass\n")
    (src / "config.yaml").write_text("key: value\n")
    subdir = src / "lib"
    subdir.mkdir()
    (subdir / "utils.py").write_text("import os\n")

    # Build a manifest matching the source files
    manifest = RepoManifest(
        session_id="delivery_test",
        repo_url="https://github.com/org/repo",
        provider="github",
        branch="main",
        fetched_commit="a" * 40,
        fetch_timestamp="2024-01-01T00:00:00+00:00",
    )
    for rel_path in ["app.py", "config.yaml", "lib/utils.py"]:
        abs_p = src / rel_path.replace("/", os.sep)
        content = abs_p.read_bytes()
        manifest.add_file(FileEntry(
            relative_path=rel_path,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
            is_binary=False,
        ))
    manifest.seal()

    # Patch PATH_POLICY to accept our temp dirs
    req = make_request(output_dir=dst_dir, session_id="delivery_test")
    with patch("prism.ingestion.sandbox_delivery.PATH_POLICY") as mock_policy:
        mock_policy.validate_work_path.return_value = Path(dst_dir)
        mock_policy.validate_repo_path.return_value = Path(dst_dir)

        result = delivery.deliver(src_dir, manifest, req)

    check("Delivery succeeds", result.success, result.error or "")
    check("Correct number of files written",
        result.files_written == 3)

    # Check files exist and have correct content
    dst = Path(dst_dir)
    check("app.py delivered", (dst / "app.py").exists())
    check("lib/utils.py delivered", (dst / "lib" / "utils.py").exists())

    # Check manifest file written
    manifest_file = dst / ".prism_manifest.json"
    check("Manifest file written", manifest_file.exists())
    manifest_data = json.loads(manifest_file.read_text())
    check("Manifest has repo_hash", "repo_hash" in manifest_data)
    check("Manifest repo_hash matches", manifest_data["repo_hash"] == manifest.repo_hash)

    # Check read-only permissions on delivered files
    app_py_mode = (dst / "app.py").stat().st_mode
    check("Delivered files are read-only (no write bits)",
        not (app_py_mode & stat.S_IWUSR) and
        not (app_py_mode & stat.S_IWGRP) and
        not (app_py_mode & stat.S_IWOTH))


# 6. Pipeline Integration — end-to-end with mocked Git client
print("\n=== 6. Pipeline Integration — End-to-End ===")

from ..git_client import GitFetchResult

# Create a real temporary repo for end-to-end test
with tempfile.TemporaryDirectory() as fake_repo, \
     tempfile.TemporaryDirectory() as sandbox_out:

    # Populate the fake fetched repo
    (Path(fake_repo) / "src").mkdir()
    (Path(fake_repo) / "src" / "app.py").write_text(
        "import os\ndef run(cmd): os.system(cmd)\n"
    )
    (Path(fake_repo) / ".git").mkdir()
    (Path(fake_repo) / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    refs = Path(fake_repo) / ".git" / "refs" / "heads"
    refs.mkdir(parents=True)
    test_commit = "deadbeef" + "0" * 32
    (refs / "main").write_text(test_commit + "\n")

    # Mock GitClient to return our fake_repo dir
    mock_client = MagicMock()
    mock_client.fetch.return_value = GitFetchResult(
        success=True,
        local_path=fake_repo,
        fetched_commit=test_commit,
        backend_used="mock",
        duration_ms=5.0,
    )

    # Mock credential provider
    mock_creds = MagicMock()
    mock_creds.get_credential.return_value = SecureString("ghp_test_token")

    # Patch PATH_POLICY and tempfile.mkdtemp to use our dirs
    with patch("prism.ingestion.pipeline.tempfile.mkdtemp", return_value=fake_repo), \
         patch("prism.ingestion.sandbox_delivery.PATH_POLICY") as mock_path:

        mock_path.validate_work_path.return_value  = Path(sandbox_out)
        mock_path.validate_repo_path.return_value = Path(fake_repo)

        result = run_ingestion(
            IngestionRequest(
                repo_url="https://github.com/testorg/testrepo",
                provider=GitProvider.GITHUB,
                branch="main",
                commit_sha=test_commit,
                credential_ref="github/testorg/testrepo",
                output_dir=sandbox_out,
                session_id="e2e_test",
            ),
            credential_provider=mock_creds,
            git_client=mock_client,
        )

    check("E2E pipeline succeeds", result.succeeded, result.error or "")
    check("E2E result has manifest", result.manifest is not None)
    if result.manifest:
        check("E2E manifest has repo_hash", len(result.manifest.repo_hash) == 64)
        check("E2E manifest files not empty", result.manifest.total_files > 0)

    # Test SSRF rejection without mocking
    result_ssrf = run_ingestion(
        IngestionRequest(
            repo_url="https://169.254.169.254/latest/meta-data/",
            provider=GitProvider.GENERIC,
            branch="main",
            credential_ref="some/cred",
            session_id="ssrf_test",
        ),
        credential_provider=mock_creds,
    )
    check("SSRF attempt rejected before network call",
        result_ssrf.status == IngestionStatus.FAILED)
    check("SSRF error message is informative",
        result_ssrf.error is not None and "SSRF" in result_ssrf.error)

    # Test branch injection rejected
    result_inj = run_ingestion(
        IngestionRequest(
            repo_url="https://github.com/org/repo",
            provider=GitProvider.GITHUB,
            branch="main;rm -rf /",
            credential_ref="some/cred",
            session_id="inject_test",
        ),
        credential_provider=mock_creds,
    )
    check("Branch injection rejected",
        result_inj.status == IngestionStatus.FAILED)


# Summary
print(f"\n{'='*60}")
print(f"Ingestion Layer Tests: {passed} passed, {failed} failed")
if failed:
    print("FAILURES DETECTED")
    sys.exit(1)
else:
    print("All ingestion tests passed ✓")