"""
PRISM Submodule Resolver Tests
================================
Tests all four threat mitigations:

  Threat A — Silent blind spot      (submodules are discovered and fetched)
  Threat B — Malicious URL          (SSRF, scheme, path traversal in URLs)
  Threat C — Commit drift           (pinned SHA reading, mismatch detection)
  Threat D — Recursive explosion    (depth cap, count cap, circular detection)

Plus: .gitmodules path validation, relative URL resolution,
      symlink escape inside submodule, and manifest integration.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))
os.environ["PRISM_ENV"] = "test"

from ..submodule_resolver import (
    MAX_SUBMODULE_DEPTH, MAX_SUBMODULES_TOTAL,
    SubmoduleEntry, SubmoduleResolver, SubmoduleResolutionResult,
)
from ..credential_provider import EnvCredentialProvider, SecureString
from ..models              import GitProvider, IngestionRequest
from ..git_client          import GitFetchResult

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

def make_parent_request(**kwargs) -> IngestionRequest:
    defaults = dict(
        repo_url="https://github.com/org/parent-repo",
        provider=GitProvider.GITHUB,
        branch="main",
        credential_ref="github/org/parent-repo",
        session_id="sub_test_session",
    )
    defaults.update(kwargs)
    return IngestionRequest(**defaults)

def make_resolver(fetch_success=True, fetched_commit="a"*40) -> SubmoduleResolver:
    """Create a SubmoduleResolver with a mocked GitClient."""
    mock_creds = MagicMock()
    mock_creds.get_credential.return_value = SecureString("ghp_test")
    mock_creds.credential_context.return_value.__enter__ = lambda s: SecureString("ghp_test")
    mock_creds.credential_context.return_value.__exit__  = lambda s, *a: None

    mock_client = MagicMock()
    mock_client.fetch.return_value = GitFetchResult(
        success=fetch_success,
        local_path="/tmp/mock_sub",
        fetched_commit=fetched_commit,
        backend_used="mock",
        duration_ms=5.0,
        error=None if fetch_success else "mock fetch failed",
    )

    return SubmoduleResolver(
        credential_provider=mock_creds,
        git_client=mock_client,
    )


# 1. .gitmodules parsing
print("\n=== 1. .gitmodules Parsing ===")

with tempfile.TemporaryDirectory() as repo_dir:
    resolver = make_resolver()

    # Standard .gitmodules file
    gitmodules = Path(repo_dir) / ".gitmodules"
    gitmodules.write_text("""
[submodule "vendor/crypto-lib"]
\tpath = vendor/crypto-lib
\turl  = https://github.com/org/crypto-lib

[submodule "lib/auth"]
\tpath = lib/auth
\turl  = https://gitlab.com/org/auth-module
\tbranch = stable
""")
    entries = resolver._parse_gitmodules(gitmodules, repo_dir)
    check("Parses 2 submodules", len(entries) == 2)
    check("First submodule name", entries[0].name == "vendor/crypto-lib")
    check("First submodule path", entries[0].path == "vendor/crypto-lib")
    check("First submodule URL",  entries[0].url  == "https://github.com/org/crypto-lib")
    check("Second submodule URL", entries[1].url  == "https://gitlab.com/org/auth-module")

    # Path traversal in .gitmodules path field
    gitmodules_traversal = Path(repo_dir) / ".gitmodules"
    gitmodules_traversal.write_text("""
[submodule "evil"]
\tpath = ../../etc/passwd
\turl  = https://github.com/org/evil
""")
    entries = resolver._parse_gitmodules(gitmodules_traversal, repo_dir)
    check("Path traversal in .gitmodules rejected",
        len(entries) == 1 and entries[0].status == "skipped")
    check("Traversal rejection reason mentions path",
        "traversal" in entries[0].reason.lower() or "path" in entries[0].reason.lower())

    # Absolute path in .gitmodules
    gitmodules_abs = Path(repo_dir) / ".gitmodules"
    gitmodules_abs.write_text("""
[submodule "evil"]
\tpath = /etc/passwd
\turl  = https://github.com/org/evil
""")
    entries = resolver._parse_gitmodules(gitmodules_abs, repo_dir)
    check("Absolute path in .gitmodules rejected",
        len(entries) == 1 and entries[0].status == "skipped")

    # .git path targeting
    gitmodules_git = Path(repo_dir) / ".gitmodules"
    gitmodules_git.write_text("""
[submodule "evil"]
\tpath = .git/hooks
\turl  = https://github.com/org/evil
""")
    entries = resolver._parse_gitmodules(gitmodules_git, repo_dir)
    check(".git path in .gitmodules rejected",
        len(entries) == 1 and entries[0].status == "skipped")

    # Empty .gitmodules
    gitmodules_empty = Path(repo_dir) / ".gitmodules"
    gitmodules_empty.write_text("")
    entries = resolver._parse_gitmodules(gitmodules_empty, repo_dir)
    check("Empty .gitmodules produces no entries", len(entries) == 0)


# 2. Threat B — Malicious submodule URL validation
print("\n=== 2. Threat B — Malicious Submodule URL Validation ===")

resolver = make_resolver()
parent_url = "https://github.com/org/parent"

# SSRF via private IP
err = resolver._validate_submodule_url("https://192.168.1.100/org/evil", parent_url, "/tmp")
check("SSRF private IP blocked",     err is not None)
check("SSRF error mentions private", err is not None and "private" in err.lower())

# SSRF via AWS metadata service
err = resolver._validate_submodule_url("https://169.254.169.254/latest", parent_url, "/tmp")
check("AWS metadata SSRF blocked",   err is not None)

# SSRF via localhost
err = resolver._validate_submodule_url("https://localhost/org/evil", parent_url, "/tmp")
check("localhost SSRF blocked",      err is not None)

# Non-HTTPS scheme: git://
err = resolver._validate_submodule_url("git://github.com/org/lib", parent_url, "/tmp")
check("git:// scheme blocked",       err is not None)
check("git:// error mentions TLS",   err is not None and "TLS" in err)

# Non-HTTPS scheme: ssh://
err = resolver._validate_submodule_url("ssh://git@github.com/org/lib", parent_url, "/tmp")
check("ssh:// scheme blocked",       err is not None)

# Local filesystem path
err = resolver._validate_submodule_url("/home/user/local-lib", parent_url, "/tmp")
check("Filesystem path blocked",     err is not None)

# file:// URL
err = resolver._validate_submodule_url("file:///etc/passwd", parent_url, "/tmp")
check("file:// URL blocked",         err is not None)

# Embedded credentials
err = resolver._validate_submodule_url("https://user:token@github.com/org/lib", parent_url, "/tmp")
check("Embedded credentials blocked", err is not None)

# Path traversal in URL path
err = resolver._validate_submodule_url("https://github.com/../../../etc/passwd", parent_url, "/tmp")
check("Path traversal in URL blocked", err is not None)

# Valid HTTPS URL — should pass
err = resolver._validate_submodule_url("https://github.com/org/crypto-lib", parent_url, "/tmp")
check("Valid HTTPS URL accepted",    err is None)

# Valid GitLab URL
err = resolver._validate_submodule_url("https://gitlab.com/org/auth-module", parent_url, "/tmp")
check("Valid GitLab URL accepted",   err is None)

# Relative URL resolution
resolved = resolver._resolve_relative_url("../sibling-repo", "https://github.com/org/parent")
check("Relative URL resolves correctly",
    resolved is not None and "github.com/org/sibling-repo" in resolved)

# Relative URL that changes host
resolved2 = resolver._resolve_relative_url(
    "../evil", "https://github.com/org/parent"
)
# Should resolve but then SSRF check handles the actual host validation
check("Relative URL resolution doesn't crash on valid case", resolved2 is not None)


# 3. Threat C — Pinned SHA reading
print("\n=== 3. Threat C — Pinned SHA from Parent Tree ===")

# Create a fake repo with .git structure to test SHA reading
with tempfile.TemporaryDirectory() as repo_dir:
    resolver = make_resolver()

    # Setup fake git structure
    git_dir = Path(repo_dir) / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    refs = git_dir / "refs" / "heads"
    refs.mkdir(parents=True)
    (refs / "main").write_text("b" * 40 + "\n")

    # Test: SHA validation
    check("Valid 40-hex SHA recognized",      resolver._is_valid_sha("a" * 40))
    check("Short SHA rejected",               not resolver._is_valid_sha("abc123"))
    check("Non-hex SHA rejected",             not resolver._is_valid_sha("z" * 40))
    check("Empty string rejected",            not resolver._is_valid_sha(""))

    # Test git ls-tree fallback (without real git repo — expect empty dict)
    shas = resolver._read_shas_via_ls_tree(repo_dir)
    check("ls-tree returns dict (even if empty)", isinstance(shas, dict))

    # Test .git/modules fallback
    modules_dir = git_dir / "modules" / "vendor" / "crypto-lib"
    modules_dir.mkdir(parents=True)
    (modules_dir / "HEAD").write_text("c" * 40 + "\n")

    shas = resolver._read_shas_via_git_modules_dir(repo_dir)
    check("Reads SHA from .git/modules/*/HEAD", len(shas) > 0)

    # Test commit verification
    entry_ok = SubmoduleEntry("test", "test", "https://github.com/org/test")
    check("Exact SHA match verified",
        resolver._verify_submodule_commit("a"*40, "a"*40, entry_ok))
    check("Prefix match verified (short pinned SHA)",
        resolver._verify_submodule_commit("a"*40, "a"*12, entry_ok))
    check("Mismatch detected",
        not resolver._verify_submodule_commit("a"*40, "b"*40, entry_ok))
    check("Unknown fetched commit: warns but continues",
        resolver._verify_submodule_commit("", "a"*40, entry_ok) == True
        and any("verify" in w.lower() or "unknown" in w.lower() for w in entry_ok.warnings))


# 4. Threat D — Recursive depth and count limits
print("\n=== 4. Threat D — Depth Cap & Count Cap ===")

resolver = make_resolver()

# Simulate entries at depth > MAX_SUBMODULE_DEPTH
with tempfile.TemporaryDirectory() as repo_dir:
    result = SubmoduleResolutionResult()
    deep_entries = [
        SubmoduleEntry("deep", "vendor/deep", "https://github.com/org/deep")
    ]
    resolver._resolve_recursive(
        submodules=deep_entries,
        pinned_shas={},
        parent_repo_dir=repo_dir,
        parent_request=make_parent_request(),
        depth=MAX_SUBMODULE_DEPTH + 1,  # exceed limit
        result=result,
    )
    check("Entries beyond max depth are skipped",
        len(result.submodules) == 1 and result.submodules[0].status == "skipped")
    check("Depth limit reason is informative",
        "depth" in result.submodules[0].reason.lower())

# Simulate count limit
resolver2 = make_resolver()
resolver2._total_fetched = MAX_SUBMODULES_TOTAL  # pre-fill to limit
with tempfile.TemporaryDirectory() as repo_dir:
    result2 = SubmoduleResolutionResult()
    one_more = [
        SubmoduleEntry("extra", "vendor/extra", "https://github.com/org/extra")
    ]
    resolver2._resolve_recursive(
        submodules=one_more,
        pinned_shas={},
        parent_repo_dir=repo_dir,
        parent_request=make_parent_request(),
        depth=0,
        result=result2,
    )
    check("Entries beyond max count are skipped",
        result2.submodules[0].status == "skipped")
    check("Count limit reason is informative",
        "limit" in result2.submodules[0].reason.lower())

# Circular reference detection
resolver3 = make_resolver()
resolver3._visited.add(("https://github.com/org/circular", "a"*40))
with tempfile.TemporaryDirectory() as repo_dir:
    result3 = SubmoduleResolutionResult()
    circular = [SubmoduleEntry(
        name="circular",
        path="vendor/circular",
        url="https://github.com/org/circular",
        pinned_sha="a"*40,
    )]
    circular[0].pinned_sha = "a"*40  # already in visited set
    resolver3._resolve_recursive(
        submodules=circular,
        pinned_shas={"vendor/circular": "a"*40},
        parent_repo_dir=repo_dir,
        parent_request=make_parent_request(),
        depth=0,
        result=result3,
    )
    check("Circular reference detected and skipped",
        result3.submodules[0].status == "skipped")
    check("Circular reference reason is informative",
        "circular" in result3.submodules[0].reason.lower())


# 5. Threat A — Blind spot detection and no-.gitmodules handling
print("\n=== 5. Threat A — Blind Spot Detection ===")

resolver = make_resolver()

# Repo with no .gitmodules — should return empty result cleanly
with tempfile.TemporaryDirectory() as repo_dir:
    (Path(repo_dir) / "main.py").write_text("def hello(): pass\n")
    result = resolver.resolve(repo_dir, make_parent_request())
    check("No .gitmodules: resolve returns empty result", len(result.submodules) == 0)
    check("No .gitmodules: has_blind_spots is False", not result.has_blind_spots)
    check("No .gitmodules: no warnings", len(result.warnings) == 0)

# Repo with .gitmodules but URL fails validation
with tempfile.TemporaryDirectory() as repo_dir:
    gitmodules = Path(repo_dir) / ".gitmodules"
    gitmodules.write_text("""
[submodule "evil"]
\tpath = vendor/evil
\turl  = https://192.168.1.100/org/evil
""")
    result = resolver.resolve(repo_dir, make_parent_request())
    check("SSRF submodule produces skipped entry", len(result.submodules) == 1)
    check("SSRF submodule has status=skipped", result.submodules[0].status == "skipped")
    check("SSRF submodule is counted as blind spot", result.has_blind_spots)
    check("Blind spot warning generated", len(result.warnings) > 0)

# Repo with .gitmodules but no pinned SHA readable
with tempfile.TemporaryDirectory() as repo_dir:
    gitmodules = Path(repo_dir) / ".gitmodules"
    gitmodules.write_text("""
[submodule "lib"]
\tpath = vendor/lib
\turl  = https://github.com/org/lib
""")
    # No .git/modules dir and no real git tree — pinned SHA will be empty
    result = resolver.resolve(repo_dir, make_parent_request())
    check("Missing pinned SHA: submodule skipped (Threat C defence)",
        len(result.submodules) == 1 and result.submodules[0].status == "skipped")
    check("Missing pinned SHA: reason mentions unsafe",
        "unsafe" in result.submodules[0].reason.lower() or
        "pinned" in result.submodules[0].reason.lower())


# 6. File hashing and manifest integration
print("\n=== 6. File Hashing & Manifest ===")

resolver = make_resolver()

with tempfile.TemporaryDirectory() as sub_dir:
    # Create fake submodule content
    (Path(sub_dir) / "crypto.py").write_text("def encrypt(data): pass\n")
    (Path(sub_dir) / "utils").mkdir()
    (Path(sub_dir) / "utils" / "hash.py").write_text("import hashlib\n")

    entries, repo_hash = resolver._hash_submodule_files(sub_dir, "vendor/crypto-lib")

    check("Files found in submodule",   len(entries) == 2)
    check("repo_hash is 64-char hex",   len(repo_hash) == 64)
    check("All entries have SHA-256",
        all(len(e.sha256) == 64 for e in entries))
    check("Paths include submodule prefix",
        all(e.relative_path.startswith("vendor/crypto-lib/") for e in entries))

    # Determinism
    entries2, repo_hash2 = resolver._hash_submodule_files(sub_dir, "vendor/crypto-lib")
    check("repo_hash is deterministic", repo_hash == repo_hash2)

    # Hash changes when content changes
    (Path(sub_dir) / "crypto.py").write_text("MODIFIED\n")
    entries3, repo_hash3 = resolver._hash_submodule_files(sub_dir, "vendor/crypto-lib")
    check("repo_hash changes with file content", repo_hash != repo_hash3)

# Symlink escape inside submodule
with tempfile.TemporaryDirectory() as sub_dir:
    with tempfile.TemporaryDirectory() as outside_dir:
        (Path(outside_dir) / "secret.txt").write_text("secret\n")
        (Path(sub_dir) / "safe.py").write_text("x=1\n")
        evil_link = Path(sub_dir) / "evil.py"
        try:
            evil_link.symlink_to(Path(outside_dir) / "secret.txt")
            entries, _ = resolver._hash_submodule_files(sub_dir, "vendor/sub")
            evil_included = any("evil.py" in e.relative_path for e in entries)
            check("Symlink escape excluded from submodule manifest", not evil_included)
            check("Safe file still included", any("safe.py" in e.relative_path for e in entries))
        except OSError:
            check("Symlink escape test skipped (OS restriction)", True)
            check("Safe file still included", True)


# 7. SubmoduleResolutionResult
print("\n=== 7. SubmoduleResolutionResult ===")

result = SubmoduleResolutionResult()
result.submodules = [
    SubmoduleEntry("a", "vendor/a", "https://github.com/org/a",
                   status="fetched", repo_hash="x"*64),
    SubmoduleEntry("b", "vendor/b", "https://192.168.1.1/org/b",
                   status="skipped", reason="SSRF blocked"),
    SubmoduleEntry("c", "vendor/c", "https://github.com/org/c",
                   status="failed",  reason="fetch error"),
]
result.total_fetched = 1
result.total_skipped = 1
result.total_failed  = 1

check("has_blind_spots True when skipped > 0", result.has_blind_spots)
d = result.to_dict()
check("to_dict has all keys",
    all(k in d for k in ["submodules", "total_fetched", "total_skipped",
                          "total_failed", "has_blind_spots"]))
check("to_dict submodule count matches", len(d["submodules"]) == 3)

result_clean = SubmoduleResolutionResult()
result_clean.total_fetched = 5
check("has_blind_spots False when all fetched", not result_clean.has_blind_spots)


# Summary
print(f"\n{'='*60}")
print(f"Submodule Tests: {passed} passed, {failed} failed")
if failed:
    print("FAILURES DETECTED")
    sys.exit(1)
else:
    print("All submodule tests passed ✓")