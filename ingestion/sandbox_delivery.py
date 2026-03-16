"""
PRISM Sandbox Delivery Layer
=============================
Moves a verified repository from the fetch temp directory into the
sandbox input mount and writes the manifest file.

Responsibilities:
  1. Copy verified files from temp fetch dir → sandbox input dir
     (only files that passed integrity verification)
  2. Enforce read-only permissions on all delivered files
     (chmod 0o444 for files, 0o555 for directories)
  3. Write .prism_manifest.json to the sandbox input dir
     (this is what the parser pipeline uses as its entry point)
  4. Validate that the output path is inside PATH_POLICY bounds
  5. Clean up the temp fetch dir after delivery

The sandbox input dir is a bind mount in the Docker/gVisor container:
    Host:      /tmp/prism_sessions/<session_id>/repo/
    Container: /sandbox/repo/   (read-only bind mount)

The parser never writes to this directory — it only reads. Write
isolation is enforced at the container level by the bind mount flags.

Why copy instead of rename/move?
    - rename() is atomic but only works on the same filesystem
    - The temp dir may be on tmpfs while sandbox dir is on a different mount
    - Copy lets us apply permission changes per-file during the transfer
    - After copy we can zero and delete the temp dir contents
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
from pathlib import Path

from .models import FileEntry, IngestionRequest, RepoManifest

from ..parser.sandbox_config import PATH_POLICY, LIMITS
    
from .exceptions import PathPolicyViolation, DeliveryError, CopyIntegrityError

logger = logging.getLogger(__name__)

# Name of the manifest file written to the sandbox input dir
MANIFEST_FILENAME = ".prism_manifest.json"

# Permissions applied to delivered files and directories
_FILE_MODE = 0o444    # r--r--r-- : readable by all, writable by none
_DIR_MODE  = 0o555    # r-xr-xr-x : traversable, not writable




class DeliveryResult:
    """Result of the sandbox delivery operation."""

    def __init__(
        self,
        success:       bool,
        output_dir:    str,
        manifest_path: str,
        files_written: int,
        bytes_written: int,
        duration_ms:   float,
        warnings:      list[str] | None = None,
        error:         str | None       = None,
    ) -> None:
        self.success       = success
        self.output_dir    = output_dir
        self.manifest_path = manifest_path
        self.files_written = files_written
        self.bytes_written = bytes_written
        self.duration_ms   = duration_ms
        self.warnings      = warnings or []
        self.error         = error


class SandboxDelivery:
    """
    Delivers verified repository files to the sandbox input directory.
    Stateless — safe to call concurrently for different sessions.
    """

    def deliver(
        self,
        source_dir:  str,
        manifest:    RepoManifest,
        request:     IngestionRequest,
    ) -> DeliveryResult:
        """
        Copy verified files to the sandbox and write the manifest.

        Args:
            source_dir: temp directory containing the fetched repo
            manifest:   sealed RepoManifest from IntegrityVerifier
            request:    original IngestionRequest (for output_dir)

        Returns:
            DeliveryResult — check .success before proceeding
        """
        import time
        start_ms  = time.monotonic() * 1000
        warnings: list[str] = []

        # ── Validate output dir is inside sandbox bounds ───────────────────────
        try:
            safe_output = PATH_POLICY.validate_work_path(request.output_dir)
        except ValueError:
            # output_dir might be the repo dir, not work dir — try repo base
            try:
                safe_output = PATH_POLICY.validate_repo_path(request.output_dir)
            except ValueError as exc:
                return DeliveryResult(
                    success=False, output_dir=request.output_dir,
                    manifest_path="", files_written=0, bytes_written=0,
                    duration_ms=0.0, error=str(exc),
                )

        output_path = Path(str(safe_output))
        output_path.mkdir(parents=True, exist_ok=True)
        source_path = Path(source_dir)

        files_written = 0
        bytes_written = 0

        # Build a set of approved relative paths from the manifest
        # Only files in the manifest (passed integrity check) are copied
        approved: set[str] = {f.relative_path for f in manifest.files}

        # ── Copy approved files to sandbox ────────────────────────────────────
        for file_entry in manifest.files:
            src = source_path / file_entry.relative_path.replace("/", os.sep)
            dst = output_path / file_entry.relative_path.replace("/", os.sep)

            if not src.exists():
                warnings.append(f"Source file missing: {file_entry.relative_path}")
                continue

            # Create parent directories
            dst.parent.mkdir(parents=True, exist_ok=True)
            # Set directory permissions: traversable but not writable
            os.chmod(dst.parent, _DIR_MODE)

            try:
                # Copy file content
                shutil.copy2(str(src), str(dst))

                # Verify copy integrity — re-hash the destination file
                # and compare against the manifest entry
                copy_hash = self._hash_file(dst)
                if copy_hash != file_entry.sha256:
                    reason = (
                        f"Copy integrity failure for {file_entry.relative_path}: "
                        f"manifest={file_entry.sha256[:16]}... "
                        f"actual={copy_hash[:16]}..."
                    )
                    logger.error(reason)
                    dst.unlink(missing_ok=True)
                    warnings.append(reason)
                    continue

                # Enforce read-only permissions
                os.chmod(str(dst), _FILE_MODE)

                files_written += 1
                bytes_written += file_entry.size_bytes

            except OSError as exc:
                warnings.append(f"Failed to copy {file_entry.relative_path}: {exc}")

        # ── Write the manifest to the sandbox ─────────────────────────────────
        manifest_path = output_path / MANIFEST_FILENAME
        try:
            manifest_json = manifest.to_json()
            manifest_path.write_text(manifest_json, encoding="utf-8")
            os.chmod(str(manifest_path), _FILE_MODE)
        except OSError as exc:
            return DeliveryResult(
                success=False, output_dir=str(output_path),
                manifest_path="", files_written=files_written,
                bytes_written=bytes_written,
                duration_ms=round((time.monotonic() * 1000 - start_ms), 2),
                error=f"Manifest write failed: {exc}",
            )

        elapsed_ms = round(time.monotonic() * 1000 - start_ms, 2)
        logger.info(
            "Sandbox delivery complete. files=%d bytes=%d dir=%s ms=%.1f",
            files_written, bytes_written, str(output_path), elapsed_ms,
        )

        return DeliveryResult(
            success=True,
            output_dir=str(output_path),
            manifest_path=str(manifest_path),
            files_written=files_written,
            bytes_written=bytes_written,
            duration_ms=elapsed_ms,
            warnings=warnings,
        )

    def _hash_file(self, path: Path) -> str:
        """SHA-256 of a file for copy integrity verification."""
        CHUNK = 65536
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return ""

    def cleanup_temp_dir(self, temp_dir: str) -> None:
        """
        Delete the temporary fetch directory after successful delivery.

        We overwrite files with zeros before deletion where possible —
        this is a best-effort measure since on tmpfs the OS may not
        actually write zeros to disk (there is no disk). On a real
        filesystem it prevents recovery of credential-adjacent data.
        """
        try:
            temp_path = Path(temp_dir)
            if not temp_path.exists():
                return

            # Walk and zero small files before deletion
            for root, dirs, files in os.walk(temp_dir):
                for fname in files:
                    fpath = Path(root) / fname
                    try:
                        size = fpath.stat().st_size
                        # Only zero files small enough to be config/credential files
                        if size < 1024 * 1024:
                            with open(fpath, "wb") as f:
                                f.write(b"\x00" * size)
                    except OSError:
                        pass

            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug("Temp fetch dir cleaned up: %s", temp_dir)

        except Exception as exc:
            logger.warning("Failed to clean up temp dir %s: %s", temp_dir, exc)