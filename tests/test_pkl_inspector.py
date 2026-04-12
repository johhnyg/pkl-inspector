#!/usr/bin/env python3
"""
Tests for pkl-inspector.

Run with: python3 -m pytest tests/ -v
"""

import os
import sys
import pickle
import tempfile
import pytest

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from pkl_inspector import PklInspector, THRESHOLD_SUSPICIOUS, THRESHOLD_DANGEROUS, THRESHOLD_CRITICAL


# ─── Test Payload Classes ─────────────────────────────────────────────────────

class SafeObject:
    """Completely safe pickle payload - no custom __reduce__."""
    pass


class OsSystemPayload:
    """Payload that calls os.system()."""
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class SubprocessPayload:
    """Payload that calls subprocess.call()."""
    def __reduce__(self):
        import subprocess
        return (subprocess.call, (["whoami"],))


class EvalPayload:
    """Payload that calls eval()."""
    def __reduce__(self):
        return (eval, ("1+1",))


class ExecPayload:
    """Payload that calls exec()."""
    def __reduce__(self):
        return (exec, ("print('pwned')",))


class OpenPayload:
    """Payload that opens a file."""
    def __reduce__(self):
        return (open, ("/etc/passwd", "r"))


class SocketPayload:
    """Payload that creates a socket."""
    def __reduce__(self):
        import socket
        return (socket.socket, ())


class NestedPayload:
    """Payload with nested reduce using getattr pattern."""
    def __reduce__(self):
        # Use __import__ and getattr chain instead of module reference
        return (eval, ("__import__('os').system",))


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def inspector():
    """Create a PklInspector instance."""
    return PklInspector()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def create_pickle(obj, directory):
    """Create a pickle file from an object."""
    filepath = os.path.join(directory, f"{obj.__class__.__name__}.pkl")
    with open(filepath, 'wb') as f:
        pickle.dump(obj, f)
    return filepath


# ─── Tests ────────────────────────────────────────────────────────────────────

class TestCleanFiles:
    """Test that clean files are marked as CLEAN."""

    def test_safe_object_is_clean(self, inspector, temp_dir):
        """A simple safe object should return CLEAN verdict."""
        filepath = create_pickle(SafeObject(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] == "CLEAN"
        assert result["score"] == 0
        assert result["safe_to_load"] is True

    def test_basic_types_are_clean(self, inspector, temp_dir):
        """Basic Python types should be CLEAN."""
        test_data = {
            "list": [1, 2, 3],
            "dict": {"a": 1, "b": 2},
            "tuple": (1, 2, 3),
            "string": "hello world",
            "number": 42,
            "float": 3.14,
            "nested": {"list": [1, {"inner": True}]}
        }

        filepath = os.path.join(temp_dir, "basic_types.pkl")
        with open(filepath, 'wb') as f:
            pickle.dump(test_data, f)

        result = inspector.scan(filepath)
        assert result["verdict"] == "CLEAN"
        assert result["safe_to_load"] is True


class TestCriticalPayloads:
    """Test that critical payloads are detected."""

    def test_os_system_is_critical(self, inspector, temp_dir):
        """os.system payload should return CRITICAL verdict."""
        filepath = create_pickle(OsSystemPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] == "CRITICAL"
        assert result["score"] >= THRESHOLD_CRITICAL
        assert result["safe_to_load"] is False
        # os.system becomes posix.system on Linux, nt.system on Windows
        assert "system" in str(result["findings"])

    def test_eval_is_critical(self, inspector, temp_dir):
        """eval payload should return CRITICAL verdict."""
        filepath = create_pickle(EvalPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] == "CRITICAL"
        assert result["score"] >= THRESHOLD_CRITICAL
        assert result["safe_to_load"] is False

    def test_exec_is_critical(self, inspector, temp_dir):
        """exec payload should return CRITICAL verdict."""
        filepath = create_pickle(ExecPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] == "CRITICAL"
        assert result["score"] >= THRESHOLD_CRITICAL
        assert result["safe_to_load"] is False


class TestDangerousPayloads:
    """Test that dangerous payloads are detected."""

    def test_subprocess_is_dangerous(self, inspector, temp_dir):
        """subprocess payload should return DANGEROUS verdict."""
        filepath = create_pickle(SubprocessPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] in ("DANGEROUS", "CRITICAL")
        assert result["score"] >= THRESHOLD_DANGEROUS
        assert result["safe_to_load"] is False


class TestSuspiciousPayloads:
    """Test that suspicious payloads are detected."""

    def test_open_is_suspicious(self, inspector, temp_dir):
        """open() payload should be flagged."""
        filepath = create_pickle(OpenPayload(), temp_dir)
        result = inspector.scan(filepath)

        # open() is HIGH risk, should be at least DANGEROUS
        assert result["verdict"] in ("SUSPICIOUS", "DANGEROUS", "CRITICAL")
        assert result["score"] >= THRESHOLD_SUSPICIOUS
        assert len(result["findings"]) > 0

    def test_socket_is_suspicious(self, inspector, temp_dir):
        """socket payload should be flagged."""
        filepath = create_pickle(SocketPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert result["verdict"] in ("SUSPICIOUS", "DANGEROUS")
        assert result["score"] >= THRESHOLD_SUSPICIOUS


class TestObfuscationPatterns:
    """Test detection of obfuscation patterns."""

    def test_getattr_detected(self, inspector, temp_dir):
        """getattr obfuscation should be detected."""
        filepath = create_pickle(NestedPayload(), temp_dir)
        result = inspector.scan(filepath)

        # Should flag the os.system even through getattr
        assert result["score"] >= THRESHOLD_SUSPICIOUS
        assert len(result["findings"]) > 0


class TestScoreThresholds:
    """Test score threshold boundaries."""

    def test_zero_score_is_clean(self, inspector, temp_dir):
        """Score 0 should give CLEAN verdict."""
        filepath = create_pickle(SafeObject(), temp_dir)
        result = inspector.scan(filepath)

        assert result["score"] == 0
        assert result["verdict"] == "CLEAN"

    def test_threshold_boundaries(self):
        """Verify threshold constants are correct."""
        assert THRESHOLD_SUSPICIOUS == 1
        assert THRESHOLD_DANGEROUS == 41
        assert THRESHOLD_CRITICAL == 80


class TestScanBytes:
    """Test scanning raw bytes."""

    def test_scan_bytes_clean(self, inspector):
        """scan_bytes should work with clean data."""
        data = pickle.dumps([1, 2, 3])
        result = inspector.scan_bytes(data, source="test_bytes")

        assert result["verdict"] == "CLEAN"
        assert result["file"] == "test_bytes"

    def test_scan_bytes_malicious(self, inspector):
        """scan_bytes should detect malicious data."""
        data = pickle.dumps(OsSystemPayload())
        result = inspector.scan_bytes(data)

        assert result["verdict"] == "CRITICAL"
        assert result["safe_to_load"] is False


class TestErrorHandling:
    """Test error handling."""

    def test_file_not_found(self, inspector):
        """Non-existent file should return error result."""
        result = inspector.scan("/nonexistent/file.pkl")

        assert result["verdict"] == "ERROR"
        assert "not found" in result["error"].lower()

    def test_invalid_pickle_data(self, inspector, temp_dir):
        """Invalid pickle data should be handled gracefully."""
        filepath = os.path.join(temp_dir, "invalid.pkl")
        with open(filepath, 'wb') as f:
            f.write(b"not a pickle file at all")

        result = inspector.scan(filepath)
        # Should either parse what it can or return error
        assert result is not None


class TestResultStructure:
    """Test result dictionary structure."""

    def test_result_has_required_fields(self, inspector, temp_dir):
        """Result should have all required fields."""
        filepath = create_pickle(SafeObject(), temp_dir)
        result = inspector.scan(filepath)

        required_fields = [
            "file", "score", "verdict", "findings",
            "safe_to_load", "analyzed_at", "version"
        ]

        for field in required_fields:
            assert field in result, f"Missing field: {field}"

    def test_findings_structure(self, inspector, temp_dir):
        """Findings should have proper structure."""
        filepath = create_pickle(OsSystemPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert len(result["findings"]) > 0
        finding = result["findings"][0]

        assert "type" in finding
        assert "severity" in finding
        assert "description" in finding


class TestGlobalsTracking:
    """Test tracking of GLOBAL opcodes."""

    def test_globals_found_populated(self, inspector, temp_dir):
        """globals_found should list loaded callables."""
        filepath = create_pickle(OsSystemPayload(), temp_dir)
        result = inspector.scan(filepath)

        assert "globals_found" in result
        # os.system becomes posix.system on Linux, nt.system on Windows
        assert any("system" in g for g in result["globals_found"])


# ─── Run Tests ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
