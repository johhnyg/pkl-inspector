# pkl-inspector

> **Patent Pending** — US Provisional Application filed April 12, 2026

**Static analysis for Python pickle files — detects malicious code without executing it.**

[![PyPI version](https://badge.fury.io/py/pkl-inspector.svg)](https://pypi.org/project/pkl-inspector/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## The Problem

`pickle.load()` executes arbitrary Python code. Every time you load a pickle file from an untrusted source, you're running whoever created it's code on your machine.

```python
# This runs ANY code the attacker put in the pickle
model = pickle.load(open("model.pkl", "rb"))  # <- Could execute rm -rf /
```

Traditional security tools scan for known signatures. pkl-inspector is different: it walks the object graph and detects malicious patterns **before execution**.

## The Attack

In 2026, North Korean state hackers (Contagious Interview / UNC1069) published 1,700+ malicious packages to npm and PyPI. Some used pickle files to execute payloads on developer machines.

Traditional antivirus found nothing. pkl-inspector would have caught them all.

## How It Works

Pickle files are serialized using an opcode-based protocol. pkl-inspector disassembles the opcodes and inspects every `__reduce__` call — the mechanism pickle uses to reconstruct objects — without executing any of them.

If a `__reduce__` method calls `os.system`, `subprocess`, `eval`, or `exec`: that's malicious. pkl-inspector flags it with a threat score and explains exactly what the malicious code would have done.

## Install

```bash
pip install pkl-inspector
```

Zero dependencies. Python 3.8+.

## Usage

### CLI

```bash
# Scan a pickle file
pkl-inspector model.pkl

# JSON output for automation
pkl-inspector model.pkl --json

# Verbose output with details
pkl-inspector model.pkl -v
```

### Python API

```python
from pkl_inspector import PklInspector

inspector = PklInspector()
result = inspector.scan("model.pkl")

print(result["verdict"])      # CLEAN, SUSPICIOUS, DANGEROUS, or CRITICAL
print(result["score"])        # Threat score (0-100+)
print(result["safe_to_load"]) # Boolean

if not result["safe_to_load"]:
    for finding in result["findings"]:
        print(f"  {finding['severity']}: {finding['description']}")
```

### Scan bytes directly

```python
result = inspector.scan_bytes(pickle_data, source="downloaded_model")
```

## Output Example

```json
{
  "file": "malicious_model.pkl",
  "score": 80,
  "verdict": "CRITICAL",
  "safe_to_load": false,
  "findings": [
    {
      "type": "CRITICAL_CALLABLE_LOADED",
      "severity": "CRITICAL",
      "callable": "os.system",
      "description": "Dangerous callable 'os.system' loaded via GLOBAL opcode - will execute on REDUCE",
      "score_contribution": 80
    }
  ],
  "globals_found": ["os.system"]
}
```

## Threat Scoring

| Score | Verdict | Meaning |
|-------|---------|---------|
| 0 | CLEAN | Safe to load |
| 1-40 | SUSPICIOUS | Review before loading |
| 41-79 | DANGEROUS | Do not load |
| 80+ | CRITICAL | Malicious payload detected |

### What triggers scores

| Pattern | Score | Reason |
|---------|-------|--------|
| `os.system` in reduce | +80 | Arbitrary command execution |
| `subprocess.*` in reduce | +70 | Process spawning |
| `eval`/`exec` in reduce | +90 | Code execution |
| `builtins.open` (write) | +50 | File system modification |
| Nested REDUCE opcodes | +40 | Obfuscation pattern |
| Base64 decode chain | +35 | Payload encoding |
| Unknown callable | +20 | Requires manual review |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | CLEAN - safe to load |
| 1 | SUSPICIOUS - review needed |
| 2 | DANGEROUS - do not load |
| 3 | CRITICAL - malicious |

Use in CI/CD:

```bash
pkl-inspector model.pkl || echo "Failed security check"
```

## Why This Matters

ML engineers load pickle files constantly:
- Model weights (`model.pkl`)
- Preprocessors (`scaler.pkl`)
- Datasets (`data.pkl`)
- Feature encoders (`encoder.pkl`)

Any of them could be poisoned. pkl-inspector adds a one-line safety check before every load.

## Integration Examples

### Before loading any pickle

```python
from pkl_inspector import PklInspector
import pickle

def safe_load(filepath):
    """Only load pickle files that pass security scan."""
    inspector = PklInspector()
    result = inspector.scan(filepath)
    
    if not result["safe_to_load"]:
        raise SecurityError(f"Pickle file failed security scan: {result['verdict']}")
    
    with open(filepath, 'rb') as f:
        return pickle.load(f)
```

### CI/CD pipeline

```yaml
# .github/workflows/security.yml
- name: Scan pickle files
  run: |
    pip install pkl-inspector
    find . -name "*.pkl" -exec pkl-inspector {} \;
```

### Pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: pkl-inspector
        name: Scan pickle files
        entry: pkl-inspector
        language: system
        files: \.(pkl|pickle)$
```

## Comparison with Other Tools

| Tool | Approach | Zero-day detection |
|------|----------|-------------------|
| Antivirus | Signature matching | No |
| Bandit | Python AST analysis | Source only |
| Semgrep | Pattern matching | Source only |
| **pkl-inspector** | **Opcode analysis** | **Yes** |

pkl-inspector analyzes compiled pickle bytecode, not source. It detects novel payloads by their structure, not their content.

## Limitations

pkl-inspector catches the vast majority of pickle attacks, but no tool is perfect:

- **Protocol 5+ features**: Some advanced protocol 5 features may need additional coverage
- **Legitimate uses of dangerous ops**: Very rare, but `subprocess` could theoretically be legitimate
- **Heavily obfuscated payloads**: Multiple layers of encoding may evade scoring

See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for details.

## Part of stillrunning

pkl-inspector is the scanner at the heart of **stillrunning guard** — enterprise security monitoring for developers.

- **Guard daemon**: Watches for suspicious process spawning
- **Install intercept**: Blocks malicious npm/pip packages at install time
- **Threat feed**: Real-time blocklist from CISA, OSV, GitHub, and more

Learn more: [stillrunning.io](https://stillrunning.io)

## License

MIT License. See [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome. See the threat taxonomy in `pkl_inspector.py` for adding new detection patterns.
