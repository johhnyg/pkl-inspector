# pkl-inspector Threat Model

What pkl-inspector catches, what it doesn't, and how it compares to other tools.

## Threat Overview

### The Attack Surface

Python pickle is an attack surface because:

1. **Code execution by design**: `__reduce__` can return any callable
2. **Implicit trust**: Developers load pickles without verification
3. **Ubiquity**: ML models, datasets, caches all use pickle
4. **No sandboxing**: pickle.load() runs in the current process

### Attack Vectors

| Vector | Example | pkl-inspector Detection |
|--------|---------|------------------------|
| Direct system call | `os.system("rm -rf /")` | CRITICAL (80+) |
| Subprocess spawn | `subprocess.Popen(...)` | DANGEROUS (70+) |
| Code evaluation | `eval("malicious_code")` | CRITICAL (90+) |
| File exfiltration | `open("/etc/passwd").read()` | HIGH (50+) |
| Network callback | `urllib.request.urlopen(...)` | MEDIUM (35+) |
| Import hijacking | `__import__("malicious")` | HIGH (50+) |

## What pkl-inspector Catches

### Category 1: Direct Execution (Score 70-90)

Any pickle that loads a dangerous callable into the execution path:

```python
# All of these are detected:
os.system, os.popen, os.exec*
subprocess.call, subprocess.run, subprocess.Popen
builtins.eval, builtins.exec, builtins.compile
```

**Detection method**: GLOBAL opcode analysis

### Category 2: File System Access (Score 40-55)

Pickles that could modify or read sensitive files:

```python
builtins.open, io.open
os.remove, os.unlink, os.rmdir
shutil.rmtree, shutil.copy, shutil.move
```

**Detection method**: GLOBAL opcode + callable taxonomy

### Category 3: Network Operations (Score 30-40)

Pickles that establish network connections:

```python
socket.socket
urllib.request.urlopen
http.client.HTTPConnection
```

**Detection method**: Module + function name matching

### Category 4: Obfuscation Patterns (Score 20-40)

Techniques used to evade simple scanning:

| Pattern | Score | Example |
|---------|-------|---------|
| Nested REDUCE | +40 | Multiple reduce operations chained |
| Base64 decode | +35 | Encoded payload strings |
| getattr chains | +25 | Dynamic attribute resolution |
| Lambda functions | +30 | Anonymous function in reduce |
| Unknown callable | +20 | Callable not in known taxonomy |

**Detection method**: Opcode counting + string analysis

## What pkl-inspector Does NOT Catch

### Known Limitations

#### 1. C Extension Modules

If an attacker creates a malicious C extension and the pickle loads it:

```python
def __reduce__(self):
    return (__import__('malicious_extension').payload, ())
```

pkl-inspector will flag the `__import__` (score +50), but cannot analyze the C code.

**Mitigation**: The `__import__` itself triggers DANGEROUS verdict.

#### 2. Protocol 5 Out-of-Band Buffers

Protocol 5 introduced buffer objects that can store data outside the opcode stream:

```python
pickle.dumps(obj, protocol=5, buffer_callback=...)
```

pkl-inspector analyzes the opcode stream but not external buffers.

**Mitigation**: Malicious code still needs a REDUCE to execute; we catch that.

#### 3. Semantic Attacks

A pickle that does something "bad" using only safe operations:

```python
# Overwrites legitimate data with attacker-controlled data
{"password": "attacker_password"}
```

This is logically malicious but uses no dangerous callables.

**Mitigation**: pkl-inspector focuses on code execution, not data integrity.

#### 4. Time-of-Check Time-of-Use (TOCTOU)

If a file is scanned, then modified, then loaded:

```bash
pkl-inspector model.pkl  # CLEAN
# Attacker modifies model.pkl
pickle.load("model.pkl")  # MALICIOUS
```

**Mitigation**: Scan immediately before loading; integrate into load wrapper.

### Theoretical Evasions

#### Heavily Layered Encoding

Multiple encoding layers could theoretically lower individual scores below threshold:

```python
def __reduce__(self):
    # Each layer adds 20-35 points, but if spread across many reduces...
    return (decode_layer1, (decode_layer2(decode_layer3(payload)),))
```

**Current status**: Multiple REDUCE operations add +40, making deep nesting still detectable.

#### Novel Callables

A new dangerous callable not in our taxonomy:

```python
# Hypothetical: new_dangerous_module.execute()
```

**Mitigation**: Unknown callables score +20, prompting manual review.

## Comparison with Other Tools

### Signature-Based Antivirus

| Aspect | Antivirus | pkl-inspector |
|--------|-----------|---------------|
| Method | Known byte patterns | Structural analysis |
| Zero-day | No | Yes |
| Polymorphic payloads | No | Yes |
| Performance | Fast | Fast |
| False negatives | Common | Rare |

**Key difference**: Antivirus looks for known bad bytes. pkl-inspector analyzes what the code WILL DO.

### Bandit (Python Security Linter)

| Aspect | Bandit | pkl-inspector |
|--------|--------|---------------|
| Input | Python source code | Compiled pickle bytes |
| Scope | Source files | Serialized objects |
| pickle detection | "pickle.load is dangerous" | Actual payload analysis |

**Key difference**: Bandit warns that pickle is dangerous. pkl-inspector tells you IF a specific pickle IS dangerous.

### Semgrep

| Aspect | Semgrep | pkl-inspector |
|--------|---------|---------------|
| Input | Source code | Binary pickle |
| Rules | Pattern matching | Opcode analysis |
| Coverage | Broad language support | pickle-specific depth |

**Key difference**: Semgrep needs source code. pkl-inspector works on the compiled artifact.

### Sandbox Execution

| Aspect | Sandbox | pkl-inspector |
|--------|---------|---------------|
| Method | Run in isolation | Static analysis |
| Time | Seconds to minutes | Milliseconds |
| Coverage | Complete | Structural |
| Anti-analysis | Vulnerable | Immune |
| Resource cost | High | Minimal |

**Key difference**: Sandboxes actually run the code. pkl-inspector never executes.

## Scoring Philosophy

### Why These Thresholds?

| Threshold | Score | Rationale |
|-----------|-------|-----------|
| CLEAN | 0 | No dangerous patterns detected |
| SUSPICIOUS | 1-40 | Something worth reviewing, not execution risk |
| DANGEROUS | 41-79 | Real execution risk, should not load |
| CRITICAL | 80+ | Confirmed malicious intent |

### Single-Hit CRITICAL

`os.system` alone scores 80 → CRITICAL. Why?

Because `os.system` in a `__reduce__` has exactly one purpose: executing shell commands when the pickle loads. There is no legitimate use case.

### Cumulative Scoring

Multiple medium-risk patterns accumulate:

```
socket.socket: +30
urllib.urlopen: +35
unknown callable: +20
nested reduce: +40
-------------------
Total: 125 → CRITICAL
```

Even if no single finding is critical, the combination indicates sophisticated attack.

## Recommendations

### Always Scan Before Loading

```python
from pkl_inspector import PklInspector

def safe_load(path):
    result = PklInspector().scan(path)
    if not result["safe_to_load"]:
        raise SecurityError(result["verdict"])
    return pickle.load(open(path, "rb"))
```

### Defense in Depth

pkl-inspector is one layer. Also consider:

1. **Source verification**: Only load pickles from trusted sources
2. **Signature verification**: Sign pickle files with cryptographic signatures
3. **Sandboxed loading**: Use containers/VMs for untrusted data
4. **Alternative formats**: Use JSON, msgpack, or protobuf when possible

### Continuous Monitoring

Integrate into CI/CD:

```yaml
- name: Scan pickle files
  run: find . -name "*.pkl" -exec pkl-inspector {} +
```

## Incident Response

If pkl-inspector flags a file as DANGEROUS or CRITICAL:

1. **Do not load the file**
2. **Preserve the file** for forensic analysis
3. **Check the source**: Where did this file come from?
4. **Review findings**: What specific callables were detected?
5. **Report**: If from a public package, report to CISA/PyPI security

## Updates

The threat taxonomy is updated as new attack patterns emerge. Check for updates:

```bash
pip install --upgrade pkl-inspector
```

Report new evasion techniques: https://github.com/johhnyg/pkl-inspector/issues
