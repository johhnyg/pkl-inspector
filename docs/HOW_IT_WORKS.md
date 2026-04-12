# How pkl-inspector Works

A technical deep dive into pickle protocol analysis and malicious payload detection.

## The Pickle Protocol

Python's pickle module serializes objects using a stack-based virtual machine. The serialized data is a sequence of opcodes that, when executed by `pickle.load()`, reconstruct the original object.

### Key Opcodes

| Opcode | Name | Description |
|--------|------|-------------|
| `\x80` | PROTO | Protocol version marker |
| `c` | GLOBAL | Push a global object (module.name) onto stack |
| `R` | REDUCE | Call the callable on stack with args |
| `b` | BUILD | Call `__setstate__` or `__dict__.update()` |
| `i` | INST | Build an instance (older protocol) |
| `.` | STOP | End of pickle |

### The Dangerous Pattern

The attack vector is the `GLOBAL` + `REDUCE` combination:

```
c os          # Push 'os' module
system        # Push 'system' function -> os.system on stack
( S'rm -rf /' # Push args tuple with command string
t R           # REDUCE: call os.system('rm -rf /')
.             # STOP
```

When `pickle.load()` processes this:
1. `GLOBAL` loads `os.system` onto the stack
2. `REDUCE` calls it with the arguments
3. **Your system executes `rm -rf /`**

## How pkl-inspector Detects This

### Step 1: Opcode Disassembly

pkl-inspector reads the raw bytes and parses opcodes WITHOUT using `pickle.load()`:

```python
class PickleOpParser:
    def parse(self) -> List[Tuple[str, Any, int]]:
        # Returns: [(opcode_name, argument, byte_position), ...]
```

This extracts the instruction stream without executing anything.

### Step 2: GLOBAL Tracking

Every `GLOBAL` opcode loads a callable. We extract and record them:

```
GLOBAL (os, system) at byte 0      -> "os.system"
GLOBAL (subprocess, call) at byte 50 -> "subprocess.call"
```

### Step 3: Threat Taxonomy Matching

Each callable is checked against our threat taxonomy:

```python
CRITICAL_CALLABLES = {
    "os.system": 80,      # Arbitrary command execution
    "subprocess.call": 70, # Process spawning
    "builtins.eval": 90,  # Code execution
    # ...
}
```

### Step 4: REDUCE Analysis

When we see `REDUCE`, we know the preceding `GLOBAL` will be called. We flag this combination:

```
GLOBAL os.system at byte 0
REDUCE at byte 25
-> Finding: "os.system will be called on REDUCE"
```

### Step 5: Scoring

Scores are accumulated based on detected patterns:

```
os.system loaded:     +80 (CRITICAL)
subprocess in reduce: +70 (DANGEROUS)
base64 decode chain:  +35 (obfuscation)
unknown callable:     +20 (suspicious)
---------------------------------
Total:                205 -> CRITICAL verdict
```

## Opcode-Level Example

### Clean Pickle

A safe pickle containing `[1, 2, 3]`:

```
\x80\x04  # PROTO 4
]        # EMPTY_LIST
(        # MARK
K\x01    # BININT1 1
K\x02    # BININT1 2
K\x03    # BININT1 3
e        # APPENDS
.        # STOP
```

No `GLOBAL` opcodes = no external callables = **CLEAN**

### Malicious Pickle

A pickle that runs `os.system("whoami")`:

```
\x80\x04     # PROTO 4
\x95\x1d...  # FRAME (29 bytes)
\x8c\x02os   # SHORT_BINUNICODE 'os'
\x8c\x06system # SHORT_BINUNICODE 'system'  
\x93         # STACK_GLOBAL (loads os.system)
\x8c\x06whoami # SHORT_BINUNICODE 'whoami'
\x85         # TUPLE1 (args tuple)
R            # REDUCE (calls os.system('whoami'))
.            # STOP
```

pkl-inspector sees:
1. `STACK_GLOBAL` resolving to `os.system`
2. `REDUCE` following it
3. **Score: 80 → CRITICAL**

## Detection Without Execution

The key insight: **We don't need to run the code to know it's dangerous.**

Traditional antivirus scans for known byte signatures. If the attacker changes one character, the signature fails.

pkl-inspector analyzes structure:
- "This pickle loads `os.system`"
- "This pickle calls `REDUCE` with shell commands"

The **intent** is visible in the opcodes, regardless of the specific payload.

## Obfuscation Detection

Attackers try to evade detection with obfuscation:

### Base64 Encoding

```python
def __reduce__(self):
    import base64
    return (base64.b64decode, (b'b3Muc3lzdGVt',))  # "os.system" encoded
```

We detect `base64.b64decode` as an obfuscation pattern (+35).

### Nested getattr

```python
def __reduce__(self):
    return (getattr, (__import__('os'), 'system'))
```

We detect:
- `getattr` usage (+25)
- Dynamic `__import__` (+50)
- Total: **DANGEROUS**

### Multiple REDUCE

Attackers chain operations to hide intent:

```python
def __reduce__(self):
    return (getattr, (getattr(__import__('os'), 'path'), 'system'))
```

We detect multiple `REDUCE` opcodes (+40 for nesting).

## What We Catch

| Pattern | Detection Method |
|---------|------------------|
| Direct os.system | GLOBAL opcode check |
| subprocess.* | GLOBAL opcode check |
| eval/exec | GLOBAL opcode check |
| File operations | GLOBAL opcode check |
| Network operations | GLOBAL opcode check |
| Base64 obfuscation | String pattern + callable |
| Nested reduces | REDUCE opcode counting |
| Dynamic resolution | STACK_GLOBAL flag |

## What We Don't Catch

No tool is perfect. Theoretical evasions:

1. **Extension modules**: Custom C extensions loaded via pickle
2. **Protocol 5 buffers**: Out-of-band data not in opcode stream
3. **Legitimate dangerous ops**: Very rare false positives possible

See [THREAT_MODEL.md](THREAT_MODEL.md) for complete analysis.

## Implementation

The core algorithm is ~400 lines of Python with zero dependencies:

```python
class PklInspector:
    def scan(self, filepath: str) -> Dict[str, Any]:
        data = open(filepath, 'rb').read()
        ops = PickleOpParser(data).parse()      # Step 1: Parse
        score, findings = ThreatAnalyzer(ops).analyze()  # Step 2-4
        verdict = self._score_to_verdict(score)  # Step 5
        return {...}
```

The simplicity is intentional: security tools should be auditable.

## Further Reading

- [Python pickle documentation](https://docs.python.org/3/library/pickle.html)
- [pickletools module](https://docs.python.org/3/library/pickletools.html)
- [Ned Batchelder's pickle presentation](https://nedbatchelder.com/blog/200403/pickle_security.html)
- [CISA advisory on supply chain attacks](https://www.cisa.gov/uscert/ncas/alerts)
