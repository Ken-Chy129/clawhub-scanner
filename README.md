# clawhub-scanner

[![npm version](https://img.shields.io/npm/v/clawhub-scanner.svg)](https://www.npmjs.com/package/clawhub-scanner)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

[中文文档](./README_zh.md)

> The security scanning engine behind [ClawHub](https://clawhub.com) — this is how ClawHub evaluates every skill before it reaches users. Now available as a standalone npm package.

## How ClawHub Scans Skills

When a skill is published to ClawHub, it goes through a multi-layer security pipeline. **This package is exactly that pipeline**, extracted from the ClawHub platform so you can run the same checks locally:

1. **Static Regex Scan** — Fast, offline pattern matching against known malicious signatures (dangerous exec, data exfiltration, crypto mining, prompt injection, etc.)
2. **LLM Security Evaluation** — An LLM-as-judge evaluator that assesses the skill across 5 security dimensions, checking whether the skill's actual behavior is coherent with its stated purpose
3. **Prompt Injection Detection** — Pre-scan filters that catch attempts to manipulate the LLM evaluator itself

This is not a generic security scanner. It is purpose-built for the ClawHub / OpenClaw skill format and understands the specific threat model of AI agent plugins: skills that can instruct AI agents to run shell commands, access credentials, read files, and send data over the network.

## Features

- **Static Regex Scan** — Detects dangerous patterns without any API key:
  - Shell command execution (`child_process`, `exec`, `spawn`)
  - Dynamic code execution (`eval`, `new Function`)
  - Crypto mining indicators (`stratum+tcp`, `coinhive`, `xmrig`)
  - Data exfiltration (file read + network send)
  - Credential harvesting (env var access + network send)
  - Obfuscated code (hex sequences, long base64 payloads)
  - Prompt injection patterns in markdown
  - Suspicious URLs in config files (URL shorteners, raw IPs)

- **LLM Security Evaluation** — 5-dimension deep analysis:
  - Purpose & capability alignment
  - Instruction scope analysis
  - Install mechanism risk
  - Credential proportionality
  - Persistence & privilege assessment

- **Prompt Injection Detection** — Identifies common injection patterns:
  - "Ignore previous instructions"
  - "You are now a..."
  - System prompt override attempts
  - Hidden base64 blocks
  - Unicode control characters

## Install

```bash
# Global install
npm install -g clawhub-scanner

# Or use directly with npx
npx clawhub-scanner --help

# Or install as project dependency
npm install clawhub-scanner
```

## CLI Usage

```bash
# Static scan (no API key needed)
clawhub-scan --static ./my-skill

# Full scan (static + LLM evaluation)
OPENAI_API_KEY=sk-xxx clawhub-scan ./my-skill

# Scan multiple skills at once
clawhub-scan --static ./skill-a ./skill-b ./skill-c

# JSON output (for CI/CD pipelines)
clawhub-scan --static --json ./my-skill

# Save results to a directory
clawhub-scan --static --output ./results ./my-skill

# Use a custom LLM model
clawhub-scan --model gpt-4o ./my-skill
```

### CLI Options

| Option | Description |
|--------|-------------|
| `--static` | Static scan only (no LLM, no API key needed) |
| `--json` | Output results as JSON |
| `--output <dir>` | Save individual JSON results to directory |
| `--model <name>` | LLM model name (default: `gpt-5-mini`) |
| `--api-key <key>` | OpenAI API key (default: `OPENAI_API_KEY` env) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | Required for LLM evaluation |
| `OPENAI_EVAL_MODEL` | Override default LLM model |

## Library Usage

```js
import {
  scanSkill,
  scanSkillContent,
  runStaticScan,
  detectInjectionPatterns,
} from 'clawhub-scanner'

// Scan a skill directory
const result = await scanSkill('/path/to/skill', { staticOnly: true })
console.log(result.staticStatus)       // 'clean' | 'suspicious' | 'malicious'
console.log(result.staticScan.findings) // Array of findings

// Scan raw content (no disk I/O)
const scan = runStaticScan(skillMdContent, [
  { path: 'helper.js', content: 'const { exec } = require("child_process")...' },
])
// => { status: 'suspicious', reasonCodes: [...], findings: [...] }

// Detect prompt injection patterns
const signals = detectInjectionPatterns('Ignore all previous instructions')
// => ['ignore-previous-instructions']

// Full scan with LLM evaluation
const fullResult = await scanSkill('/path/to/skill', {
  apiKey: 'sk-xxx',
  model: 'gpt-4o',
})
console.log(fullResult.verdict)    // 'benign' | 'suspicious' | 'malicious'
console.log(fullResult.confidence) // 'high' | 'medium' | 'low'
```

### API Reference

#### `scanSkill(dirPath, options?)` → `Promise<ScanResult | null>`

Scan a skill directory. Returns `null` if no `SKILL.md` is found.

#### `scanSkillContent(skillMd, files?, options?)` → `Promise<ScanResult>`

Scan from raw content without reading from disk.

#### `runStaticScan(skillMd, files)` → `StaticScanResult`

Run regex-based static analysis only. Synchronous, no API key needed.

#### `detectInjectionPatterns(text)` → `string[]`

Detect prompt injection patterns in text content.

## Scan Result Format

```json
{
  "skill": "my-skill",
  "timestamp": "2026-03-13T08:00:00.000Z",
  "staticScan": {
    "status": "suspicious",
    "reasonCodes": ["suspicious.dangerous_exec"],
    "findings": [
      {
        "code": "suspicious.dangerous_exec",
        "severity": "critical",
        "file": "helper.js",
        "line": 5,
        "message": "Shell command execution detected.",
        "evidence": "exec('rm -rf /')"
      }
    ]
  },
  "injectionSignals": [],
  "llmResult": {
    "verdict": "suspicious",
    "confidence": "high",
    "summary": "...",
    "dimensions": { ... },
    "user_guidance": "..."
  }
}
```

## Reason Codes

| Code | Severity | Description |
|------|----------|-------------|
| `suspicious.dangerous_exec` | critical | Shell command execution via child_process |
| `suspicious.dynamic_code_execution` | critical | eval() or new Function() usage |
| `malicious.crypto_mining` | critical | Crypto mining indicators |
| `malicious.env_harvesting` | critical | Env var access + network send |
| `suspicious.potential_exfiltration` | warn | File read + network send |
| `suspicious.obfuscated_code` | warn | Obfuscated/encoded payloads |
| `suspicious.prompt_injection_instructions` | warn | Prompt injection in markdown |
| `suspicious.install_untrusted_source` | warn | URL shorteners or raw IPs |

## How It Works — The ClawHub Security Pipeline

```
┌─────────────────────────────────────────────────────────┐
│                   Skill Published                       │
│              (SKILL.md + code files)                    │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 1: Static Regex Scan                             │
│  ─────────────────────────                              │
│  • Pattern match against known malicious signatures     │
│  • Check code files for dangerous APIs                  │
│  • Check configs for suspicious URLs                    │
│  • Check markdown for prompt injection                  │
│  Result: clean / suspicious / malicious                 │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 2: Prompt Injection Pre-filter                   │
│  ────────────────────────────────                       │
│  • Detect "ignore previous instructions" patterns       │
│  • Catch system prompt override attempts                │
│  • Flag hidden base64 blocks & unicode control chars    │
│  • Feed signals to LLM as adversarial context           │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│  Layer 3: LLM-as-Judge Evaluation                       │
│  ────────────────────────────                           │
│  5-dimension coherence analysis:                        │
│  1. Purpose ↔ Capability alignment                      │
│  2. Instruction scope boundaries                        │
│  3. Install mechanism risk                              │
│  4. Credential proportionality                          │
│  5. Persistence & privilege assessment                  │
│                                                         │
│  Verdict: benign / suspicious / malicious               │
│  + confidence level + plain-language user guidance      │
└─────────────────────────────────────────────────────────┘
```

The key insight of this scanner is **coherence detection, not malware classification**. A `child_process.exec()` call is normal in a deployment skill but suspicious in a markdown formatter. The LLM evaluator understands context and asks: "does this capability belong here?"

## What is a Skill?

A **skill** is a plugin for AI agents (like [Claude Code](https://claude.com/claude-code) or [OpenClaw](https://openclaw.com)). Each skill contains:

- `SKILL.md` — Instructions that tell the AI agent what to do
- Optional code files (`.js`, `.py`, `.sh`, etc.)
- Optional metadata (YAML frontmatter) declaring dependencies, env vars, install specs

Skills can be powerful — and dangerous. They can instruct AI agents to run shell commands, access your credentials, read your files, and send data over the network. **Always scan before installing.**

## Related Projects

- [ClawHub](https://clawhub.com) — The skill marketplace where this scanner runs in production
- [OpenClaw](https://openclaw.com) — Open-source AI agent framework
- [anygen-skills](https://github.com/Ken-Chy129/anygen-skills) — A collection of AI skills scanned by this tool

## License

MIT
