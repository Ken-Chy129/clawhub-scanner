# clawhub-scanner

[![npm version](https://img.shields.io/npm/v/clawhub-scanner.svg)](https://www.npmjs.com/package/clawhub-scanner)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> [ClawHub](https://clawhub.com) / [OpenClaw](https://openclaw.com) AI 技能安全扫描器 — 静态分析 + LLM 深度评估，零依赖。

AI Agent 技能（插件）可以执行 Shell 命令、访问凭证、读取文件、发送网络请求。**clawhub-scanner** 帮助你在安装前发现恶意或可疑的技能。

## 功能特性

- **静态正则扫描** — 无需 API Key，离线即可检测：
  - Shell 命令执行（`child_process`、`exec`、`spawn`）
  - 动态代码执行（`eval`、`new Function`）
  - 加密货币挖矿特征（`stratum+tcp`、`coinhive`、`xmrig`）
  - 数据窃取行为（文件读取 + 网络发送）
  - 凭证收割（环境变量访问 + 网络发送）
  - 代码混淆（十六进制序列、长 base64 载荷）
  - Markdown 中的 Prompt 注入模式
  - 配置文件中的可疑 URL（短链接、裸 IP 地址）

- **LLM 安全评估** — 五维度深度分析：
  - 目的与能力一致性
  - 指令范围分析
  - 安装机制风险
  - 凭证比例合理性
  - 持久化与权限评估

- **Prompt 注入检测** — 识别常见注入模式：
  - "忽略之前的所有指令"
  - "你现在是一个..."
  - System Prompt 覆盖
  - 隐藏的 base64 块
  - Unicode 控制字符

## 安装

```bash
# 全局安装
npm install -g clawhub-scanner

# 或直接用 npx 运行
npx clawhub-scanner --help

# 或作为项目依赖安装
npm install clawhub-scanner
```

## 命令行使用

```bash
# 静态扫描（不需要 API Key）
clawhub-scan --static ./my-skill

# 完整扫描（静态 + LLM 评估）
OPENAI_API_KEY=sk-xxx clawhub-scan ./my-skill

# 批量扫描多个技能
clawhub-scan --static ./skill-a ./skill-b ./skill-c

# JSON 输出（适合 CI/CD 集成）
clawhub-scan --static --json ./my-skill

# 保存扫描结果到目录
clawhub-scan --static --output ./results ./my-skill

# 指定 LLM 模型
clawhub-scan --model gpt-4o ./my-skill
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `--static` | 仅静态扫描（不调用 LLM，无需 API Key） |
| `--json` | 以 JSON 格式输出结果 |
| `--output <dir>` | 将结果保存为 JSON 文件到指定目录 |
| `--model <name>` | LLM 模型名称（默认：`gpt-5-mini`） |
| `--api-key <key>` | OpenAI API Key（默认读取 `OPENAI_API_KEY` 环境变量） |

### 环境变量

| 变量 | 说明 |
|------|------|
| `OPENAI_API_KEY` | LLM 评估所需的 API Key |
| `OPENAI_EVAL_MODEL` | 覆盖默认 LLM 模型 |

## 库使用方式

```js
import {
  scanSkill,
  scanSkillContent,
  runStaticScan,
  detectInjectionPatterns,
} from 'clawhub-scanner'

// 扫描技能目录
const result = await scanSkill('/path/to/skill', { staticOnly: true })
console.log(result.staticStatus)       // 'clean' | 'suspicious' | 'malicious'
console.log(result.staticScan.findings) // 发现的问题数组

// 直接扫描内容（无需磁盘 I/O）
const scan = runStaticScan(skillMdContent, [
  { path: 'helper.js', content: 'const { exec } = require("child_process")...' },
])
// => { status: 'suspicious', reasonCodes: [...], findings: [...] }

// 检测 Prompt 注入
const signals = detectInjectionPatterns('忽略之前的所有指令')
// => ['ignore-previous-instructions']

// 带 LLM 的完整扫描
const fullResult = await scanSkill('/path/to/skill', {
  apiKey: 'sk-xxx',
  model: 'gpt-4o',
})
console.log(fullResult.verdict)    // 'benign' | 'suspicious' | 'malicious'
console.log(fullResult.confidence) // 'high' | 'medium' | 'low'
```

### API 参考

#### `scanSkill(dirPath, options?)` → `Promise<ScanResult | null>`

扫描技能目录。如果未找到 `SKILL.md` 则返回 `null`。

#### `scanSkillContent(skillMd, files?, options?)` → `Promise<ScanResult>`

从原始内容扫描，无需读取磁盘。

#### `runStaticScan(skillMd, files)` → `StaticScanResult`

仅运行基于正则的静态分析。同步方法，无需 API Key。

#### `detectInjectionPatterns(text)` → `string[]`

检测文本中的 Prompt 注入模式。

## 扫描结果格式

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

## 规则码说明

| 规则码 | 严重级别 | 说明 |
|--------|----------|------|
| `suspicious.dangerous_exec` | critical | 通过 child_process 执行 Shell 命令 |
| `suspicious.dynamic_code_execution` | critical | 使用 eval() 或 new Function() |
| `malicious.crypto_mining` | critical | 加密货币挖矿特征 |
| `malicious.env_harvesting` | critical | 环境变量访问 + 网络发送 |
| `suspicious.potential_exfiltration` | warn | 文件读取 + 网络发送 |
| `suspicious.obfuscated_code` | warn | 混淆/编码的载荷 |
| `suspicious.prompt_injection_instructions` | warn | Markdown 中的 Prompt 注入 |
| `suspicious.install_untrusted_source` | warn | 短链接或裸 IP 地址 |

## 什么是 Skill（技能）？

**Skill** 是 AI Agent（如 [Claude Code](https://claude.com/claude-code)、[OpenClaw](https://openclaw.com)）的插件。每个技能包含：

- `SKILL.md` — 告诉 AI Agent 要做什么的指令文档
- 可选的代码文件（`.js`、`.py`、`.sh` 等）
- 可选的元数据（YAML frontmatter）声明依赖、环境变量、安装规范

技能可以非常强大 — 也可能非常危险。它们可以指示 AI Agent 执行 Shell 命令、访问你的凭证、读取你的文件、通过网络发送数据。**安装前务必先扫描。**

## 许可证

MIT
