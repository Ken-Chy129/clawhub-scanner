import { extname } from 'node:path'
import {
  CODE_EXTENSIONS, REASON_CODES, MALICIOUS_CODES, INJECTION_PATTERNS,
} from './constants.mjs'

function findFirstLine(content, pattern) {
  const lines = content.split('\n')
  for (let i = 0; i < lines.length; i++) {
    if (pattern.test(lines[i])) return { line: i + 1, text: lines[i].slice(0, 160) }
  }
  return { line: 1, text: (lines[0] ?? '').slice(0, 160) }
}

/**
 * Run regex-based static security scan on skill files.
 *
 * @param {string} skillMd - Content of SKILL.md
 * @param {{ path: string, content: string }[]} files - Other files in the skill
 * @returns {{ status: 'clean'|'suspicious'|'malicious', reasonCodes: string[], findings: object[] }}
 */
export function runStaticScan(skillMd, files) {
  const findings = []
  const add = (code, severity, file, line, message, evidence) => {
    findings.push({ code, severity, file, line, message, evidence: evidence.slice(0, 160) })
  }

  const allFiles = [{ path: 'SKILL.md', content: skillMd }, ...files]

  for (const { path, content } of allFiles) {
    const ext = extname(path).toLowerCase()

    // Code file checks
    if (CODE_EXTENSIONS.has(ext)) {
      if (/child_process/.test(content) && /\b(exec|execSync|spawn|spawnSync)\s*\(/.test(content)) {
        const m = findFirstLine(content, /\b(exec|execSync|spawn|spawnSync)\s*\(/)
        add(REASON_CODES.DANGEROUS_EXEC, 'critical', path, m.line, 'Shell command execution detected.', m.text)
      }
      if (/\beval\s*\(|new\s+Function\s*\(/.test(content)) {
        const m = findFirstLine(content, /\beval\s*\(|new\s+Function\s*\(/)
        add(REASON_CODES.DYNAMIC_CODE, 'critical', path, m.line, 'Dynamic code execution detected.', m.text)
      }
      if (/stratum\+tcp|coinhive|cryptonight|xmrig/i.test(content)) {
        const m = findFirstLine(content, /stratum\+tcp|coinhive|cryptonight|xmrig/i)
        add(REASON_CODES.CRYPTO_MINING, 'critical', path, m.line, 'Crypto mining behavior detected.', m.text)
      }
      const hasFileRead = /readFileSync|readFile|open\(/.test(content)
      const hasNetSend = /\bfetch\b|http\.request|\baxios\b|\brequests\.(get|post)\b/.test(content)
      if (hasFileRead && hasNetSend) {
        const m = findFirstLine(content, /readFileSync|readFile|open\(/)
        add(REASON_CODES.EXFILTRATION, 'warn', path, m.line, 'File read + network send (possible exfiltration).', m.text)
      }
      const hasEnv = /process\.env|os\.environ|os\.getenv/.test(content)
      if (hasEnv && hasNetSend) {
        const m = findFirstLine(content, /process\.env|os\.environ|os\.getenv/)
        add(REASON_CODES.CREDENTIAL_HARVEST, 'critical', path, m.line, 'Env var access + network send.', m.text)
      }
      if (/(\\x[0-9a-fA-F]{2}){6,}/.test(content) || /(?:atob|Buffer\.from|base64\.b64decode)\s*\(\s*["'][A-Za-z0-9+/=]{200,}/.test(content)) {
        const m = findFirstLine(content, /(\\x[0-9a-fA-F]{2}){6,}|(?:atob|Buffer\.from|base64\.b64decode)/)
        add(REASON_CODES.OBFUSCATED_CODE, 'warn', path, m.line, 'Obfuscated payload detected.', m.text)
      }
    }

    // Markdown checks
    if (/\.(md|markdown|mdx)$/i.test(path)) {
      if (/ignore\s+(all\s+)?previous\s+instructions/i.test(content) ||
          /system\s*prompt\s*[:=]/i.test(content) ||
          /you\s+are\s+now\s+(a|an)\b/i.test(content)) {
        const m = findFirstLine(content, /ignore\s+(all\s+)?previous|system\s*prompt|you\s+are\s+now/i)
        add(REASON_CODES.INJECTION_INSTRUCTIONS, 'warn', path, m.line, 'Prompt injection pattern detected.', m.text)
      }
    }

    // Config file checks
    if (/\.(json|yaml|yml|toml)$/i.test(path)) {
      if (/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd)\//i.test(content) ||
          /https?:\/\/\d{1,3}(?:\.\d{1,3}){3}/i.test(content)) {
        const m = findFirstLine(content, /https?:\/\/(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd|(\d{1,3}\.){3}\d)/i)
        add(REASON_CODES.SUSPICIOUS_INSTALL_SOURCE, 'warn', path, m.line, 'Suspicious URL detected.', m.text)
      }
    }
  }

  const reasonCodes = [...new Set(findings.map(f => f.code))].sort()
  let status = 'clean'
  if (reasonCodes.some(c => MALICIOUS_CODES.has(c) || c.startsWith('malicious.'))) status = 'malicious'
  else if (reasonCodes.length > 0) status = 'suspicious'

  return { status, reasonCodes, findings }
}

/**
 * Detect prompt injection patterns in text.
 *
 * @param {string} text - Text content to check
 * @returns {string[]} Names of detected injection patterns
 */
export function detectInjectionPatterns(text) {
  return INJECTION_PATTERNS.filter(({ regex }) => regex.test(text)).map(({ name }) => name)
}
