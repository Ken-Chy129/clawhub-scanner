export const MAX_SKILL_MD_CHARS = 6000
export const MAX_FILE_CHARS = 10000
export const MAX_TOTAL_FILE_CHARS = 50000
export const MAX_OUTPUT_TOKENS = 16000
export const MAX_RETRIES = 3

export const CODE_EXTENSIONS = new Set([
  '.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx',
  '.py', '.rb', '.sh', '.bash', '.zsh', '.go',
  '.rs', '.c', '.cpp', '.java',
])

export const SCAN_FILE_EXTENSIONS = new Set([
  ...CODE_EXTENSIONS,
  '.md', '.markdown', '.mdx',
  '.json', '.yaml', '.yml', '.toml',
  '.txt', '.cfg', '.ini', '.conf',
])

export const REASON_CODES = {
  DANGEROUS_EXEC: 'suspicious.dangerous_exec',
  DYNAMIC_CODE: 'suspicious.dynamic_code_execution',
  CREDENTIAL_HARVEST: 'malicious.env_harvesting',
  EXFILTRATION: 'suspicious.potential_exfiltration',
  OBFUSCATED_CODE: 'suspicious.obfuscated_code',
  SUSPICIOUS_NETWORK: 'suspicious.nonstandard_network',
  CRYPTO_MINING: 'malicious.crypto_mining',
  INJECTION_INSTRUCTIONS: 'suspicious.prompt_injection_instructions',
  SUSPICIOUS_INSTALL_SOURCE: 'suspicious.install_untrusted_source',
  MANIFEST_PRIVILEGED_ALWAYS: 'suspicious.privileged_always',
}

export const MALICIOUS_CODES = new Set([
  REASON_CODES.CREDENTIAL_HARVEST,
  REASON_CODES.CRYPTO_MINING,
])

export const INJECTION_PATTERNS = [
  { name: 'ignore-previous-instructions', regex: /ignore\s+(all\s+)?previous\s+instructions/i },
  { name: 'you-are-now', regex: /you\s+are\s+now\s+(a|an)\b/i },
  { name: 'system-prompt-override', regex: /system\s*prompt\s*[:=]/i },
  { name: 'base64-block', regex: /[A-Za-z0-9+/=]{200,}/ },
  { name: 'unicode-control-chars', regex: /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]/ },
]

export const DIMENSION_LABELS = {
  purpose_capability: 'Purpose & Capability',
  instruction_scope: 'Instruction Scope',
  install_mechanism: 'Install Mechanism',
  environment_proportionality: 'Credentials',
  persistence_privilege: 'Persistence & Privilege',
}
