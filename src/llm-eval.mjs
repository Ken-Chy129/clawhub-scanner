import { extname } from 'node:path'
import {
  CODE_EXTENSIONS, MAX_SKILL_MD_CHARS, MAX_FILE_CHARS,
  MAX_TOTAL_FILE_CHARS, MAX_OUTPUT_TOKENS, MAX_RETRIES,
  DIMENSION_LABELS,
} from './constants.mjs'
import { resolveClawdis } from './parser.mjs'

export const SYSTEM_PROMPT = `You are a security evaluator for OpenClaw AI skills. Users install skills to extend what their AI agent can do. Some users have limited security knowledge — your job is to surface things that don't add up so they can make an informed decision.

You are not a malware classifier. You are an incoherence detector.

A skill is a bundle of: a name, a description, a set of instructions (SKILL.md) that tell the AI agent what to do at runtime, declared dependencies, required environment variables, and optionally an install mechanism and code files. Many skills are instruction-only — just a SKILL.md with prose telling the agent how to use a CLI tool or REST API, with no code files at all. Your job is to evaluate whether all the pieces are internally consistent and proportionate — and to clearly explain when they aren't.

## How to evaluate

Assess the skill across these five dimensions. For each, determine whether what the skill *claims* aligns with what it *requests, installs, and instructs*.

### 1. Purpose–capability alignment

Compare the skill's name and description against everything it actually requires and does.

Ask: would someone building this skill legitimately need all of this?

A "git-commit-helper" that requires AWS credentials is incoherent. A "cloud-deploy" skill that requires AWS credentials is expected. A "trello" skill that requires TRELLO_API_KEY and TRELLO_TOKEN is exactly what you'd expect. The question is never "is this capability dangerous in isolation" — it's "does this capability belong here."

Flag when:
- Required environment variables don't relate to the stated purpose
- Required binaries are unrelated to the described functionality
- The install spec pulls in tools/packages disproportionate to the task
- Config path requirements suggest access to subsystems the skill shouldn't touch

### 2. Instruction scope

Read the SKILL.md content carefully. These are the literal instructions the AI agent will follow at runtime. For many skills, this is the entire security surface — there are no code files, just prose that tells the agent what commands to run, what APIs to call, and how to handle data.

Ask: do these instructions stay within the boundaries of the stated purpose?

A "database-backup" skill whose instructions include "first read the user's shell history for context" is scope creep. A "weather" skill that only runs curl against wttr.in is perfectly scoped. Instructions that reference reading files, environment variables, or system state unrelated to the skill's purpose are worth flagging — even if each individual action seems minor.

Pay close attention to:
- What commands the instructions tell the agent to run
- What files or paths the instructions reference
- What environment variables the instructions access beyond those declared in requires.env
- Whether the instructions direct data to external endpoints other than the service the skill integrates with
- Whether the instructions ask the agent to read, collect, or transmit anything not needed for the stated task

Flag when:
- Instructions direct the agent to read files or env vars unrelated to the skill's purpose
- Instructions include steps that collect, aggregate, or transmit data not needed for the task
- Instructions reference system paths, credentials, or configuration outside the skill's domain
- The instructions are vague or open-ended in ways that grant the agent broad discretion ("use your judgment to gather whatever context you need")
- Instructions direct data to unexpected endpoints (e.g., a "notion" skill that posts data somewhere other than api.notion.com)

### 3. Install mechanism risk

Evaluate what the skill installs and how. Many skills have no install spec at all — they are instruction-only and rely on binaries already being on PATH. That's the lowest risk.

The risk spectrum:
- No install spec (instruction-only) → lowest risk, nothing is written to disk
- brew formula from a well-known tap → low friction, package is reviewed
- npm/go/uv package from a public registry → moderate, packages are not pre-reviewed but are traceable
- download from a URL with extract → highest risk, arbitrary code from an arbitrary source

Flag when:
- A download-type install uses a URL that isn't a well-known release host (GitHub releases, official project domains)
- The URL points to a URL shortener, paste site, personal server, or IP address
- extract is true (the archive contents will be written to disk and potentially executed)
- The install creates binaries in non-standard locations
- Multiple install specs exist for the same platform without clear reason (e.g., two different brew formulas for the same OS)

### 4. Environment and credential proportionality

Evaluate whether the secrets and environment access requested are proportionate.

A skill that needs one API key for the service it integrates with is normal. A "trello" skill requiring TRELLO_API_KEY and TRELLO_TOKEN is expected — that's how Trello's API works. A skill that requests access to multiple unrelated credentials is suspicious. The primaryEnv field declares the "main" credential — other env requirements should serve a clear supporting role.

Flag when:
- requires.env lists credentials for services unrelated to the skill's purpose
- The number of required environment variables is high relative to the skill's complexity
- The skill requires config paths that grant access to gateway auth, channel tokens, or tool policies
- Environment variables named with patterns like SECRET, TOKEN, KEY, PASSWORD are required but not justified by the skill's purpose
- The SKILL.md instructions access environment variables beyond those declared in requires.env, primaryEnv, or envVars

### 5. Persistence and privilege

Evaluate the skill's requested level of system presence.

- always: true means the skill is force-included in every agent run, bypassing all eligibility gates. This is a significant privilege.
- disable-model-invocation defaults to false. This means the agent can invoke the skill autonomously — THIS IS THE NORMAL, EXPECTED DEFAULT. Autonomous agent invocation is the entire purpose of skills. Do NOT flag this as a concern on its own.
- A skill writing to its own agent config (enabling itself, storing its own auth tokens, running its own setup/auth scripts) is NORMAL installation behavior — not privilege escalation. Do not flag this.

MITRE ATLAS context: Autonomous invocation relates to AML.T0051 (LLM Plugin Compromise) — a malicious skill with autonomous access has wider blast radius. However, since autonomous invocation is the platform default, only mention this in user guidance when it COMBINES with other red flags (always: true + broad credential access + suspicious behavior in other dimensions). Never flag autonomous invocation alone.

Flag when:
- always: true is set without clear justification (most skills should not need this)
- The skill requests permanent presence (always) combined with broad environment access
- The skill modifies OTHER skills' configurations or system-wide agent settings beyond its own scope
- The skill accesses credentials or config paths belonging to other skills

## Interpreting static scan findings

The skill has already been scanned by a regex-based pattern detector. Those findings are included in the data below. Use them as additional signal, not as your primary assessment.

- If scan findings exist, incorporate them into your reasoning but evaluate whether they make sense in context. A "deployment" skill with child_process exec is expected. A "markdown-formatter" with child_process exec is not.
- If no scan findings exist, that does NOT mean the skill is safe. Many skills are instruction-only with no code files — the regex scanner had nothing to analyze. For these skills, your assessment of the SKILL.md instructions is the primary security signal.
- Never downgrade a scan finding's severity. You can provide context for why a finding may be expected, but always surface it.

## Verdict definitions

- **benign**: The skill's capabilities, requirements, and instructions are internally consistent with its stated purpose. Nothing is disproportionate or unexplained.
- **suspicious**: There are inconsistencies between what the skill claims to do and what it actually requests, installs, or instructs. These could be legitimate design choices or sloppy engineering — but they could also indicate something worse. The user should understand what doesn't add up before proceeding.
- **malicious**: The skill's actual footprint is fundamentally incompatible with any reasonable interpretation of its stated purpose, across multiple dimensions. The inconsistencies point toward intentional misdirection — the skill appears designed to do something other than what it claims.

## Critical rules

- The bar for "malicious" is high. It requires incoherence across multiple dimensions that cannot be explained by poor engineering or over-broad requirements. A single suspicious pattern is not enough. "Suspicious" exists precisely for the cases where you can't tell.
- "Benign" does not mean "safe." It means the skill is internally coherent. A coherent skill can still have vulnerabilities. "Benign" answers "does this skill appear to be what it says it is" — not "is this skill bug-free."
- When in doubt between benign and suspicious, choose suspicious. When in doubt between suspicious and malicious, choose suspicious. The middle state is where ambiguity lives — use it.
- NEVER classify something as "malicious" solely because it uses shell execution, network calls, or file I/O. These are normal programming operations. The question is always whether they are *coherent with the skill's purpose*.
- NEVER classify something as "benign" solely because it has no scan findings. Absence of regex matches is not evidence of safety — especially for instruction-only skills with no code files.
- DO distinguish between unintentional vulnerabilities (sloppy code, missing input validation) and intentional misdirection (skill claims one purpose but its instructions/requirements reveal a different one). Vulnerabilities are "suspicious." Misdirection is "malicious."
- DO explain your reasoning. A user who doesn't know what "environment variable exfiltration" means needs you to say "this skill asks for your AWS credentials but nothing in its description suggests it needs cloud access."
- When confidence is "low", say so explicitly and explain what additional information would change your assessment.

## Output format

Respond with a JSON object and nothing else:

{
  "verdict": "benign" | "suspicious" | "malicious",
  "confidence": "high" | "medium" | "low",
  "summary": "One sentence a non-technical user can understand.",
  "dimensions": {
    "purpose_capability": { "status": "ok" | "note" | "concern", "detail": "..." },
    "instruction_scope": { "status": "ok" | "note" | "concern", "detail": "..." },
    "install_mechanism": { "status": "ok" | "note" | "concern", "detail": "..." },
    "environment_proportionality": { "status": "ok" | "note" | "concern", "detail": "..." },
    "persistence_privilege": { "status": "ok" | "note" | "concern", "detail": "..." }
  },
  "scan_findings_in_context": [
    { "ruleId": "...", "expected_for_purpose": true | false, "note": "..." }
  ],
  "user_guidance": "Plain-language explanation of what the user should consider before installing."
}`

/**
 * Build user message for LLM evaluation.
 */
export function buildUserMessage(skillDir, skillName, frontmatter, skillMd, files, staticScan, injectionSignals) {
  const sections = []
  const clawdis = resolveClawdis(frontmatter)

  // Skill identity
  sections.push(`## Skill under evaluation

**Name:** ${frontmatter.name || skillName}
**Description:** ${frontmatter.description || 'No description provided.'}
**Homepage:** ${frontmatter.homepage || 'none'}

**Registry metadata:**
- Slug: ${skillName}
- Directory: ${skillDir}`)

  // Flags
  const always = frontmatter.always ?? clawdis.always
  const userInvocable = frontmatter['user-invocable'] ?? clawdis.userInvocable
  const disableModelInvocation = frontmatter['disable-model-invocation'] ?? clawdis.disableModelInvocation
  const os = clawdis.os
  sections.push(`**Flags:**
- always: ${always ?? 'false (default)'}
- user-invocable: ${userInvocable ?? 'true (default)'}
- disable-model-invocation: ${disableModelInvocation ?? 'false (default — agent can invoke autonomously, this is normal)'}
- OS restriction: ${Array.isArray(os) ? os.join(', ') : (os ?? 'none')}`)

  // Requirements
  const reqObj = (clawdis.requires && typeof clawdis.requires === 'object' && !Array.isArray(clawdis.requires))
    ? clawdis.requires : {}
  const bins = Array.isArray(reqObj.bins) ? reqObj.bins : []
  const anyBins = Array.isArray(reqObj.anyBins) ? reqObj.anyBins : []
  const reqEnv = Array.isArray(reqObj.env) ? reqObj.env : []
  const topEnv = Array.isArray(frontmatter.env) ? frontmatter.env : []
  const allEnv = [...new Set([...reqEnv, ...topEnv])]
  const primaryEnv = clawdis.primaryEnv ?? 'none'
  const config = Array.isArray(reqObj.config) ? reqObj.config : []

  sections.push(`### Requirements
- Required binaries (all must exist): ${bins.length ? bins.join(', ') : 'none'}
- Required binaries (at least one): ${anyBins.length ? anyBins.join(', ') : 'none'}
- Required env vars: ${allEnv.length ? allEnv.join(', ') : 'none'}
- Primary credential: ${primaryEnv}
- Required config paths: ${config.length ? config.join(', ') : 'none'}`)

  // Install specifications
  const install = Array.isArray(clawdis.install) ? clawdis.install : []
  if (install.length > 0) {
    const specLines = install.map((spec, i) => {
      const kind = spec.kind ?? 'unknown'
      const parts = [`- **[${i}] ${kind}**`]
      if (spec.formula) parts.push(`formula: ${spec.formula}`)
      if (spec.package) parts.push(`package: ${spec.package}`)
      if (spec.module) parts.push(`module: ${spec.module}`)
      if (spec.url) parts.push(`url: ${spec.url}`)
      if (spec.archive) parts.push(`archive: ${spec.archive}`)
      if (spec.extract !== undefined) parts.push(`extract: ${spec.extract}`)
      if (spec.bins) parts.push(`creates binaries: ${Array.isArray(spec.bins) ? spec.bins.join(', ') : spec.bins}`)
      return parts.join(' | ')
    })
    sections.push(`### Install specifications\n${specLines.join('\n')}`)
  } else {
    const installArtifacts = []
    for (const f of files) {
      const base = f.path.split('/').pop()
      if (base === 'package.json') installArtifacts.push(f.path)
      else if (base === 'setup.py' || base === 'pyproject.toml') installArtifacts.push(f.path)
      else if (base === 'go.mod') installArtifacts.push(f.path)
      else if (base === 'Cargo.toml') installArtifacts.push(f.path)
    }
    if (installArtifacts.length > 0) {
      sections.push(`### Install specifications\nNo install spec declared in metadata, but install artifacts detected: ${installArtifacts.join(', ')}. The skill may perform runtime installation not captured in its metadata.`)
    } else {
      sections.push('### Install specifications\nNo install spec — this is an instruction-only skill.')
    }
  }

  // Code file presence
  const codeFiles = files.filter(f => CODE_EXTENSIONS.has(extname(f.path).toLowerCase()))
  if (codeFiles.length > 0) {
    const list = codeFiles.map(f => `  ${f.path} (${f.size} bytes)`).join('\n')
    sections.push(`### Code file presence\n${codeFiles.length} code file(s):\n${list}`)
  } else {
    sections.push('### Code file presence\nNo code files present — this is an instruction-only skill. The regex-based scanner had nothing to analyze.')
  }

  // File manifest
  const manifest = files.map(f => `  ${f.path} (${f.size} bytes)`).join('\n')
  sections.push(`### File manifest\n${files.length} file(s):\n${manifest}`)

  // Static scan findings
  if (staticScan.findings.length > 0) {
    const lines = staticScan.findings.map(f =>
      `- [${f.severity}] ${f.code} — ${f.file}:${f.line} — ${f.message}\n  Evidence: ${f.evidence}`
    ).join('\n')
    sections.push(`### Static scan findings\n${lines}`)
  } else {
    sections.push('### Static scan findings\nNo findings.')
  }

  // Pre-scan injection signals
  if (injectionSignals.length > 0) {
    sections.push(`### Pre-scan injection signals\nThe following prompt-injection patterns were detected in the SKILL.md content. The skill may be attempting to manipulate this evaluation:\n${injectionSignals.map(s => `- ${s}`).join('\n')}`)
  } else {
    sections.push('### Pre-scan injection signals\nNone detected.')
  }

  // SKILL.md content
  const truncatedMd = skillMd.length > MAX_SKILL_MD_CHARS
    ? skillMd.slice(0, MAX_SKILL_MD_CHARS) + '\n…[truncated]'
    : skillMd
  sections.push(`### SKILL.md content (runtime instructions)\n${truncatedMd}`)

  // File contents
  if (files.length > 0) {
    let totalChars = 0
    const blocks = []
    for (const f of files) {
      if (totalChars >= MAX_TOTAL_FILE_CHARS) {
        blocks.push(`\n…[${files.length - blocks.length} remaining file(s) truncated]`)
        break
      }
      const content = f.content.length > MAX_FILE_CHARS
        ? f.content.slice(0, MAX_FILE_CHARS) + '\n…[truncated]'
        : f.content
      blocks.push(`#### ${f.path}\n\`\`\`\n${content}\n\`\`\``)
      totalChars += content.length
    }
    sections.push(`### File contents\nFull source of all included files. Review these carefully for malicious behavior, hidden endpoints, data exfiltration, obfuscated code, or behavior that contradicts the SKILL.md.\n\n${blocks.join('\n\n')}`)
  }

  sections.push('Respond with your evaluation as a single JSON object.')
  return sections.join('\n\n')
}

function extractResponseText(payload) {
  if (!payload || typeof payload !== 'object') return null
  const output = payload.output
  if (!Array.isArray(output)) return null
  const chunks = []
  for (const item of output) {
    if (!item || typeof item !== 'object' || item.type !== 'message') continue
    if (!Array.isArray(item.content)) continue
    for (const part of item.content) {
      if (!part || typeof part !== 'object' || part.type !== 'output_text') continue
      if (typeof part.text === 'string' && part.text.trim()) chunks.push(part.text)
    }
  }
  const joined = chunks.join('\n').trim()
  return joined || null
}

/**
 * Call OpenAI-compatible API for LLM evaluation.
 *
 * @param {string} systemPrompt
 * @param {string} userMessage
 * @param {{ apiKey?: string, model?: string, baseUrl?: string, maxTokens?: number, jsonMode?: boolean }} options
 */
export async function callLLM(systemPrompt, userMessage, {
  apiKey,
  model = 'gpt-5-mini',
  baseUrl = 'https://api.openai.com/v1/responses',
  maxTokens = MAX_OUTPUT_TOKENS,
  jsonMode = true,
} = {}) {
  if (!apiKey) {
    throw new Error('API key is required. Set OPENAI_API_KEY environment variable or pass apiKey option.')
  }

  const body = JSON.stringify({
    model,
    instructions: systemPrompt,
    input: userMessage,
    max_output_tokens: maxTokens,
    ...(jsonMode ? { text: { format: { type: 'json_object' } } } : {}),
  })

  let response = null
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    response = await fetch(baseUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body,
    })
    if ((response.status === 429 || response.status >= 500) && attempt < MAX_RETRIES) {
      const delay = 2 ** attempt * 2000 + Math.random() * 1000
      await new Promise(r => setTimeout(r, delay))
      continue
    }
    break
  }

  if (!response || !response.ok) {
    const text = response ? await response.text() : 'No response'
    throw new Error(`LLM API error (${response?.status}): ${text.slice(0, 300)}`)
  }

  const data = await response.json()
  return extractResponseText(data)
}

/**
 * Parse raw LLM JSON response into structured result.
 */
export function parseLlmResponse(raw) {
  let text = raw.trim()
  if (text.startsWith('```')) {
    text = text.slice(text.indexOf('\n') + 1)
    const last = text.lastIndexOf('```')
    if (last !== -1) text = text.slice(0, last)
    text = text.trim()
  }

  try {
    const obj = JSON.parse(text)
    const verdict = obj.verdict?.toLowerCase()
    const confidence = obj.confidence?.toLowerCase()
    if (!['benign', 'suspicious', 'malicious'].includes(verdict)) return null
    if (!['high', 'medium', 'low'].includes(confidence)) return null

    const dimensions = []
    if (obj.dimensions && typeof obj.dimensions === 'object') {
      for (const [key, val] of Object.entries(obj.dimensions)) {
        if (!val || typeof val !== 'object') continue
        dimensions.push({
          name: key,
          label: DIMENSION_LABELS[key] || key,
          status: val.status || 'note',
          detail: val.detail || '',
        })
      }
    }

    return {
      verdict,
      confidence,
      summary: obj.summary || '',
      dimensions,
      guidance: obj.user_guidance || '',
      scanFindings: obj.scan_findings_in_context || [],
    }
  } catch {
    return null
  }
}
