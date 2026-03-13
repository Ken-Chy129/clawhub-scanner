import { readSkillDir } from './reader.mjs'
import { runStaticScan, detectInjectionPatterns } from './static-scan.mjs'
import { buildUserMessage, callLLM, parseLlmResponse, SYSTEM_PROMPT } from './llm-eval.mjs'

/**
 * @typedef {Object} ScanOptions
 * @property {boolean}  [staticOnly=false]  Only run static scan, skip LLM evaluation
 * @property {string}   [apiKey]            OpenAI API key (defaults to OPENAI_API_KEY env)
 * @property {string}   [model]             LLM model name (defaults to OPENAI_EVAL_MODEL env or 'gpt-5-mini')
 * @property {string}   [baseUrl]           LLM API base URL
 */

/**
 * @typedef {Object} ScanResult
 * @property {string}  name           Skill name
 * @property {string}  staticStatus   'clean' | 'suspicious' | 'malicious'
 * @property {Object}  staticScan     Static scan result with findings
 * @property {string|null}  verdict   LLM verdict (null if skipped)
 * @property {string|null}  confidence LLM confidence (null if skipped)
 * @property {Object|null}  result    Full LLM result (null if skipped)
 * @property {string[]} [injectionSignals]  Detected injection patterns
 */

/**
 * Scan a skill directory for security issues.
 *
 * @param {string} dirPath - Absolute path to the skill directory
 * @param {ScanOptions} [options={}]
 * @returns {Promise<ScanResult|null>} Scan result, or null if directory is invalid
 */
export async function scanSkill(dirPath, options = {}) {
  const {
    staticOnly = false,
    apiKey = process.env.OPENAI_API_KEY,
    model = process.env.OPENAI_EVAL_MODEL || 'gpt-5-mini',
    baseUrl = 'https://api.openai.com/v1/responses',
  } = options

  const data = readSkillDir(dirPath)
  if (!data) return null

  const { skillMd, frontmatter, files } = data
  const skillName = dirPath.split('/').pop()

  // Static scan
  const staticScan = runStaticScan(skillMd, files)
  const allContent = [skillMd, ...files.map(f => f.content)].join('\n')
  const injectionSignals = detectInjectionPatterns(allContent)

  if (staticOnly) {
    return {
      name: skillName,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
    }
  }

  if (!apiKey) {
    return {
      name: skillName,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
    }
  }

  // LLM evaluation
  const userMessage = buildUserMessage(dirPath, skillName, frontmatter, skillMd, files, staticScan, injectionSignals)

  let raw
  try {
    raw = await callLLM(SYSTEM_PROMPT, userMessage, { apiKey, model, baseUrl })
  } catch (e) {
    return {
      name: skillName,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
      error: e.message,
    }
  }

  if (!raw) {
    return {
      name: skillName,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
      error: 'Empty LLM response',
    }
  }

  const result = parseLlmResponse(raw)

  return {
    name: skillName,
    staticStatus: staticScan.status,
    staticScan,
    verdict: result?.verdict ?? null,
    confidence: result?.confidence ?? null,
    result,
    injectionSignals,
    llmRaw: raw,
  }
}

/**
 * Scan a skill from raw content (without reading from disk).
 *
 * @param {string} skillMd - Content of SKILL.md
 * @param {{ path: string, content: string, size?: number }[]} [files=[]] - Additional files
 * @param {ScanOptions} [options={}]
 * @returns {Promise<ScanResult>}
 */
export async function scanSkillContent(skillMd, files = [], options = {}) {
  const {
    name = 'unknown',
    staticOnly = false,
    apiKey = process.env.OPENAI_API_KEY,
    model = process.env.OPENAI_EVAL_MODEL || 'gpt-5-mini',
    baseUrl = 'https://api.openai.com/v1/responses',
  } = options

  const normalizedFiles = files.map(f => ({
    path: f.path,
    content: f.content,
    size: f.size ?? Buffer.byteLength(f.content, 'utf-8'),
  }))

  const staticScan = runStaticScan(skillMd, normalizedFiles)
  const allContent = [skillMd, ...normalizedFiles.map(f => f.content)].join('\n')
  const injectionSignals = detectInjectionPatterns(allContent)

  if (staticOnly || !apiKey) {
    return {
      name,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
    }
  }

  const { parseFrontmatter } = await import('./parser.mjs')
  const frontmatter = parseFrontmatter(skillMd)
  const userMessage = buildUserMessage('.', name, frontmatter, skillMd, normalizedFiles, staticScan, injectionSignals)

  let raw
  try {
    raw = await callLLM(SYSTEM_PROMPT, userMessage, { apiKey, model, baseUrl })
  } catch (e) {
    return {
      name,
      staticStatus: staticScan.status,
      staticScan,
      verdict: null,
      confidence: null,
      result: null,
      injectionSignals,
      error: e.message,
    }
  }

  const result = raw ? parseLlmResponse(raw) : null

  return {
    name,
    staticStatus: staticScan.status,
    staticScan,
    verdict: result?.verdict ?? null,
    confidence: result?.confidence ?? null,
    result,
    injectionSignals,
    llmRaw: raw,
  }
}
