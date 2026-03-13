#!/usr/bin/env node

import { resolve } from 'node:path'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { scanSkill } from '../src/scanner.mjs'
import { printResult, printSummaryTable, log, formatResultJson } from '../src/formatter.mjs'

const HELP = `
clawhub-scanner — Security scanner for ClawHub / OpenClaw AI skills

Usage:
  clawhub-scan <path> [path...]           Scan skill directories
  clawhub-scan --static <path> [path...]  Static scan only (no LLM)
  clawhub-scan --json <path> [path...]    Output JSON results
  clawhub-scan --help                     Show this help

Options:
  --static       Only run regex-based static scan (no API key needed)
  --json         Output results as JSON to stdout
  --output <dir> Save individual JSON results to directory
  --model <name> LLM model name (default: gpt-5-mini or OPENAI_EVAL_MODEL env)
  --api-key <key> OpenAI API key (default: OPENAI_API_KEY env)

Environment:
  OPENAI_API_KEY     LLM API key (required for full evaluation)
  OPENAI_EVAL_MODEL  LLM model override (default: gpt-5-mini)

Examples:
  clawhub-scan ./my-skill
  clawhub-scan --static ./skill-a ./skill-b
  clawhub-scan --json ./my-skill > result.json
  npx clawhub-scanner ./my-skill
`

function parseArgs(argv) {
  const args = { paths: [], staticOnly: false, json: false, output: null, model: null, apiKey: null }
  let i = 0
  while (i < argv.length) {
    const arg = argv[i]
    if (arg === '--help' || arg === '-h') {
      console.log(HELP)
      process.exit(0)
    } else if (arg === '--static') {
      args.staticOnly = true
    } else if (arg === '--json') {
      args.json = true
    } else if (arg === '--output' && i + 1 < argv.length) {
      args.output = argv[++i]
    } else if (arg === '--model' && i + 1 < argv.length) {
      args.model = argv[++i]
    } else if (arg === '--api-key' && i + 1 < argv.length) {
      args.apiKey = argv[++i]
    } else if (!arg.startsWith('-')) {
      args.paths.push(arg)
    } else {
      log.err(`Unknown option: ${arg}`)
      process.exit(1)
    }
    i++
  }
  return args
}

async function main() {
  const args = parseArgs(process.argv.slice(2))

  if (args.paths.length === 0) {
    console.log(HELP)
    process.exit(1)
  }

  const options = {
    staticOnly: args.staticOnly,
    ...(args.apiKey ? { apiKey: args.apiKey } : {}),
    ...(args.model ? { model: args.model } : {}),
  }

  const results = []
  const jsonResults = []

  for (const p of args.paths) {
    const dirPath = resolve(p)
    if (!existsSync(dirPath)) {
      log.err(`Directory not found: ${dirPath}`)
      continue
    }

    const r = await scanSkill(dirPath, options)
    if (!r) {
      log.warn(`Skipping ${p}: no SKILL.md found`)
      continue
    }

    results.push(r)

    if (args.json) {
      jsonResults.push(formatResultJson(r.name, r.staticScan, r.result, r.injectionSignals))
    } else {
      printResult(r.name, r.result, r.staticScan)
      if (args.staticOnly && r.injectionSignals?.length > 0) {
        log.info(`Injection Signals: ${r.injectionSignals.join(', ')}`)
      }
    }

    if (args.output) {
      mkdirSync(args.output, { recursive: true })
      const outPath = resolve(args.output, `${r.name}.json`)
      writeFileSync(outPath, JSON.stringify(formatResultJson(r.name, r.staticScan, r.result, r.injectionSignals), null, 2))
      log.ok(`Result saved: ${outPath}`)
    }
  }

  if (args.json) {
    console.log(JSON.stringify(jsonResults.length === 1 ? jsonResults[0] : jsonResults, null, 2))
  } else if (results.length > 1) {
    printSummaryTable(results)
  }

  if (!args.json && !args.staticOnly) {
    const safe = results.filter(r => r.verdict === 'benign').length
    const sus = results.filter(r => r.verdict === 'suspicious').length
    const mal = results.filter(r => r.verdict === 'malicious').length
    const fail = results.filter(r => !r.verdict).length
    log.info(`Done. benign=${safe} suspicious=${sus} malicious=${mal}${fail ? ` failed=${fail}` : ''}`)
  }
}

main().catch(e => {
  log.err(e.message)
  process.exit(1)
})
