const R = '\x1b[0m', B = '\x1b[1m', DIM = '\x1b[2m'
const RED = '\x1b[31m', GRN = '\x1b[32m', YLW = '\x1b[33m', BLU = '\x1b[34m'

const VERDICT_COLORS = { benign: GRN, suspicious: YLW, malicious: RED }

export const log = {
  info: (msg) => console.log(`${BLU}[INFO]${R} ${msg}`),
  ok:   (msg) => console.log(`${GRN}[ OK ]${R} ${msg}`),
  warn: (msg) => console.log(`${YLW}[WARN]${R} ${msg}`),
  err:  (msg) => console.log(`${RED}[ERR ]${R} ${msg}`),
}

export function colorVerdict(verdict) {
  return `${VERDICT_COLORS[verdict] || ''}${B}${verdict.toUpperCase()}${R}`
}

/**
 * Print single skill scan result to terminal.
 */
export function printResult(skillName, result, staticScan) {
  console.log(`\n${'═'.repeat(60)}`)
  console.log(`${B} ${skillName}${R}`)
  console.log('═'.repeat(60))

  console.log(`\n${B}Static Scan:${R} ${staticScan.status === 'clean' ? `${GRN}clean${R}` : colorVerdict(staticScan.status)}`)
  if (staticScan.findings.length > 0) {
    for (const f of staticScan.findings) {
      const sev = f.severity === 'critical' ? RED : YLW
      console.log(`  ${sev}[${f.severity}]${R} ${f.code} — ${f.file}:${f.line}`)
      console.log(`          ${DIM}${f.message}${R}`)
    }
  }

  if (!result) {
    console.log(`\n${B}LLM Eval:${R} ${RED}SKIPPED${R}`)
    return
  }

  console.log(`\n${B}LLM Verdict:${R} ${colorVerdict(result.verdict)} (confidence: ${result.confidence})`)
  console.log(`${B}Summary:${R} ${result.summary}`)

  if (result.dimensions.length > 0) {
    console.log(`\n${B}Dimensions:${R}`)
    for (const d of result.dimensions) {
      const icon = d.status === 'ok' ? `${GRN}✓${R}` : d.status === 'concern' ? `${RED}✗${R}` : `${YLW}⚠${R}`
      console.log(`  ${icon} ${d.label}: ${d.detail}`)
    }
  }

  if (result.guidance) {
    console.log(`\n${B}User Guidance:${R}`)
    console.log(`  ${result.guidance}`)
  }
}

/**
 * Print summary table for multiple scan results.
 */
export function printSummaryTable(results) {
  console.log(`\n${'═'.repeat(70)}`)
  console.log(`${B} Summary${R}`)
  console.log('═'.repeat(70))
  console.log(`  ${'Skill'.padEnd(25)} ${'Static'.padEnd(12)} ${'LLM Verdict'.padEnd(15)} Confidence`)
  console.log(`  ${'─'.repeat(25)} ${'─'.repeat(12)} ${'─'.repeat(15)} ${'─'.repeat(10)}`)
  for (const r of results) {
    const staticCol = r.staticStatus === 'clean'
      ? `${GRN}clean${R}`.padEnd(12 + 9)
      : colorVerdict(r.staticStatus).padEnd(12 + 9)
    const llmCol = r.verdict
      ? colorVerdict(r.verdict).padEnd(15 + 9)
      : `${DIM}—${R}`.padEnd(15 + 5)
    const conf = r.confidence || '—'
    console.log(`  ${r.name.padEnd(25)} ${staticCol} ${llmCol} ${conf}`)
  }
  console.log()
}

/**
 * Format scan result as plain JSON (for programmatic output).
 */
export function formatResultJson(skillName, staticScan, llmResult, injectionSignals) {
  return {
    skill: skillName,
    timestamp: new Date().toISOString(),
    staticScan,
    injectionSignals,
    llmResult,
  }
}
