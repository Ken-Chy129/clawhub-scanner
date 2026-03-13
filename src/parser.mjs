export function parseFrontmatter(text) {
  const match = text.match(/^---\s*\n([\s\S]*?)\n---/)
  if (!match) return {}
  return yamlParseBlock(match[1].split('\n'), { pos: 0 }, -1)
}

function yamlScalar(val) {
  if (val === 'true') return true
  if (val === 'false') return false
  if (val === 'null' || val === '~') return null
  return val.replace(/^["']|["']$/g, '')
}

function yamlParseBlock(lines, cursor, parentIndent) {
  const result = {}
  while (cursor.pos < lines.length) {
    const line = lines[cursor.pos]
    if (line.trim() === '' || line.trim().startsWith('#')) { cursor.pos++; continue }
    const indent = line.search(/\S/)
    if (indent <= parentIndent) break

    const kv = line.match(/^(\s*)([\w][\w.-]*):\s*(.*)$/)
    if (!kv) { cursor.pos++; continue }

    const key = kv[2]
    const val = kv[3].trim()
    if (val !== '') {
      result[key] = yamlScalar(val)
      cursor.pos++
    } else {
      cursor.pos++
      result[key] = yamlParseValue(lines, cursor, indent)
    }
  }
  return result
}

function yamlParseList(lines, cursor, parentIndent) {
  const result = []
  while (cursor.pos < lines.length) {
    const line = lines[cursor.pos]
    if (line.trim() === '' || line.trim().startsWith('#')) { cursor.pos++; continue }
    const indent = line.search(/\S/)
    if (indent <= parentIndent) break

    const lm = line.match(/^(\s*)-\s+(.*)$/)
    if (!lm) break

    const dashIndent = lm[1].length
    const itemContent = lm[2].trim()
    const itemKv = itemContent.match(/^([\w][\w.-]*):\s*(.*)$/)

    if (itemKv) {
      const obj = {}
      obj[itemKv[1]] = itemKv[2] ? yamlScalar(itemKv[2]) : ''
      cursor.pos++
      while (cursor.pos < lines.length) {
        const subLine = lines[cursor.pos]
        if (subLine.trim() === '' || subLine.trim().startsWith('#')) { cursor.pos++; continue }
        const subIndent = subLine.search(/\S/)
        if (subIndent <= dashIndent) break
        const subKv = subLine.match(/^(\s*)([\w][\w.-]*):\s*(.*)$/)
        if (!subKv) break
        const subKey = subKv[2]
        const subVal = subKv[3].trim()
        if (subVal) {
          obj[subKey] = yamlScalar(subVal)
          cursor.pos++
        } else {
          cursor.pos++
          obj[subKey] = yamlParseValue(lines, cursor, subIndent)
        }
      }
      result.push(obj)
    } else {
      result.push(yamlScalar(itemContent))
      cursor.pos++
    }
  }
  return result
}

function yamlParseValue(lines, cursor, parentIndent) {
  while (cursor.pos < lines.length && lines[cursor.pos].trim() === '') cursor.pos++
  if (cursor.pos >= lines.length) return ''
  const line = lines[cursor.pos]
  const indent = line.search(/\S/)
  if (indent <= parentIndent) return ''
  if (line.trim().startsWith('- ')) {
    return yamlParseList(lines, cursor, parentIndent)
  }
  return yamlParseBlock(lines, cursor, parentIndent)
}

export function resolveClawdis(frontmatter) {
  if (frontmatter.clawdis && typeof frontmatter.clawdis === 'object') return frontmatter.clawdis
  const meta = frontmatter.metadata
  if (meta && typeof meta === 'object') {
    if (meta.openclaw && typeof meta.openclaw === 'object') return meta.openclaw
    if (meta.clawdbot && typeof meta.clawdbot === 'object') return meta.clawdbot
  }
  return {}
}
