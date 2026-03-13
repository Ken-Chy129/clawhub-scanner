import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { join, extname } from 'node:path'
import { SCAN_FILE_EXTENSIONS } from './constants.mjs'
import { parseFrontmatter } from './parser.mjs'

const SKIP_DIRS = new Set(['__pycache__', 'node_modules', '.git'])

/**
 * Read and parse a skill directory.
 *
 * @param {string} dirPath - Absolute path to the skill directory
 * @returns {{ skillMd: string, frontmatter: object, files: { path: string, size: number, content: string }[] } | null}
 */
export function readSkillDir(dirPath) {
  const skillMdPath = join(dirPath, 'SKILL.md')
  if (!existsSync(skillMdPath)) return null

  const skillMd = readFileSync(skillMdPath, 'utf-8')
  const frontmatter = parseFrontmatter(skillMd)

  const files = []

  const walk = (dir, prefix) => {
    for (const entry of readdirSync(dir)) {
      if (entry.startsWith('.') && entry !== '.gitignore') continue
      const full = join(dir, entry)
      const rel = prefix ? `${prefix}/${entry}` : entry
      const stat = statSync(full)
      if (stat.isDirectory()) {
        if (SKIP_DIRS.has(entry)) continue
        walk(full, rel)
      } else if (rel.toLowerCase() !== 'skill.md' && SCAN_FILE_EXTENSIONS.has(extname(entry).toLowerCase())) {
        try {
          const content = readFileSync(full, 'utf-8')
          files.push({ path: rel, size: stat.size, content })
        } catch { /* skip binary files */ }
      }
    }
  }
  walk(dirPath, '')

  return { skillMd, frontmatter, files }
}
