/**
 * The other half of the route drift guard.
 *
 * A Go test in backend/internal/router proves that every route this package
 * DECLARES is still mounted by qshield. That catches a rename inside qshield. It
 * cannot catch the opposite and likelier mistake: adding a call and forgetting
 * to declare it, which leaves the route unguarded and a customer's integration
 * free to break on the next rename.
 *
 * So this walks the source for qshield paths and insists each one is declared.
 * Paths only - the verb is not visible in a string literal, and the Go guard
 * checks the verb on everything that reaches it.
 */

import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'

/** Any qshield route, written as a literal anywhere in the source. */
const ROUTE_IN_SOURCE = /['"`](\/api\/v1\/[^'"`\s]*)['"`]/g

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name)
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full))
    else if (full.endsWith('.ts')) out.push(full)
  }
  return out
}

/**
 * Reduces a path to its shape, so a declaration and a call agree without having
 * to agree on parameter names. The manifest writes the router's `{key_id}`; the
 * source interpolates whatever the method called its argument.
 */
function shapeOf(route: string): string {
  return route.replace(/\$\{[^}]*\}/g, '{}').replace(/\{[^}]*\}/g, '{}')
}

const declared = new Set(
  readFileSync(path.join(process.cwd(), 'routes.manifest'), 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('#'))
    .map((line) => shapeOf(line.split(/\s+/)[1] ?? '')),
)

const called = new Map<string, string>()
for (const file of sourceFiles(path.join(process.cwd(), 'src'))) {
  const text = readFileSync(file, 'utf8')
  for (const match of text.matchAll(ROUTE_IN_SOURCE)) {
    const route = match[1]
    if (route !== undefined) called.set(shapeOf(route), path.basename(file))
  }
}

test('the manifest declares at least one route, and the source calls at least one', () => {
  // Both sides can go empty and leave the comparison below passing while it
  // checks nothing at all.
  assert.ok(declared.size > 0, 'routes.manifest declares nothing')
  assert.ok(called.size > 0, 'no qshield route was found in the source; the scan is not working')
})

test('every qshield route the source calls is declared in the manifest', () => {
  const undeclared = [...called.entries()]
    .filter(([shape]) => !declared.has(shape))
    .map(([shape, file]) => `  ${shape}  (called from ${file})`)

  assert.deepEqual(
    undeclared,
    [],
    'these routes are called but not declared in sdk/js/routes.manifest:\n' +
      `${undeclared.join('\n')}\n\n` +
      'Add each one as "METHOD /path" in the same change that added the call. An ' +
      'undeclared route is one qshield can rename without anything turning red, and the ' +
      "first sign of it would be a customer's integration failing after an upgrade.",
  )
})
