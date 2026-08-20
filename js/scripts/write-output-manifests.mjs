// The package declares "type": "module", so every emitted .js file is treated as
// an ES module by default. The CommonJS output needs the opposite, and Node
// resolves that from the nearest package.json. Writing one manifest into each
// output directory is what makes `import` and `require` both work without a
// bundler and without renaming files to .mjs and .cjs.
import { writeFile } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

const manifests = [
  ['dist/esm/package.json', { type: 'module' }],
  ['dist/cjs/package.json', { type: 'commonjs' }],
]

for (const [relativePath, manifest] of manifests) {
  await writeFile(join(packageRoot, relativePath), `${JSON.stringify(manifest, null, 2)}\n`)
}
