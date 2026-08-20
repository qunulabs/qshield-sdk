// Removes the compiled test output, so a deleted test file cannot keep passing
// from a stale build.
import { rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

await rm(join(packageRoot, '.test-out'), { recursive: true, force: true })
