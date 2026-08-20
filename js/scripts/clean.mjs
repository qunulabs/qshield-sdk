// Removes the build output. Kept as a script rather than `rm -rf` so the build
// works the same way on Windows, where a developer may run pnpm from cmd.
import { rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)))

await rm(join(packageRoot, 'dist'), { recursive: true, force: true })
