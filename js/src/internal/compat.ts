/**
 * Telling the customer when this library and their qshield are too far apart.
 *
 * The obvious model - say something whenever the two versions differ - was
 * rejected. qshield ships patch releases often, and an advisory that appears on
 * every patch is one people stop reading within a month. So qshield names the
 * OLDEST library release it still supports, and only two situations are worth a
 * word: this library is older than that floor, or it is newer than qshield
 * itself and may ask for something that is not there yet. Everything between is
 * normal and says nothing.
 *
 * It advises and never fails. A library that refused to run on a version
 * mismatch would turn a routine qshield upgrade into a simultaneous outage
 * across every integration a customer has built.
 *
 * The two versions arrive on the token exchange, which the library has to make
 * before it can do anything else, so the advisory costs no request of its own.
 *
 * Only the release numbers are compared. A leading `v` and any suffix after the
 * patch number are removed first, so a development or customer-specific build
 * counts as its own release rather than as something older than itself. Any
 * value that is not three numbers is treated as unknown and silences the check
 * outright, which is what keeps an unstamped build quiet.
 */

import type { VersionsSeen } from './token.js'
import { SDK_VERSION } from './version.js'

/** A release, reduced to the three numbers that are compared. */
export interface Release {
  readonly major: number
  readonly minor: number
  readonly patch: number
}

const RELEASE_PATTERN = /^(\d+)\.(\d+)\.(\d+)$/

/**
 * Whether a version string names a published release of this library.
 *
 * A published release is always three plain numbers, because a prerelease tag
 * is never published, and the version this library carries when it was built
 * from source is a prerelease of nothing. So a suffix on THIS library's own
 * version means it was not published, and the check has nothing to compare.
 *
 * Note that the rule is deliberately one-sided. A qshield deployment may well
 * be running a prerelease build, and that build is genuinely its own release,
 * so a suffix on the DEPLOYMENT's version is stripped rather than rejected.
 */
export function isPublishedRelease(raw: string): boolean {
  const text = raw.trim()
  return RELEASE_PATTERN.test(text.startsWith('v') || text.startsWith('V') ? text.slice(1) : text)
}

/**
 * Reads a release out of a version string, or reports that it cannot.
 *
 * Handles the shapes qshield actually produces: a bare number, a tag with a
 * leading `v`, a prerelease such as `v0.14.0-dev1`, a build description such as
 * `v0.14.0-3-gabc1234-dirty`, and the placeholders a build that was never
 * stamped reports.
 */
export function parseRelease(raw: string | undefined): Release | undefined {
  if (typeof raw !== 'string') return undefined

  let text = raw.trim()
  if (text.startsWith('v') || text.startsWith('V')) text = text.slice(1)

  const cut = text.search(/[-+]/)
  if (cut !== -1) text = text.slice(0, cut)

  const match = RELEASE_PATTERN.exec(text)
  if (match === null) return undefined

  const [, major, minor, patch] = match as unknown as [string, string, string, string]
  return { major: Number(major), minor: Number(minor), patch: Number(patch) }
}

/** Orders two releases: negative if a is older, zero if equal, positive if newer. */
export function compareReleases(a: Release, b: Release): number {
  if (a.major !== b.major) return a.major - b.major
  if (a.minor !== b.minor) return a.minor - b.minor
  return a.patch - b.patch
}

function shown(release: Release): string {
  return `${release.major}.${release.minor}.${release.patch}`
}

/**
 * The sentence to pass to the warning handler, or nothing when the pair is fine
 * or cannot be judged.
 *
 * Pure, so it can be read and tested on its own.
 */
export function advisoryFor(
  seen: VersionsSeen,
  sdkVersion: string = SDK_VERSION,
): string | undefined {
  // Built from source, or otherwise never published. Comparing such a build
  // against a real deployment would nag every developer on every run and teach
  // them to ignore the advisory.
  if (!isPublishedRelease(sdkVersion)) return undefined

  const mine = parseRelease(sdkVersion)
  const deployment = parseRelease(seen.qshieldVersion)
  const floor = parseRelease(seen.minSdkVersion)
  if (mine === undefined || deployment === undefined || floor === undefined) return undefined

  if (compareReleases(mine, floor) < 0) {
    return (
      `This qshield client library is version ${shown(mine)}, and the qshield at this address ` +
      `supports version ${shown(floor)} and newer. Some calls may fail. Upgrade the ` +
      `@qnulabs/qshield-sdk package to version ${shown(floor)} or later.`
    )
  }

  if (compareReleases(mine, deployment) > 0) {
    return (
      `This qshield client library is version ${shown(mine)} and the qshield at this address ` +
      `is version ${shown(deployment)}. The library is newer than the deployment and may ask ` +
      `for something the deployment does not offer yet. Install version ${shown(deployment)} ` +
      `of the @qnulabs/qshield-sdk package, or ask for the deployment to be upgraded.`
    )
  }

  return undefined
}
