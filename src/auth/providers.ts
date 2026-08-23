import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { isAbsolute, join, relative as relative_ } from 'node:path'
import type { ProviderReference } from '../schema/grant'
import { paths } from '../paths'

/**
 * Credential resolution behind an interface. v0 resolves explicitly named
 * environment values and owner-only files under the APImanac data directory.
 * A provider that cannot resolve a component reports the component name and
 * never where it looked.
 */

export interface ResolvedComponent {
  readonly name: string
  readonly value: string
}

export type ComponentFailureCode = 'missing' | 'unreadable' | 'insecure_permissions'

export interface ComponentFailure {
  readonly name: string
  readonly code: ComponentFailureCode
  /** Names the component only — never the variable name or the path. */
  readonly message: string
}

export type ComponentResult = ResolvedComponent | ComponentFailure

export function isResolved(result: ComponentResult): result is ResolvedComponent {
  return 'value' in result
}

export interface CredentialProvider {
  resolve(component: string, reference: ProviderReference): ComponentResult
}

function realpathSafe(path: string): string | undefined {
  try {
    return realpathSync(path)
  } catch {
    return undefined
  }
}

function isInside(candidate: string, directory: string): boolean {
  const relative = relative_(directory, candidate)
  return relative.length > 0 && !relative.startsWith('..') && !isAbsolute(relative)
}

const failure = (name: string, code: ComponentFailureCode, message: string): ComponentFailure => ({
  name,
  code,
  message,
})

export const environmentProvider: CredentialProvider = {
  resolve(component, reference) {
    if (reference.provider !== 'env') {
      return failure(
        component,
        'missing',
        `component \`${component}\` is not bound to an environment value`,
      )
    }
    const value = process.env[reference.variable]
    if (value === undefined || value === '') {
      return failure(
        component,
        'missing',
        `component \`${component}\` did not resolve; the user must activate its binding`,
      )
    }
    return { name: component, value }
  },
}

export const fileProvider: CredentialProvider = {
  resolve(component, reference) {
    if (reference.provider !== 'file') {
      return failure(component, 'missing', `component \`${component}\` is not bound to a file`)
    }
    // Confined to the credentials directory: a grant is user-written, but the
    // schema says these paths live there, so the code should agree.
    const directory = realpathSafe(paths.credentialsDir())
    const path = isAbsolute(reference.path)
      ? reference.path
      : join(paths.credentialsDir(), reference.path)
    if (!existsSync(path)) {
      return failure(
        component,
        'missing',
        `component \`${component}\` did not resolve; the user must activate its binding`,
      )
    }
    const resolved = realpathSafe(path)
    if (!directory || !resolved || !isInside(resolved, directory)) {
      return failure(
        component,
        'unreadable',
        `component \`${component}\` is bound to a file outside the APImanac credentials directory`,
      )
    }
    const mode = statSync(path).mode & 0o077
    if (mode !== 0) {
      // A group- or world-readable credential file is not usable.
      return failure(
        component,
        'insecure_permissions',
        `component \`${component}\` is stored in a file readable beyond its owner; tighten it to owner-only (0600)`,
      )
    }
    try {
      const value = readFileSync(path, 'utf8').replace(/\r?\n$/, '')
      if (value === '') {
        return failure(
          component,
          'missing',
          `component \`${component}\` resolved to an empty value`,
        )
      }
      return { name: component, value }
    } catch {
      return failure(component, 'unreadable', `component \`${component}\` could not be read`)
    }
  },
}

/** Dispatches to the provider a grant names. */
export const defaultProvider: CredentialProvider = {
  resolve(component, reference) {
    return reference.provider === 'env'
      ? environmentProvider.resolve(component, reference)
      : fileProvider.resolve(component, reference)
  },
}

/** Test-only provider, supplied through the library API and never through argv. */
export function injectedProvider(values: Readonly<Record<string, string>>): CredentialProvider {
  return {
    resolve(component) {
      const value = values[component]
      return value === undefined
        ? failure(component, 'missing', `component \`${component}\` did not resolve`)
        : { name: component, value }
    },
  }
}
