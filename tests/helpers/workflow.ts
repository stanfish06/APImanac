import { readFileSync } from 'node:fs'
import { sha256Tagged } from '../../src/catalog/canonical'
import { profilePath, workflowPath, workflowScriptPath } from '../../src/catalog/load'
import type { ParamsSchemaNode } from '../../src/schema/workflow'
import type { TempRepo } from './repo'

/**
 * Workflow fixtures. Binding digests are computed from the worktree profile
 * file, which equals the blob digest whenever the profile is committed clean —
 * exactly the state the execution fixture leaves its profiles in.
 */

export function profileDigest(repo: TempRepo, apiId: string, profileId: string): string {
  return sha256Tagged(readFileSync(repo.path(profilePath(apiId, profileId))))
}

export interface WorkflowFixture {
  readonly apiId: string
  readonly workflowId: string
  /** `<api-id>/<profile-id>` keys to bind, digests resolved from the repo. */
  readonly bindings: readonly string[]
  readonly script: string
  readonly params?: ParamsSchemaNode
  readonly description?: string
}

export function writeWorkflow(repo: TempRepo, fixture: WorkflowFixture): void {
  repo.writeYaml(workflowPath(fixture.apiId, fixture.workflowId), {
    workflow_id: fixture.workflowId,
    api_id: fixture.apiId,
    description: fixture.description ?? '',
    bindings: fixture.bindings.map((profile) => {
      const [api, id] = profile.split('/') as [string, string]
      return { profile, blob_sha256: profileDigest(repo, api, id) }
    }),
    ...(fixture.params ? { params: fixture.params } : {}),
  })
  repo.write(workflowScriptPath(fixture.apiId, fixture.workflowId), fixture.script)
}
