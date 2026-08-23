# APImanac

A CLI to manage public APIs for AI agent to use.

## Install

```sh
bun install --frozen-lockfile
bun run tsc --noEmit && bun test
bun build --compile --outfile dist/apimanac src/cli.ts
install -Dm755 dist/apimanac ~/.local/bin/apimanac
```

`mise run <task>` and `nix develop` expose the same commands.

## Configuring the catalog root

1. `--catalog <path>`
2. `APIMANAC_CATALOG`
3. `catalog_root` in `$XDG_CONFIG_HOME/apimanac/config.yaml`

The catalog root is never discovered — the working directory is not consulted.
Start from the example:

```sh
cp -r examples/starter ~/my-catalog
cd ~/my-catalog && git init && git add -A && git commit -m 'start from the example'
export APIMANAC_CATALOG=~/my-catalog
```

### Catalog layout

```
catalog/
  manifest.yaml                      # schema version and the api source list
  meta/<api-id>.yaml                 # meta for each api
  execution/<api-id>/<profile>.yaml  # execution configs for each api
  sources/<source>/manifest.yaml     # upstream revision, content hash, counts
  sources/<source>/outcomes.yaml     # one outcome per upstream entry
  specs/                             # only specifications a verified profile needs
```

## Commands

```
build          validate the catalog and rebuild the derived store, offline
search         ranked search over the discovery projection
show           one record: profiles, permissions, hashes, readiness, health
add            write an uncommitted candidate from a URL, or --manual
refresh        run a source adapter over fetched input (--payload, --pin), or
               apply a field-level candidate (--candidate)
validate       integrity check
migrate        schema step
auth status    credential check
call           send one request
verify         verify public api
cache list     origin, path and account labels
cache clear    remove cached response
cache prune    remove expired entries
mcp            stdio MCP server: search_apis, get_api, call_api
```

`--json` after each command to output in json format. `apimanac <command> --help`
documents that command's flags.

## Review and commit new apis

```sh
apimanac add https://api.example.com/openapi.json
git diff                                        # review the candidates
git add catalog/ && git commit -m 'add example'
```

`add`, `refresh`, `migrate` and `verify` only ever write uncommitted worktree
changes. APImanac never stages, commits, pushes or merges.

A profile is callable only when its file is tracked, byte-identical to `HEAD`,
valid, `verified`, and evidence-matched — plus, when it needs a credential,
paired with a ready grant whose fingerprint matches. The committed blob is
re-read before every call, so an edit after the last build refuses the next call
rather than executing under the edited rule.

## Modify an authenticated profile

Certain APIs need local credentials to execute.

```sh
$EDITOR $CATALOG/catalog/execution/github/pat.yaml   # 1. write the candidate

apimanac show github                                 # 2. read its fingerprint
#     verification: candidate
#     authority fingerprint: v1:sha256:7b529b4d…

$EDITOR $XDG_CONFIG_HOME/apimanac/grants.yaml        # 3. activate a grant, by hand
chmod 600 $XDG_CONFIG_HOME/apimanac/grants.yaml

apimanac verify github --profile pat                 # 4. probe it, answering the prompt
#   Send it? [y/N] y

git add catalog/ && git commit -m 'verify github/pat'  # 5. commit profile + evidence
```

```yaml
# $XDG_CONFIG_HOME/apimanac/grants.yaml — owner-only, untracked
version: 1
grants:
  - credential_id: github-pat
    api_id: github
    profile_id: pat
    origins: [https://api.github.com]
    authority_fingerprint: v1:sha256:7b529b4d…    # from `apimanac show`
    accounts:
      - name: personal
        default: true
        components:
          token: { provider: env, variable: MY_GITHUB_PAT }
```

## Calling

```sh
apimanac call openalex --path /works --query 'per-page=1,filter=is_oa:true'
apimanac call github --profile pat --path /user
apimanac call openalex --path /works/W2741809807 --response file
```

Call can save response to file in case the response is large.

## MCP configuration

```json
{
  "mcpServers": {
    "apimanac": {
      "command": "apimanac",
      "args": ["mcp"],
      "env": { "APIMANAC_CATALOG": "/home/you/apimanac-catalog" }
    }
  }
}
```

Confirmed operations need a client that negotiates elicitation at protocol
revision `2025-06-18` or later. The server speaks stdio and opens no listener.

Skill: `skill/SKILL.md`. Every command and tool behaves identically without it.
