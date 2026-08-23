# Starter catalog

Five hand-curated public APIs, enough to exercise every part of APImanac. This
directory is a catalog root: it is what CI validates and builds against, and
what the test suite copies as a fixture. **APImanac never reads it implicitly**
— the catalog root is always configured, never discovered.

Copy it to start your own catalog:

```sh
cp -r examples/starter ~/my-catalog
cd ~/my-catalog && git init && git add -A && git commit -m 'start from the example'
export APIMANAC_CATALOG=~/my-catalog
apimanac validate
```

Every profile here ships as `candidate`, so nothing is callable until you run
`apimanac verify <api> --profile <profile>` and commit the evidence. That is the
point: the example cannot hand you live authority.

| API | Profiles | Auth |
|---|---|---|
| `openalex` | `public` | none |
| `crossref` | `public` | none |
| `datacite` | `public` | none |
| `ncbi-eutils` | `public`, `keyed` | none / query key |
| `github` | `pat` | bearer |

`catalog/sources/` is absent on purpose: no upstream import is committed here.
Adapters take already-fetched input, so `refresh` needs the payload and its pin:

```sh
apimanac refresh public-apis --payload entries.json --pin pin.yaml
apimanac refresh nango       --payload providers.yaml --pin pin.yaml --scopes scopes.yaml
apimanac refresh apis-guru   --payload list.json --pin pin.yaml --specs ./specs
```

`--specs` holds one file per upstream list id, with `/` written as `__` — so
`googleapis.com:drive` is `googleapis.com:drive.json`. Without it the APIs.guru
import is metadata-only, since origins come from the specification and never
from the list.

A `pin.yaml` records what you fetched:

```yaml
revision: <commit id, tag, or dated version>
content_hash: v1:sha256:<hex of the payload>
retrieved_at: 2026-08-23T00:00:00Z
```
