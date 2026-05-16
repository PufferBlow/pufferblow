# Contributing to Pufferblow

Pufferblow is an open-source, self-hosted community server. We welcome
contributions — bug fixes, features, docs, tests, and discussions about
where the project should go next.

This guide is for **server-side** contributions in this repo. The
official client lives at [`PufferBlow/client`](https://github.com/PufferBlow/client),
the voice SFU at [`PufferBlow/media-sfu`](https://github.com/PufferBlow/media-sfu),
and the Python SDK at [`PufferBlow/pypufferblow`](https://github.com/PufferBlow/pypufferblow);
each has its own contributing notes.

## Before you start

1. **Check existing issues and PRs.** If you're about to fix
   something or add a feature, search first — there may already
   be an open discussion.
2. **For non-trivial changes, open an issue first.** A short
   write-up of what you intend to do, before you write the code,
   saves both of us time. "Non-trivial" means anything that
   touches the data model, adds a new dependency, changes a
   public API shape, or refactors more than one module.
3. **Read [`SECURITY.md`](./SECURITY.md)** before reporting
   vulnerabilities — those go through a private channel, not a
   PR.

## Development setup

Pufferblow uses [Poetry](https://python-poetry.org/) for dependency
management and Python 3.10+ for the server.

```bash
git clone https://github.com/PufferBlow/pufferblow.git
cd pufferblow
poetry install
poetry run pufferblow setup    # generates config.toml
poetry run pufferblow serve    # starts the API server
```

The server expects a Postgres database, a memcached instance, and
(optionally) S3-compatible object storage. The fastest path to a
working dev environment is the Docker Compose stack — see
[`DOCKER_PRODUCTION.md`](./DOCKER_PRODUCTION.md) for the full
config; for dev you only need the `postgres` and `memcached`
services.

## Code style

- **Lint**: `poetry run ruff check pufferblow/` (CI runs this; PRs
  red on lint failure won't be reviewed until they're green).
- **Types**: we type-hint new code. Existing untyped code is
  fair game to annotate as you touch it — incremental adoption,
  not a flag day.
- **Format**: Ruff handles both lint and format. Don't introduce
  trailing whitespace or mixed indentation.
- **Imports**: standard library, then third-party, then local —
  Ruff enforces this.

## Commit messages

We follow a relaxed [Conventional Commits](https://www.conventionalcommits.org/)
style. The prefix tells the reader what kind of change this is:

```
feat(voice): ...        new feature
fix(auth): ...          bug fix
refactor(db): ...       no behavior change, restructured
docs(api): ...          documentation only
test(channels): ...     test-only change
chore(deps): ...        dependency bumps, build tooling
perf(media): ...        performance improvement
```

Commit subjects are lowercase, under 72 characters, no trailing
period. Bodies are wrapped at 72 columns and explain **why**,
not just **what** — the diff already shows the what.

## Pull requests

- One logical change per PR. If you've got two unrelated fixes,
  open two PRs.
- Include tests for new behavior. For bug fixes, add a regression
  test that fails on the parent commit and passes on yours.
- Update relevant docs in the same PR. If you change a CLI
  command, update `ADMIN.md`; if you change federation behavior,
  update `FEDERATION.md`.
- Link the issue you're closing in the PR description
  (`Closes #123`).
- Don't squash commits in your PR branch — we squash on merge if
  the history needs it; preserve your incremental commits so we
  can see how you arrived at the final shape.

CI runs `ruff` and `pytest`. PRs need green CI plus one
maintainer approval to merge.

## Testing

```bash
poetry run pytest                    # full suite
poetry run pytest pufferblow/tests/test_auth.py     # one file
poetry run pytest -k "federation"   # match by name
```

New code should land with tests. If you've changed a manager
(`pufferblow/api/managers/*.py`) the request-level tests under
`pufferblow/tests/api/` are usually the right home.

## Reporting bugs

- Open an issue at [github.com/PufferBlow/pufferblow/issues](https://github.com/PufferBlow/pufferblow/issues).
- Include: Python version, OS, the commit SHA you're running, a
  minimal reproduction, and the relevant server logs (redact
  tokens before pasting).
- Security issues: do **not** open a public issue — see
  [`SECURITY.md`](./SECURITY.md).

## Code of conduct

By participating, you agree to abide by the
[Code of Conduct](./CODE_OF_CONDUCT.md). Be excellent to each
other.

## Questions

- General usage: [GitHub Discussions](https://github.com/PufferBlow/pufferblow/discussions).
- Real-time chat: the project's own instance (linked from the
  README), once it's publicly available.
