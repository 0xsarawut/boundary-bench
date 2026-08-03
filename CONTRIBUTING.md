# Contributing to Boundary-Bench

Thanks for your interest in improving Boundary-Bench. Contributions are
welcome: bug reports, fixes, documentation, new policy definitions, and
harness adapter improvements.

## Development setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/):

```bash
uv sync --extra dev --extra harbor --extra daytona
```

## Tests and linting

CI runs both of these on every PR; please run them locally first:

```bash
uv run ruff check src tests
uv run pytest -q
```

## Pull request process

1. Fork the repository and create a branch for your change.
2. Open a pull request against `main`.
3. Every PR requires a passing CI run and an approving review from a
   maintainer before it can be merged. Maintainers handle the merge.

## License

By contributing, you agree that your contributions are licensed under
the [MIT License](LICENSE).
