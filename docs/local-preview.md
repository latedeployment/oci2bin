# Local Preview

Use `uv` to build and preview the documentation site.

Serve locally:

```bash
uv run --group docs mkdocs serve
```

Build strictly:

```bash
uv run --locked --group docs mkdocs build --strict
```

The GitHub Pages workflow uses the same `uv run --locked --group docs` build command.
