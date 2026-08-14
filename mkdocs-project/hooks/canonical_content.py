"""Expose canonical virtual mounts and enforce URL lifecycle during MkDocs builds."""

from __future__ import annotations

import json
from pathlib import Path

from mkdocs.structure.files import File, Files


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_PATH = REPOSITORY_ROOT / "publishing" / "content-status.json"
VIRTUAL_MOUNTS = (
    (REPOSITORY_ROOT / "labs", Path("labs")),
    (REPOSITORY_ROOT / "site-pages", Path(".")),
)


def _lifecycle() -> dict[str, dict[str, object]]:
    return json.loads(LIFECYCLE_PATH.read_text(encoding="utf-8"))


def on_files(files: Files, config) -> Files:
    """Add Markdown from virtual mounts without duplicating source files."""

    existing = {file.src_uri for file in files}
    for source_root, destination_root in VIRTUAL_MOUNTS:
        for source in sorted(source_root.rglob("*.md")):
            if any(part in {"node_modules", ".venv", ".terraform"} for part in source.parts):
                continue
            relative = source.relative_to(source_root)
            destination = (destination_root / relative).as_posix()
            if destination.startswith("./"):
                destination = destination[2:]
            if destination in existing:
                # The repository README is still exposed through a legacy
                # index.md symlink for contributor tooling. The site homepage
                # has its own canonical Markdown and intentionally replaces it.
                if source_root == REPOSITORY_ROOT / "site-pages" and destination == "index.md":
                    for current in list(files):
                        if current.src_uri == destination:
                            files.remove(current)
                    existing.remove(destination)
                else:
                    raise RuntimeError(f"virtual documentation path collides: {destination}")
            files.append(
                File.generated(
                    config,
                    destination,
                    content=source.read_text(encoding="utf-8"),
                )
            )
            existing.add(destination)

    lifecycle = _lifecycle()
    by_url = {
        "/" if not file.url else f"/{file.url}": file
        for file in files
        if file.is_documentation_page()
    }
    for url, record in sorted(lifecycle.items()):
        if record.get("status") != "archived":
            continue
        source_uri = f"{url.strip('/')}/index.md"
        original = by_url.get(url)
        if original is not None:
            files.remove(original)
        title = str(record.get("title", "Previous content"))
        for prefix in ("Old page: ", "Archived reference: "):
            if title.startswith(prefix):
                title = title[len(prefix) :]
        archive_markdown = f"""---
title: {json.dumps(f"Old page: {title}")}
robots: "noindex, nofollow"
---

# Old page: {title}

!!! warning "Archived reference"

    This URL is retained so historical links do not break. The previous content
    is retired, excluded from current guidance, and must not be treated as
    technically current or implementation evidence.
"""
        generated = File.generated(config, source_uri, content=archive_markdown)
        files.append(generated)
        by_url[url] = generated
    return files
