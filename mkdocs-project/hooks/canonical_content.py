"""Expose canonical virtual mounts and enforce URL lifecycle during MkDocs builds."""

from __future__ import annotations

import json
import html
import subprocess
from pathlib import Path

from mkdocs.structure.files import File, Files


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LIFECYCLE_PATH = REPOSITORY_ROOT / "publishing" / "content-status.json"
MERMAID_RUNTIME_PATH = REPOSITORY_ROOT / "node_modules" / "mermaid" / "dist" / "mermaid.min.js"
MERMAID_RUNTIME_DESTINATION = "js/vendor/mermaid.min.js"
VIRTUAL_MOUNTS = (
    (REPOSITORY_ROOT / "labs", Path("labs")),
    (REPOSITORY_ROOT / "site-pages", Path(".")),
)
DOCS_CATALOG: dict[str, object] = {}


def _build_docs_catalog() -> dict[str, object]:
    """Build normalized UI/navigation data from canonical repository inputs."""

    command = ["node", "scripts/render-docs-data.mjs"]
    completed = subprocess.run(
        command,
        cwd=REPOSITORY_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"documentation catalog generation failed: {detail}")
    return json.loads(completed.stdout)


def _generated_nav(catalog: dict[str, object]) -> list[object]:
    navigation = catalog["navigation"]
    research = ["research/index.md"]
    for group in navigation["researchGroups"]:
        children: list[object] = [group["index"]]
        children.extend({item["title"]: item["path"]} for item in group["children"])
        research.append({group["title"]: children})

    labs: list[object] = ["labs/index.md"]
    labs.extend({item["title"]: item["path"]} for item in navigation["labs"])
    scripts: list[object] = ["scripts/index.md"]
    scripts.extend({item["title"]: item["path"]} for item in navigation["scriptCategories"])
    return [
        {"Home": "index.md"},
        {"Research": research},
        {"Labs": labs},
        {"Scripts": scripts},
        {"Study notes": [
            "study-notes/index.md",
            {"AZ-900": [
                "docs/certification-notes/az-900/README.md",
                {"Domain 1 - Cloud concepts": "docs/certification-notes/az-900/domain-1-concepts.md"},
                {"Domain 2 - Architecture and services": "docs/certification-notes/az-900/domain-2-architecture-services.md"},
                {"Domain 3 - Management and governance": "docs/certification-notes/az-900/domain-3-management-governance.md"},
            ]},
            {"SC-500": [
                "docs/certification-notes/sc-500/README.md",
                {"Domain 1 - Identity": "docs/certification-notes/sc-500/domain-1-identity.md"},
                {"Domain 2 - Storage and networking": "docs/certification-notes/sc-500/domain-2-storage-networking.md"},
                {"Domain 3 - Secure compute": "docs/certification-notes/sc-500/domain-3-secure-compute.md"},
                {"Domain 4 - Manage and monitor posture": "docs/certification-notes/sc-500/domain-4-manage-monitor-posture.md"},
            ]},
            {"Security+": "docs/certification-notes/security-plus/README.md"},
            {"Google Cybersecurity": "docs/certification-notes/google-cybersecurity/README.md"},
        ]},
        {"About": "about/index.md"},
    ]


def on_config(config):
    """Build the canonical catalog before MkDocs resolves navigation."""

    global DOCS_CATALOG
    DOCS_CATALOG = _build_docs_catalog()
    config.nav = _generated_nav(DOCS_CATALOG)
    return config


def _lifecycle() -> dict[str, dict[str, object]]:
    return json.loads(LIFECYCLE_PATH.read_text(encoding="utf-8"))


def on_files(files: Files, config) -> Files:
    """Add Markdown from virtual mounts without duplicating source files."""

    existing = {file.src_uri for file in files}
    if not MERMAID_RUNTIME_PATH.is_file():
        raise RuntimeError("Mermaid runtime is missing; run npm ci before building documentation")
    if MERMAID_RUNTIME_DESTINATION in existing:
        raise RuntimeError(f"generated documentation path collides: {MERMAID_RUNTIME_DESTINATION}")
    files.append(
        File.generated(
            config,
            MERMAID_RUNTIME_DESTINATION,
            content=MERMAID_RUNTIME_PATH.read_text(encoding="utf-8"),
        )
    )
    existing.add(MERMAID_RUNTIME_DESTINATION)
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


def on_page_markdown(markdown: str, page, config, files) -> str:
    """Move the first H1 of component-managed pages into the Jinja header."""

    source = page.file.src_uri
    item = DOCS_CATALOG.get("pageMap", {}).get(source)
    if source == "index.md":
        page.meta["description"] = config.site_description
        return ""
    if not item:
        return markdown
    title = str(item["title"])
    expected = f"# {title}"
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != expected:
        raise RuntimeError(f"{source}: expected first heading {expected!r}")
    page.meta["description"] = item.get("summary") or config.site_description
    body = "\n".join(lines[1:]).lstrip()
    if item.get("kind") == "script-category":
        # Category Markdown owns only the short introduction. Script details are
        # generated from the canonical YAML catalog to avoid two implementations.
        body = body.split('\n<div id="', 1)[0].rstrip()
    return body


def on_page_context(context, page, config, nav):
    """Expose normalized page and homepage data to semantic Jinja partials."""

    source = page.file.src_uri
    context["docs_catalog"] = DOCS_CATALOG
    context["docs_page"] = DOCS_CATALOG.get("pageMap", {}).get(source)
    context["docs_home"] = source == "index.md"
    return context


def on_post_build(config):
    """Add concise catalog context to Material's generated search records."""

    search_path = Path(config.site_dir) / "search" / "search_index.json"
    if not search_path.exists():
        raise RuntimeError("Material search index was not generated")
    payload = json.loads(search_path.read_text(encoding="utf-8"))
    by_location: dict[str, dict[str, object]] = {}
    for item in DOCS_CATALOG.get("pageMap", {}).values():
        if not item.get("url"):
            continue
        by_location[str(item["url"]).strip("/") + "/"] = item
    labels = {"research": "Research", "lab": "Lab", "script-category": "Scripts"}
    for record in payload.get("docs", []):
        item = by_location.get(str(record.get("location", "")))
        if not item:
            continue
        context = f'{item.get("domainLabel", "")} · {labels.get(item.get("kind"), "Content")}'
        summary = str(item.get("summary") or "")
        prefix = f'<p>{html.escape(context)}</p>'
        if summary:
            prefix += f'<p>{html.escape(summary)}</p>'
        record["text"] = f'{prefix} {record.get("text", "")}'.strip()
    search_path.write_text(json.dumps(payload, separators=(",", ":")), encoding="utf-8")
