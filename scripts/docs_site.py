"""Publish existing root Markdown alongside docs without duplicating source files."""

import posixpath
import re
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

from mkdocs.config.defaults import MkDocsConfig
from mkdocs.structure.files import File, Files
from mkdocs.structure.pages import Page

ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCS = {path.name: path for path in ROOT.glob("*.md")}
REPOSITORY = "https://github.com/open-devops-agent/open-devops-agent"
LINK = re.compile(r"(\]\()([^\s)]+)(\))")


def on_files(files: Files, config: MkDocsConfig) -> Files:
    """Add root guides as generated pages while leaving their sources untouched."""
    for name, source in sorted(ROOT_DOCS.items()):
        files.append(File.generated(config, f"project/{name}", abs_src_path=str(source)))
    return files


def on_page_markdown(markdown: str, page: Page, config: MkDocsConfig, files: Files) -> str:
    """Map repository links to site pages or GitHub without copying code or config."""
    uri = page.file.src_uri
    source = ROOT_DOCS[Path(uri).name] if uri.startswith("project/") else ROOT / "docs" / uri

    def rewrite(match: re.Match[str]) -> str:
        url = urlsplit(match[2])
        if url.scheme or url.netloc or url.path.startswith("/"):
            return match[0]
        fragment = re.sub(r"-+", "-", url.fragment)
        if not url.path:
            return f"{match[1]}#{fragment}{match[3]}" if fragment else match[0]
        target = (source.parent / unquote(url.path)).resolve()
        # A few older indexes link root-level guides as if they were in docs/.
        if not target.exists() and Path(url.path).name in ROOT_DOCS:
            target = ROOT_DOCS[Path(url.path).name]
        if not target.exists() and (ROOT / "docs" / Path(url.path).name).is_file():
            target = ROOT / "docs" / Path(url.path).name
        if not target.is_relative_to(ROOT):
            return match[0]
        relative = target.relative_to(ROOT)
        if target.suffix == ".md" and target.is_file():
            if target.parent == ROOT:
                destination = f"project/{target.name}"
            elif target.is_relative_to(ROOT / "docs"):
                destination = target.relative_to(ROOT / "docs").as_posix()
            else:
                link = f"{REPOSITORY}/blob/main/{quote(relative.as_posix())}"
                if url.fragment:
                    link += f"#{url.fragment}"
                return f"{match[1]}{link}{match[3]}"
            path = posixpath.relpath(destination, posixpath.dirname(uri) or ".")
            rewritten = urlunsplit(("", "", quote(path), url.query, fragment))
        elif target.exists():
            kind = "tree" if target.is_dir() else "blob"
            rewritten = f"{REPOSITORY}/{kind}/main/{quote(relative.as_posix())}"
            if url.fragment:
                rewritten += f"#{url.fragment}"
        else:
            return match[0]
        return f"{match[1]}{rewritten}{match[3]}"

    lines = []
    fence = None
    for line in markdown.splitlines(keepends=True):
        stripped = line.lstrip()
        if stripped.startswith(("```", "~~~")):
            marker = stripped[:3]
            fence = None if fence == marker else marker if fence is None else fence
            lines.append(line)
        else:
            lines.append(line if fence else LINK.sub(rewrite, line))
    return "".join(lines)
