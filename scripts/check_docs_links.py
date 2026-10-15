"""Check generated documentation links and fragment identifiers without network access."""

import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit


class PageLinks(HTMLParser):
    """Collect local link targets and identifiers from a generated HTML page."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.identifiers: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = dict(attrs)
        if identifier := attributes.get("id"):
            self.identifiers.add(identifier)
        for key in ("href", "src"):
            if value := attributes.get(key):
                self.links.append(value)


def check_site(site: Path, base_path: str) -> list[str]:
    """Return missing local file and fragment errors across the generated site."""
    pages: dict[Path, PageLinks] = {}
    for path in site.rglob("*.html"):
        parsed = PageLinks()
        parsed.feed(path.read_text(encoding="utf-8"))
        pages[path.resolve()] = parsed
    if not pages:
        return [f"No HTML pages found in {site}; build the documentation first."]
    errors = []
    for path, parsed in pages.items():
        for link in parsed.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            if url.path.startswith("/"):
                if not url.path.startswith(base_path):
                    errors.append(f"{path.relative_to(site)}: outside site base: {link}")
                    continue
                target = site / unquote(url.path[len(base_path):])
            else:
                target = path.parent / unquote(url.path) if url.path else path
            target = target.resolve()
            if target.is_dir():
                target /= "index.html"
            if not target.is_relative_to(site) or not target.exists():
                errors.append(f"{path.relative_to(site)}: missing local file: {link}")
            elif url.fragment and target in pages:
                if unquote(url.fragment) not in pages[target].identifiers:
                    errors.append(f"{path.relative_to(site)}: missing anchor: {link}")
    print(f"Checked {len(pages)} HTML pages; found {len(errors)} local link errors.")
    return errors


def main() -> int:
    """Check a built site and exit unsuccessfully when any local link is broken."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=Path("site"))
    parser.add_argument("--base-path", default="/open-devops-agent/")
    args = parser.parse_args()
    errors = check_site(args.site.resolve(), args.base_path)
    for error in errors:
        print(error)
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
