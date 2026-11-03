"""Check local HTML links and fragment targets in the actual staged website."""
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get("id"):
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            value = attrs.get(key)
            if value:
                self.links.append(value)


root = Path(sys.argv[1] if len(sys.argv) > 1 else ".artifacts/site").resolve()
parsed = {}
for file in root.rglob("*.html"):
    document = Links()
    document.feed(file.read_text())
    parsed[file] = document
errors, checked = [], 0
for file, document in parsed.items():
    route = "/" + file.relative_to(root).as_posix()
    if route.endswith("index.html"):
        route = route[:-10]
    for link in document.links:
        raw = urlsplit(link)
        if raw.scheme not in ("", "http", "https") or (raw.netloc and raw.netloc != "docs.jasonachkardiab.com"):
            continue
        absolute = urlsplit(urljoin(route, link))
        path = unquote(absolute.path).lstrip("/")
        target = (root / path).resolve()
        if target != root and root not in target.parents:
            errors.append(f"{route}: escapes site: {link}")
            continue
        if target.is_dir():
            target /= "index.html"
        checked += 1
        if not target.is_file():
            errors.append(f"{route}: missing {link}")
        elif absolute.fragment and target in parsed:
            fragment = unquote(absolute.fragment)
            # Material's #__... controls and empty top anchors are real IDs.
            if fragment not in parsed[target].ids:
                errors.append(f"{route}: missing fragment {link}")
if errors:
    print("\n".join(sorted(set(errors))), file=sys.stderr)
    raise SystemExit(1)
print(f"PASS: {checked} rendered local links and fragments across {len(parsed)} HTML pages")
