"""Builds the default avatars and banners the server ships and serves.

Source: the brand sheet's avatar set (`<brand sheet>/brand/avatars/pb-avatar-<expression>-<tone>.svg`,
12 tones x 6 expressions). Output, under `pufferblow/assets/default-art/`:

  avatars/pb-avatar-<expression>-<tone>.svg   the source art, minus the embedded provenance blob
  banners/pb-banner-<expression>-<tone>.svg   a wide banner in the same tone, with the same face
                                              drawn large and faint at the right edge

Run `node scripts/assets/render_default_art_pngs.cjs` afterwards for the PNG renditions.

    python scripts/assets/build_default_art.py [path/to/brand/avatars]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Wherever the current brand sheet lives; pass a path to use another copy.
SOURCES = [
    ROOT.parent / "brand" / "ui-mockups" / "brand" / "avatars",
    ROOT.parent / "UI mockups form" / "brand" / "avatars",
]
OUT = ROOT / "pufferblow" / "assets" / "default-art"

NAME = re.compile(r"^pb-avatar-([a-z]+)-([a-z]+)\.svg$")
METADATA = re.compile(r"<metadata>.*?</metadata>", re.S)
CIRCLE = re.compile(r'<circle cx="60" cy="60" r="60" fill="(#[0-9a-fA-F]{6})"')
MASK_GROUP = re.compile(r"(<mask id=\"[^\"]+\"[^>]*>)<g transform=\"[^\"]*\">(.*)</g></mask>", re.S)
FISH_RECT = re.compile(r'<rect width="120" height="120" fill="(#[0-9a-fA-F]{6})" mask="url\(#([^)]+)\)"></rect>')

BANNER_W, BANNER_H = 1500, 500


def clean(svg: str) -> str:
    svg = METADATA.sub("", svg)
    svg = svg.replace(' xmlns:c2pa="http://c2pa.org/manifest"', "")
    return svg.strip() + "\n"


def banner(svg: str, expression: str, tone: str) -> str:
    background = CIRCLE.search(svg)
    fish = FISH_RECT.search(svg)
    mask = MASK_GROUP.search(svg)
    if not (background and fish and mask):
        raise ValueError(f"unexpected avatar structure for {expression}/{tone}")
    mask_id = f"banner-{expression}-{tone}"
    # The face (spines, body, eyes, mouth) is centred near (60, 58) in a 120 box; scale it up so it
    # sits near the right edge, fully in frame.
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{BANNER_W}" height="{BANNER_H}" viewBox="0 0 300 100" preserveAspectRatio="xMidYMid slice">'
        f'<defs><mask id="{mask_id}" maskUnits="userSpaceOnUse" x="-100" y="-100" width="500" height="300">'
        f'<g transform="translate(236 52) scale(.95) translate(-60 -58)">{mask.group(2)}</g></mask></defs>'
        f'<rect width="300" height="100" fill="{background.group(1)}"/>'
        f'<rect width="300" height="100" fill="{fish.group(1)}" opacity=".16" mask="url(#{mask_id})"/>'
        f"</svg>\n"
    )


def main() -> None:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else next((p for p in SOURCES if p.is_dir()), SOURCES[0])
    files = sorted(p for p in source.glob("pb-avatar-*.svg") if NAME.match(p.name))
    if not files:
        raise SystemExit(f"no avatars in {source}")
    for sub in ("avatars", "banners"):
        (OUT / sub).mkdir(parents=True, exist_ok=True)
    for path in files:
        expression, tone = NAME.match(path.name).groups()
        svg = path.read_text(encoding="utf-8")
        (OUT / "avatars" / path.name).write_text(clean(svg), encoding="utf-8", newline="\n")
        (OUT / "banners" / f"pb-banner-{expression}-{tone}.svg").write_text(banner(clean(svg), expression, tone), encoding="utf-8", newline="\n")
    print(f"wrote {len(files)} avatars and {len(files)} banners to {OUT}")


if __name__ == "__main__":
    main()
