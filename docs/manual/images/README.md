# SVG Diagram Style Guide

This documents the style conventions used for flowchart/diagram SVGs
in this directory, so that new diagrams are visually consistent.

## Fonts

- **Primary:** Arial, Helvetica, sans-serif
- **Title:** 12px, bold
- **Phase/section labels:** 11px, bold, fill `#444`
- **Body text:** 10px, fill `#333`
- **Edge labels (Yes/No):** 9px, fill `#555`
- **Annotations/italic notes:** 8px, fill `#666`, italic

## Colors

| Element | Fill | Stroke | Notes |
|---------|------|--------|-------|
| Process box (action) | `#e8e8e8` | `#333` | `rx:4 ry:4` rounded corners |
| Decision diamond | `#fff8dc` (cornsilk) | `#333` | |
| Terminal (start/done) | `#d4edda` (light green) | `#333` | `rx:12 ry:12` pill shape |
| Redirect / error | `#f8d7da` (light red) | `#333` or `#b33` | `rx:12 ry:12` pill shape |
| Phase box (grouping) | `#fafafa` | `#888` | `rx:8 ry:8`, contains related steps |
| Warning box | `#f8d7da` | `#b33` | `rx:4 ry:4`, stroke-width 1.5 |
| Lines/arrows | — | `#333` | stroke-width 1.2 |
| Dashed lines (loops) | — | `#333` | stroke-dasharray: 5,4 |

## Arrowhead Marker

```xml
<marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
  <polygon points="0 0, 10 3.5, 0 7" fill="#333"/>
</marker>
```

## SVG Boilerplate

```xml
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">
  <defs>
    <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
      <polygon points="0 0, 10 3.5, 0 7" fill="#333"/>
    </marker>
    <style>
      text { font-family: Arial, Helvetica, sans-serif; font-size: 10px; fill: #333; }
      .title { font-size: 12px; font-weight: bold; }
      .phase { font-size: 11px; font-weight: bold; fill: #444; }
      .label { font-size: 9px; fill: #555; }
      .small { font-size: 8px; fill: #666; font-style: italic; }
      rect.process { fill: #e8e8e8; stroke: #333; stroke-width: 1.2; rx: 4; ry: 4; }
      polygon.decision { fill: #fff8dc; stroke: #333; stroke-width: 1.2; }
      rect.terminal { fill: #d4edda; stroke: #333; stroke-width: 1.2; rx: 12; ry: 12; }
      rect.redirect { fill: #f8d7da; stroke: #333; stroke-width: 1.2; rx: 12; ry: 12; }
      rect.phase-box { fill: #fafafa; stroke: #888; stroke-width: 1.2; rx: 8; ry: 8; }
      line, path { stroke: #333; stroke-width: 1.2; fill: none; marker-end: url(#arrowhead); }
      .dashed { stroke-dasharray: 5,4; }
    </style>
  </defs>
  <!-- diagram content here -->
</svg>
```

## Generating PNGs from SVGs

Use `rsvg-convert` (from `librsvg`):

```bash
# Install (macOS):
brew install librsvg

# Install (Fedora/RHEL/CentOS):
dnf install librsvg2-tools

# Install (Debian/Ubuntu):
apt-get install librsvg2-bin

# Convert at 1x (matching SVG viewBox dimensions):
rsvg-convert -o rewrite_l_flag_looping.png rewrite_l_flag_looping.svg

# Or specify explicit dimensions:
rsvg-convert -w 520 -h 720 -o rewrite_l_flag_looping.png rewrite_l_flag_looping.svg
```

Existing PNGs in this directory are at 1x scale (matching their SVG
viewBox width/height). Keep PNGs at 1x for consistency with the rest
of the documentation build.

## General Conventions

- Diamonds for decisions, rounded rectangles for actions, pill shapes
  for start/end terminals.
- Yes/No labels on decision branches (9px, gray).
- Phase boxes group related steps that occur in the same processing context.
- Dashed lines indicate loop-back paths or optional flows.
- Titles centered at the top of the SVG.
- Typical viewBox widths: 440–650px. Heights: 360–750px.
