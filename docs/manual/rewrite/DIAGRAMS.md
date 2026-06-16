# Proposed Flowcharts for rewrite/ Documentation

Pursuant to [bz 70041](https://bz.apache.org/bugzilla/show_bug.cgi?id=70041). See also the comment on that ticket for current status.

The existing diagrams in `../images/` are:

| File | Used in | Shows |
|------|---------|-------|
| `mod_rewrite_fig1` | tech.xml (Figure 1) | Per-request overview: server + per-dir phases |
| `rewrite_process_uri` | tech.xml (Figure 2) | Rule/condition matching control flow |
| `mod_rewrite_fig2` | tech.xml (Figure 3) | Backreference flow between Rule and Cond |
| `rewrite_backreferences` | intro.xml (Figure 1) | Backreference flow (example-driven) |
| `syntax_rewriterule` | intro.xml (Figure 2) | RewriteRule syntax diagram |
| `syntax_rewritecond` | intro.xml (Figure 3) | RewriteCond syntax diagram |
| `rewrite_l_flag_looping` | htaccess.xml (loops section) | [L] flag looping in per-directory context |

---

## 1. ✅ Accurate Per-Server / Per-Directory Processing (tech.xml Figure 1)

**Status:** DONE — already redrawn in the current SVG style (`mod_rewrite_fig1.svg`).
Shows both per-server and per-directory phases with pattern matching, conditions,
substitution, and flag effects.

---

## 2. ✅ Per-Directory Looping (.htaccess [L] vs [END])

**Status:** DONE — committed in r1935412 (trunk) and r1935413 (2.4.x).
File: `rewrite_l_flag_looping.svg` / `.png` in `docs/manual/images/`.
Referenced from htaccess.xml, "The [L] flag and looping" section.

Shows the internal subrequest cycle, the [END] escape path, the
condition-guard escape path, and the unguarded infinite loop.

---

## 3. ✅ Path Stripping and RewriteBase Pipeline

**Status:** DONE — committed in r1935417 (trunk) and r1935418 (2.4.x).
File: `rewrite_path_stripping.svg` / `.png` in `docs/manual/images/`.
Referenced from htaccess.xml, "What URL does the rule see?" section.

Shows the full per-directory URL transformation pipeline with a three-way
branch after substitution: relative path (RewriteBase prepended →
subrequest), absolute path starting with / (used as-is → subrequest),
and absolute URI (external redirect, no subrequest).

---

## 4. Module Processing Order (mod_rewrite vs mod_alias)

**Target page:** tech.xml, "Module Processing Order" section

**Problem:** mod_rewrite runs before mod_alias in server context but AFTER
it in per-directory context. This reversal is a common source of confusion
and the text warns about it, but a visual would make it instantly clear.

**Proposed diagram — two-column comparison:**

```
SERVER CONTEXT                PER-DIRECTORY CONTEXT
─────────────────             ──────────────────────
Request arrives               Request arrives
      │                             │
      ▼                             ▼
┌────────────┐               ┌────────────┐
│mod_rewrite │  ← FIRST      │ mod_alias  │  ← FIRST
│(URL-to-    │               │(URL-to-    │
│ filename)  │               │ filename)  │
└────────────┘               └────────────┘
      │                             │
      ▼                             ▼
┌────────────┐               ┌────────────┐
│ mod_alias  │               │mod_rewrite │
│(URL-to-    │               │(Fixup      │
│ filename)  │               │ phase)     │
└────────────┘               └────────────┘
      │                             │
      ▼                             ▼
   Content                       Content
```

---

## 5. Simplified Overview for Beginners

**Target page:** intro.xml (new figure, or replacement for prose in the
introduction section)

**Problem:** The intro page jumps fairly quickly into regex syntax. A
simple "what happens when a request hits a RewriteRule" flowchart at the
top would orient beginners before they dive into pattern syntax.

**Proposed diagram — the "happy path":**
- Request arrives with URL-path
- RewriteEngine On?
  - No → pass through unchanged
  - Yes → evaluate rules in order:
    - RewriteCond(s) pass?
      - No → skip this rule, try next
      - Yes → Pattern matches URL?
        - No → skip this rule, try next
        - Yes → Apply substitution → Done (simplified; link to tech.xml for full details)

Explicitly labeled: "Simplified overview — see Technical Details for
the complete processing model including phases, flags, and looping."

---

## 6. ❌ Flag Selection Guide — WONTFIX as flowchart

A decision-tree flowchart doesn't work for flags because flags are
composable — you stack them (`[R=301,L]`, `[P,QSA]`, `[E=VAR:1,END]`).
A flowchart's Yes/No branching implies mutual exclusion, which is wrong.

**Instead:** A categorized quick-reference table was added directly to
flags.xml, grouping flags by purpose with a "Common combos" column that
shows typical stacking patterns.

---

## Implementation Notes

- All diagrams should be produced as SVG (with PNG fallback for older browsers).
- Follow UML activity diagram conventions where practical: filled circle
  for start, circled dot for end, diamonds for decisions, rounded
  rectangles for actions.
- Source files for diagrams should be committed alongside the SVG/PNG so
  future maintainers can edit them (e.g., Graphviz .dot, or draw.io XML).
- Label simplified diagrams explicitly as overviews and link to
  the authoritative technical page.

See README.md in ../images for more detail on format, fonts, colors,
etc.

