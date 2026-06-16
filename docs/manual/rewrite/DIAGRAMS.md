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

## 3. Path Stripping and RewriteBase Pipeline

**Target page:** htaccess.xml, "What URL does the rule see?" section

**Problem:** Users consistently get confused about what string the pattern
actually matches against in per-directory context, what RewriteBase does,
and how the substitution result is turned back into a full URL.

**Proposed diagram — linear transformation pipeline:**
```
Incoming URL-path: /app/products/widget
                        │
                        ▼
          ┌─────────────────────────┐
          │  Strip directory prefix  │
          │  Prefix: /app/           │
          └─────────────────────────┘
                        │
                        ▼
         Pattern matches: products/widget
            (no leading slash)
                        │
                        ▼
          ┌─────────────────────────┐
          │     Apply substitution   │
          │  Result: shop.php?item=widget │
          └─────────────────────────┘
                        │
                        ▼
          ┌─────────────────────────┐
          │  Prepend RewriteBase    │
          │  Base: /app/            │
          └─────────────────────────┘
                        │
                        ▼
     Internal subrequest: /app/shop.php?item=widget
```

Show the contrast: if substitution starts with `/` or `http://`,
RewriteBase is not applied (absolute path bypasses prepend step).

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

## 6. Flag Selection Guide

**Target page:** flags.xml (new figure at top of page)

**Problem:** The flags page is a long alphabetical reference. Users often
don't know which flag they need. A decision-tree diagram would serve as a
navigation aid.

**Proposed diagram — decision tree:**
```
What do you want to do?
├── Redirect the client to a different URL? → [R]
├── Stop processing rules?
│   ├── In server context? → [L]
│   └── In .htaccess (stop completely)? → [END]
├── Proxy the request to a backend? → [P]
├── Set an environment variable? → [E]
├── Set a MIME type? → [T]
├── Skip the next N rules? → [S]
├── Restart rule processing from the top? → [N]
├── Send a specific HTTP status? → [R=4xx] or [F] / [G]
├── Apply rule as last resort only? → [L] with conditions
└── Pass through to next handler? → [PT]
```

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

