# Rewrite Docs — Redundancy Cleanup TODO

Working list of cross-file redundancies to resolve. Each item should
result in one file "owning" the content and others cross-referencing it.

## HIGH Priority

- [x] **Per-directory path stripping** explained in full across three files
      (intro.xml, tech.xml, htaccess.xml) with near-identical comparison
      tables in tech.xml and htaccess.xml.
      → htaccess.xml owns it; others get a brief mention + xref.

- [x] **[L] vs [END] looping** fully described in three places
      (htaccess.xml, plus both the [L] and [END] sections of flags.xml).
      → htaccess.xml owns the full explanation; flags.xml slims down + xrefs.

- [x] **FallbackResource / front-controller** recipe appears in four
      places across three files (avoid.xml, remapping.xml ×2, htaccess.xml).
      → avoid.xml owns it; others cross-reference.

## MEDIUM Priority

- [x] **index.xml is a mini-intro, not a TOC** — duplicates module
      description and complexity warnings from intro.xml.
      → Rewritten as concise intro + structured guide overview.

- [x] **Duplicate SSRF warning in flags.xml** — two nearly identical
      warning boxes within the [P] flag section.
      → Remove the literal duplicate.

- [x] **Two hostname canonicalization sections in remapping.xml** —
      "canonicalhost" and "www-resolve" cover the same concept.
      → Merge "www-resolve" into "canonicalhost".

- [ ] **HTTPS redirect** covered in both avoid.xml and remapping.xml.
      → remapping.xml owns the recipe; avoid.xml references it.

## LOW Priority

- [ ] **Harmonize `<seealso>` blocks** — htaccess.xml not consistently
      listed in other files' seealso despite being a major topic.

- [ ] **Deprecated stub files** (access.xml, advanced.xml, proxy.xml) —
      consider removal or ensure they don't appear in navigation.

- [ ] **Figure numbering collision** — both intro.xml and tech.xml use
      "Figure 1" for different images.
