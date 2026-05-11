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

- [x] **HTTPS redirect** covered in both avoid.xml and remapping.xml.
      → remapping.xml owns the recipe; avoid.xml references it.

## LOW Priority

- [ ] **Harmonize `<seealso>` blocks** — htaccess.xml not consistently
      listed in other files' seealso despite being a major topic.

- [ ] **Deprecated stub files** (access.xml, advanced.xml, proxy.xml) —
      consider removal or ensure they don't appear in navigation.

- [ ] **Figure numbering collision** — both intro.xml and tech.xml use
      "Figure 1" for different images.

---

## Potential Topics to Cover

Based on 20 years of users@httpd.apache.org questions, these are the
most common mod_rewrite pain points that the guide does not adequately
address. Sorted by priority.

### HIGH — Widely asked, not covered

- [ ] **Redirect vs. RewriteRule processing order** — mod_rewrite runs
      *before* mod_alias regardless of config file order. Mixing them
      in the same context confuses users every year. Belongs in avoid.xml
      or tech.xml.

- [ ] **%{HTTPS} behind a load balancer / SSL terminator** — %{HTTPS}
      queries mod_ssl directly; it is not an environment variable.
      Behind a reverse proxy, check %{HTTP:X-Forwarded-Proto} instead.
      Add to the HTTPS redirect recipe in remapping.xml.

- [ ] **URL encoding pipeline** — Apache decodes percent-encoded chars
      before pattern matching. %{THE_REQUEST} preserves the raw form.
      AllowEncodedSlashes, [B]/[NE]/[BNP] flags. No coherent
      explanation exists in the guide. Could be a new section in
      intro.xml or tech.xml.

- [ ] **REDIRECT_ prefix for environment variables** — env vars set by
      [E=] are renamed to REDIRECT_FOO after internal redirects. Not
      mentioned in the [E] flag section at all. Add to flags.xml.

- [ ] **RewriteRule inside `<If>` or `<Location>` switches to
      per-directory context** — counter-intuitive behavior even when
      the block is inside a VirtualHost. Add a warning to htaccess.xml
      or tech.xml.

- [ ] **Query string is NOT part of the RewriteRule pattern** — users
      put `?query` or full URLs in their patterns. Make this explicit
      in intro.xml's RewriteRule basics section.

### MEDIUM — Common, easy to add

- [ ] **Let's Encrypt ACME challenge exemption** — one-liner recipe,
      universally needed alongside HTTPS redirect. Add to remapping.xml.

- [ ] **301 caching by browsers** — users fix their config but still
      see the old broken redirect. Mention in htaccess.xml or intro.xml.

- [ ] **[R=4xx] sends a redirect header, not a status response** — add
      a warning to the [R] flag section in flags.xml.

- [ ] **"Don't start .htaccess patterns with /"** — implicit in the
      current path-stripping section but never called out as a warning
      box. Add to htaccess.xml.

### LOW — Niche but prevents support questions

- [ ] **prg: RewriteMap must flush stdout** — add note to rewritemap.xml.

- [ ] **mod_rewrite cannot inspect POST body** — one-sentence note in
      intro.xml.
