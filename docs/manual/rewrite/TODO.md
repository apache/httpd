# Rewrite Docs —  Suggested addition

Based on 20 years of users@httpd.apache.org questions, these are the
most common mod_rewrite pain points that the guide does not adequately
address. Sorted by priority.

## HIGH — Widely asked, not covered

- [ ] **RewriteRule inside `<If>` or `<Location>` switches to
      per-directory context** — counter-intuitive behavior even when
      the block is inside a VirtualHost. Add a warning to htaccess.xml
      or tech.xml.

- [ ] **Query string is NOT part of the RewriteRule pattern** — users
      put `?query` or full URLs in their patterns. Make this explicit
      in intro.xml's RewriteRule basics section.

## MEDIUM — Common, easy to add

- [ ] **Let's Encrypt ACME challenge exemption** — one-liner recipe,
      universally needed alongside HTTPS redirect. Add to remapping.xml.

- [x] **301 caching by browsers** — users fix their config but still
      see the old broken redirect. Mention in htaccess.xml or intro.xml.

- [x] **[R=4xx] sends a redirect header, not a status response** — add
      a warning to the [R] flag section in flags.xml.

- [x] **"Don't start .htaccess patterns with /"** — implicit in the
      current path-stripping section but never called out as a warning
      box. Add to htaccess.xml.

## LOW

- [x] **prg: RewriteMap must flush stdout** — add note to rewritemap.xml.

- [x] **mod_rewrite cannot inspect POST body** — one-sentence note in
      intro.xml.

- [ ] **flags** - Add examples to flags that lack them. (See bz #70043)

