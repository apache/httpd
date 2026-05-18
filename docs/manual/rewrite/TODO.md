# Rewrite Docs —  Suggested addition

Based on 20 years of users@httpd.apache.org questions, these are the
most common mod_rewrite pain points that the guide does not adequately
address. Sorted by priority.

## HIGH — Widely asked, not covered

- [x] **Redirect vs. RewriteRule processing order** — mod_rewrite runs
      *before* mod_alias regardless of config file order. Mixing them
      in the same context confuses users every year. Belongs in avoid.xml
      or tech.xml.

- [x] **%{HTTPS} behind a load balancer / SSL terminator** — %{HTTPS}
      queries mod_ssl directly; it is not an environment variable.
      Behind a reverse proxy, check %{HTTP:X-Forwarded-Proto} instead.
      Add to the HTTPS redirect recipe in remapping.xml.

- [x] **URL encoding pipeline** — Apache decodes percent-encoded chars
      before pattern matching. %{THE_REQUEST} preserves the raw form.
      AllowEncodedSlashes, [B]/[NE]/[BNP] flags. No coherent
      explanation exists in the guide. Could be a new section in
      intro.xml or tech.xml.

- [x] **REDIRECT_ prefix for environment variables** — env vars set by
      [E=] are renamed to REDIRECT_FOO after internal redirects. Not
      mentioned in the [E] flag section at all. Add to flags.xml.

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

- [ ] **301 caching by browsers** — users fix their config but still
      see the old broken redirect. Mention in htaccess.xml or intro.xml.

- [ ] **[R=4xx] sends a redirect header, not a status response** — add
      a warning to the [R] flag section in flags.xml.

- [ ] **"Don't start .htaccess patterns with /"** — implicit in the
      current path-stripping section but never called out as a warning
      box. Add to htaccess.xml.

## LOW

- [ ] **prg: RewriteMap must flush stdout** — add note to rewritemap.xml.

- [ ] **mod_rewrite cannot inspect POST body** — one-sentence note in
      intro.xml.

- [ ] **flags** - Add examples to flags that lack them. (See bz #70043)

