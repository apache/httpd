# AGENTS.md - Apache HTTP Server Documentation

This file provides instructions for AI agents working on the Apache HTTP Server documentation.

## Project Overview

This is the documentation source for the [Apache HTTP Server](https://httpd.apache.org/). Documentation is written in a custom XML format and transformed via XSLT. The source lives under `docs/manual/`.

## Inline Markup Rules

- `<var>` — Use for any user-supplied placeholder value. Never use `<em>` for placeholders.
  ```xml
  <syntax>Listen <var>port</var></syntax>
  <p>Replace <var>hostname</var> with your server's FQDN.</p>
  ```
- `<em>` — Use only for rhetorical emphasis (e.g., *not*, *must*, *only*, *all*, *before*, *after*). Never for placeholders, keywords, or warnings.
- `<code>` — Use for literal strings: filenames, paths, HTTP methods, header names, config keywords (`On`, `Off`, `None`), MIME types, env vars, CLI flags, signal names. Never nest `<strong>` inside `<code>`.
- `<strong>` — Use sparingly for critical warnings. Never inside `<code>`. Prefer `<note type="warning">` when appropriate.
- `<program>` — Use for httpd executables that have manual pages (`httpd`, `apachectl`, `htpasswd`, `rotatelogs`, `configure`). Never use `<code>` for these.
- `<module>` — Use for Apache module names (`mod_rewrite`, `mod_ssl`, `core`). Never use `<code>` for these.
- `<directive>` — Use for directive names. Include `module` attribute when referencing outside the directive's own module doc. Use `type="section"` for section directives.
  ```xml
  <directive module="core">ServerRoot</directive>
  <directive module="core" type="section">VirtualHost</directive>
  ```
- `<glossary>` — Use for glossary-defined terms. Use `ref` attribute when link target differs from display text.

## Directive Syntax Definitions

- Use `<var>` for all user-supplied arguments in `<syntax>` blocks.
- Literal keyword choices appear untagged, separated by `|`.
- Use these standard argument-type names in `<var>` tags:
  `file-path`, `directory-path`, `URL-path`, `url`, `filename`, `extension`, `regex`, `expression`, `number`, `bytes`, `seconds`, `duration`, `hostname`, `name`, `value`, `provider-name`, `env-variable`, `MIME-type`, `method`

### Quoting in Config Examples

Quote these in `<highlight language="config">` blocks:
- Filesystem paths: `ServerRoot "/usr/local/apache2"`
- URLs: `Redirect "/" "https://example.com/"`
- AuthName values: `AuthName "Restricted Area"`
- Regex patterns: `RewriteRule "^/old(.*)" "/new$1"`

Do NOT quote bare keywords: `AllowOverride None`, `Options FollowSymLinks`, `Require all granted`

## Block-Level Elements

### Code Examples

Use `<example>` with nested `<highlight language="...">`:

```xml
<example>
<highlight language="config">
Listen 80
Listen 8000
</highlight>
</example>
```

Valid `language` values: `config`, `lua`, `c`, `perl`, `sh`, `html`.

Never use bare `<example>` with `<br />` line breaks — that is a legacy pattern. Convert to `<highlight>` when editing such files.

### Notes and Warnings

```xml
<note>
<p>Informational callout text.</p>
</note>

<note type="warning">
<p>Critical warning text.</p>
</note>
```

Never use `<strong>Note:</strong>` in prose as a substitute for `<note>`.

### See Also

Place `<seealso>` elements after `<summary>` and before the first `<section>`.

## Prose Style

- Address the reader in second person ("you"). Avoid impersonal third-person ("the administrator should...").
- Contractions are acceptable ("doesn't", "won't", "can't").
- Use American English spelling (`behavior`, `customize`, `recognize`, `authorize`, `color`).
- Product name: first reference → "Apache HTTP Server" or "Apache httpd"; subsequent → "httpd". Never use bare "Apache" for the server.
- Use the Oxford comma ("addresses, hostnames, and ports").
- Prefer active voice ("Use this directive to..." not "The directive is used to...").
- Keep sentences concise. Break complex instructions into steps or bullet lists.

## Formatting and Structure

- Use spaces, not tabs. Don't mix indentation widths within a file.
- Content inside `<highlight>` blocks should be left-aligned (whitespace is preserved in output).
- Every manual page follows this structure:
  ```xml
  <?xml version="1.0" encoding="UTF-8" ?>
  <!DOCTYPE manualpage SYSTEM "./style/manualpage.dtd">
  <?xml-stylesheet type="text/xsl" href="./style/manual.en.xsl"?>

  <manualpage metafile="BASENAME.xml.meta">
    <title>Page Title</title>
    <summary>...</summary>
    <seealso>...</seealso>
    <section id="unique-id">
      <title>Section Title</title>
      ...
    </section>
  </manualpage>
  ```
- Section `id` values: short, lowercase, hyphenated. These are URL anchors and must remain stable once published.
- Use UTF-8 encoding. Write non-ASCII as literal UTF-8 (e.g., `é à ü`), not XML entities, unless the file already uses entities consistently.

## Reader's Guide (How Markup Renders)

Understanding how markup renders helps agents write documentation that reads well for end users:

- `<em>` (italic) — Emphasis. The reader should pay special attention to the marked word.
- `<var>` (slanted/colored) — Placeholder. The reader replaces it with their own value.
- `<code>` (monospace) — Literal value. Type it exactly as shown.
- `<strong>` (bold) — Critical point. The reader must not skip it.
- `<module>` and `<directive>` — Rendered as clickable cross-reference links to the relevant docs.
- `<program>` — Rendered as a clickable link to the program's manual page.
- `<example>`/`<highlight>` — Rendered as shaded code blocks the reader can copy and adapt.
- `<note>` — Rendered as a callout box. `<note type="warning">` renders as a warning box indicating pitfalls or destructive actions.
- In directive syntax lines:
  - Placeholders are values the reader supplies (e.g., `file-path`, `URL-path`, `regex`).
  - Literal keywords appear as-is (`On`, `Off`, `All`, `None`).
  - `[ ]` indicates optional arguments.
  - `|` separates alternative choices.
  - `...` indicates the argument may be repeated.
  - Quoted arguments in examples mean quotes are required or recommended in the config file.
