# CLAUDE.md

## Lessons

- `internal/web/static/admin.css` must keep a custom property literally named `--color-canvas` — `pages_test.go` asserts it as the asset marker. Never mention "localStorage" anywhere in web assets (tests grep case-insensitively).
- Styling `<meter>` pseudo-elements (`::-webkit-meter-bar`, `::-webkit-meter-optimum-value`, etc.) requires `-webkit-appearance: none; appearance: none;` on the `meter` element in Chromium/WebKit; `accent-color` does not apply to `<meter>`.
- ARIA prohibits accessible names (`aria-label`) on `role=generic` elements (plain `div`/`span`); give the element a naming-permitted role (e.g. `role="note"`) or use visually-hidden text instead.
- WCAG 1.4.11 non-text contrast: form-control boundaries need >=3:1 against adjacent surfaces. On this dark deck, input borders use `--color-border-strong: #5A6A84` (3.24:1 vs `--surface-panel`, 3.61:1 vs `--surface-sunken`); `#3A4557` fails.
- In stacked mobile layouts, a divider rule like `.x > div + div { border-bottom: ... }` combined with `.x > div:last-child { border-bottom: 0 }` deletes the divider entirely when there are only two children — apply the border to every cell (`> div`) and reset only the last child.
- `admin.js` is frozen; its DOM hooks (`data-copy-target`, `data-copy-status`, `id="new-api-key"`, `data-oauth-*`) and all Go template `{{...}}` actions/CSRF fields must survive template edits byte-identical.
