---
name: Hemlig console
description: 'The PixelCI design system adopted as-is: white cards on a cool grey desk, one indigo accent for the action, status in small coloured tags.'
source: 'PixelCI DESIGN.md (zyno-io/pixelci, 5e073c7) — tokens, type, shape, elevation and component rules are inherited verbatim; this file records only the Hemlig mapping.'
---

# Design System: Hemlig console

Hemlig adopts the **PixelCI design system as-is** ("The Review Desk": a tidy,
well-lit workstation). The tokens, typography ramp, radii, shadows, component
anatomy and named rules are PixelCI's and are not restated here; read the
PixelCI `DESIGN.md` for them. The implementation lives in `src/styles.css`
(tokens as CSS custom properties for light, redeclared for dark) and is exposed
to Tailwind v4 through `@theme`.

## What is inherited unchanged

- **Tokens:** `bg`, `surface`, `surface-2`, `surface-3`, `surface-hover`,
  `border`, `border-strong`, `text`, `text-2`, `text-3`, `placeholder`,
  `accent`, `accent-hover`, `accent-text`, `accent-soft`, `focus`, `link`, and
  the status triplets `danger|warning|success|info|release|neutral` with
  `-soft` and `-border`, plus `danger-strong`. Light and dark values are exactly
  PixelCI's.
- **Type:** Inter (self-hosted, 400/500/600/700, `cv11 ss01 tnum`) for
  everything a person wrote; platform monospace for everything a machine
  produced (The Machine Text Rule). Ramp 11–20px; weight before size.
- **Shape and depth:** 12/8/5px nested radii; hairline borders on containers,
  control outline on controls; resting / attached / floating shadows.
- **Components:** 32px controls (default, primary, ghost, danger buttons;
  inputs; selects), 19px tags, notices, cards with hairline-divided rows,
  46px translucent top bar with nav links, sticky page header, modal, empty
  state.
- **Named rules:** The One Indigo Rule, The Tag Triplet Rule, The Weight Before
  Size Rule, The Machine Text Rule, The Rows In One Card Rule, The Nested Radius
  Rule, The Inset Ring Rule, The Shadow Means Detached Rule.
- **Theme:** follows the OS unless the administrator picks Light or Dark from
  the theme menu in the top bar (stored per browser).

## Hemlig status mapping

Every status is a tag with a word in it (The Tag Triplet Rule).

| Where | Status | Tone |
| --- | --- | --- |
| Secret | `ACTIVE` | success |
| Secret | `PENDING_VALUE` | warning |
| Secret | `ARCHIVED` | neutral |
| API identity | `ACTIVE` | success |
| API identity | `REVOKED`, `EXPIRED` | danger |
| Enrollment / operation | `PENDING` | warning |
| Enrollment / operation | `FAILED` | danger |
| Audit outcome | `succeeded` | success |
| Audit outcome | `attempted`, `authorized` | neutral |
| Audit outcome | `failed` | danger |
| Any | unknown value | neutral |

`info` and `release` are available but unassigned; do not invent meanings for
them.

## Hemlig layout notes

- Page container max 1120px, padding 28px 20px 48px (16px 12px 32px under
  640px). Each page: a sticky page header (title left, the one primary action
  right), then cards.
- The top bar carries, left to right: the Hemlig wordmark, the environment
  switcher (a select, with "Manage" as a ghost link), the primary nav (Secrets,
  Consumers, Environments, Audit, Trust, About), then on the right the
  dev-bridge warning tag when applicable, the signed-in name in Meta Grey, the
  theme menu and Sign out (ghost).
- Collections (secrets, folders, consumers, identities, revisions, audit
  events) are one card with hairline-divided rows; tables keep their columns
  but live inside that card, with a Label caps header row.
- IDs, fingerprints, version IDs, paths, and timestamps from the API are
  monospace.
- Destructive actions (archive, revoke) are danger buttons that lead to a
  confirmation.
