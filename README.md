# Code Guardian

An interactive security threat atlas for developers and security engineers — from junior to architect level.

**Live:** https://liyovsky-ops.github.io/CodeGuardian/

## What is it

A static site covering **14 threat categories** and **789 concrete vulnerabilities** (OWASP aligned), built as a developer reference and portfolio project. Each threat includes:

- Name, description, and confidence rating (Confirmed / Probable / Needs research)
- **Severity badge** — Critical / High / Medium / Low
- **Detection difficulty** — Easy / Medium / Hard / Very Hard
- Clickable **CWE** links (cwe.mitre.org)
- **Vulnerable** and **Secure** code tabs with syntax highlighting
- One-click **copy** for code examples

Also includes: a detectability matrix (static vs runtime) and developer conclusions.

## Features

- Sticky sidebar with category nav + severity counters (desktop), hamburger menu (mobile)
- Full-text search + filters by severity and difficulty
- Collapsible threat cards, reading progress bar, back-to-top
- Dark / light mode (persisted in localStorage)
- Deep links (e.g. `#cat-injection`) auto-scroll to category
- EN / PL language switcher
- Research threats toggle — hide unverified threats by default

## Stack

**Vite** · **Vanilla JS** (ES modules) · **YAML** content pipeline · **Prism.js** (bundled, no CDN) · **DOMPurify** · **Vitest**

## Project structure

```
CodeGuardian/
  src/
    content/categories/   # 14 × (meta.yaml + threats.yaml) — all threat data
    data/                 # JS importers per category
    modules/              # renderer, filters, interactions, theme, clipboard, highlight, dom, badges
    i18n/                 # EN/PL UI strings
    __tests__/            # unit tests (vitest)
    app.js                # bootstrap
    style.css
  index.html
  vite.config.js
  .github/workflows/      # deploy to GitHub Pages on push
```

## Local development

```bash
npm install
npm run dev       # dev server → http://localhost:5173
npm run build     # production build → dist/
npm test          # run unit tests
```

## Security note

All **VULNERABLE** code examples are illustrative only — never use in production.

Threat confidence levels:
- **Confirmed** — validated by multiple sources
- **Probable** — likely real, needs testing
- **Needs research** — theoretical / requires further investigation
