# Logixia documentation website

Built with [VitePress](https://vitepress.dev). It is a separate package from the library, with its own `package.json` and lockfile.

```bash
cd website
npm ci --ignore-scripts
npm run docs:dev       # dev server on http://localhost:5173/logixia/
npm run docs:build     # production build; fails on dead links
npm run docs:preview   # serve the production build
npm run check:snippets # typecheck every ts code block in the markdown
npm run og             # re-render public/og.png from scripts/og.svg
```

## Authoring

- Every page needs `title` and `description` (160 characters or fewer) in its frontmatter. Articles also need `date` (YYYY-MM-DD) and `tags`. An invalid `date` fails the build and names the file.
- The sidebar is generated from the files in `guide/` and `articles/`; there is no page list to edit. Restart the dev server after adding a file.
- Code blocks tagged `ts` or `typescript` are typechecked against the library source in CI (`npm run check:snippets`). Mark an intentionally partial snippet with an HTML comment on the line before it: `<!-- snippet-check: skip -->`.

## Dev server advisory

`npm audit` reports GHSA-67mh-4wv8-2f99 (esbuild 0.21, pulled in by Vite 5, which VitePress 1.x pins). It only affects the development server: a web page you open in the same browser could send requests to it. Keep the dev server bound to localhost, which is the default, and do not pass `--host`. The production build and the deployed site are not affected. Dependabot tracks `/website`; the advisory goes away once a stable VitePress release moves to a patched Vite.
