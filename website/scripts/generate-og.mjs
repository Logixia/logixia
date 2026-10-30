// Renders scripts/og.svg to public/og.png (1200x630). Run: npm run og
// The renderer is installed on demand into a temp directory (pinned version, no install
// scripts) so the docs build and CI installs never download its native binary. The SVG
// has its text converted to paths, so the output does not depend on installed fonts.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const RESVG_VERSION = '2.6.2';
const tmp = mkdtempSync(join(tmpdir(), 'logixia-og-'));

try {
  execFileSync(
    'npm',
    [
      'install',
      '--prefix',
      tmp,
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      `@resvg/resvg-js@${RESVG_VERSION}`,
    ],
    { stdio: 'inherit' }
  );
  const { Resvg } = createRequire(join(tmp, 'noop.js'))('@resvg/resvg-js');
  const svg = readFileSync(fileURLToPath(new URL('./og.svg', import.meta.url)), 'utf8');
  const png = new Resvg(svg, { fitTo: { mode: 'width', value: 1200 } }).render().asPng();
  writeFileSync(fileURLToPath(new URL('../public/og.png', import.meta.url)), png);
  console.log(`og.png written (${png.length} bytes)`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
