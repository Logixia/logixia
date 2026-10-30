// Renders public/og.png (1200x630) from the project banner (.github/assets/logixia-banner.png):
// the banner is scaled to the full width and centered on its own background colour.
// Run: npm run og
// The renderer is installed on demand into a temp directory (pinned version, no install
// scripts) so the docs build and CI installs never download its native binary.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const RESVG_VERSION = '2.6.2';
const WIDTH = 1200;
const HEIGHT = 630;
// Banner is 3200x1280 (2.5:1); at 1200 wide it is 480 tall.
const BANNER_HEIGHT = 480;
const BACKGROUND = '#060508';

const banner = readFileSync(
  fileURLToPath(new URL('../../.github/assets/logixia-banner.png', import.meta.url))
).toString('base64');
const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}">
  <rect width="${WIDTH}" height="${HEIGHT}" fill="${BACKGROUND}"/>
  <image href="data:image/png;base64,${banner}" x="0" y="${(HEIGHT - BANNER_HEIGHT) / 2}" width="${WIDTH}" height="${BANNER_HEIGHT}"/>
</svg>`;

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
  const png = new Resvg(svg, { fitTo: { mode: 'width', value: WIDTH } }).render().asPng();
  writeFileSync(fileURLToPath(new URL('../public/og.png', import.meta.url)), png);
  console.log(`og.png written (${png.length} bytes)`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
