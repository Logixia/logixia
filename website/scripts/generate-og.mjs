// Renders scripts/og.svg to public/og.png (1200x630). Run: npm run og
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Resvg } from '@resvg/resvg-js';

const svg = readFileSync(fileURLToPath(new URL('./og.svg', import.meta.url)), 'utf8');
const png = new Resvg(svg, {
  fitTo: { mode: 'width', value: 1200 },
  font: { loadSystemFonts: true },
})
  .render()
  .asPng();
writeFileSync(fileURLToPath(new URL('../public/og.png', import.meta.url)), png);
console.log(`og.png written (${png.length} bytes)`);
