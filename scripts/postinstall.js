#!/usr/bin/env node

'use strict';

// Suppress in CI or silent npm installs
if (
  process.env.CI === 'true' ||
  process.env.CI === '1' ||
  process.env.LOGIXIA_NO_BANNER === 'true' ||
  (process.env.npm_config_loglevel &&
    ['silent', 'error', 'warn'].includes(process.env.npm_config_loglevel))
) {
  process.exit(0);
}

try {
  const pc = require('picocolors');
  const pkg = require('../package.json');

  // ── ASCII logo (hand-crafted, zero deps) ──────────────────────────────────
  const logo = [
    '  ██╗      ██████╗  ██████╗ ██╗██╗  ██╗██╗ █████╗ ',
    '  ██║     ██╔═══██╗██╔════╝ ██║╚██╗██╔╝██║██╔══██╗',
    '  ██║     ██║   ██║██║  ███╗██║ ╚███╔╝ ██║███████║',
    '  ██║     ██║   ██║██║   ██║██║ ██╔██╗ ██║██╔══██║',
    '  ███████╗╚██████╔╝╚██████╔╝██║██╔╝ ██╗██║██║  ██║',
    '  ╚══════╝ ╚═════╝  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝',
  ];

  // Gradient: cyan → blue → magenta (manual per-line coloring)
  const colors = [pc.cyan, pc.cyan, pc.blue, pc.blue, pc.magenta, pc.magenta];
  const coloredLogo = logo.map((line, i) => colors[i](pc.bold(line))).join('\n');

  const width = 54;
  const border = pc.dim('  ' + '─'.repeat(width));

  const line = (label, value, colorFn = pc.white) =>
    `  ${pc.dim('│')}  ${pc.bold(label.padEnd(10))} ${colorFn(value)}`;

  const banner = [
    '',
    coloredLogo,
    '',
    border,
    line('version', `v${pkg.version}`, pc.green),
    line('desc', pkg.description.slice(0, 42) + '…', pc.dim),
    border,
    line('docs', pkg.homepage, pc.cyan),
    line('issues', pkg.bugs.url, pc.yellow),
    line('sponsor', 'https://github.com/sponsors/webcoderspeed', pc.magenta),
    border,
    `  ${pc.dim('│')}  ${pc.bold(pc.green('❤'))}  ${pc.dim('Enjoying logixia? Sponsor to keep it alive!')}`,
    border,
    '',
  ].join('\n');

  process.stdout.write(banner + '\n');
} catch {
  // Never break the install
}
