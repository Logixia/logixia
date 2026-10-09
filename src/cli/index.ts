#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

import { Command } from 'commander';
import pc from 'picocolors';

import { analyzeCommand } from './commands/analyze';
import { exploreCommand } from './commands/explore';
import { exportCommand } from './commands/export';
import { queryCommand } from './commands/query';
import { searchCommand } from './commands/search';
import { statsCommand } from './commands/stats';
import { tailCommand } from './commands/tail';
// Built to dist/cli/index.js, so the package root is two levels up.
const pkgPath = path.resolve(__dirname, '../..', 'package.json');
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let pkg: any;
try {
  pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8')) as { version?: string };
} catch {
  pkg = { version: '0.0.0' };
}

const program = new Command();
program
  .name('logixia')
  .description('Logixia CLI for log management and analysis')
  .version(pkg.version || '0.0.0');

program.addCommand(analyzeCommand);
program.addCommand(tailCommand);
program.addCommand(statsCommand);
program.addCommand(searchCommand);
program.addCommand(queryCommand);
program.addCommand(exportCommand);
program.addCommand(exploreCommand);

program.on('command:*', () => {
  console.error(
    pc.red('Invalid command: %s\nSee --help for a list of available commands.'),
    program.args.join(' ')
  );
  process.exit(1);
});

export function isDirectRun(argv1: string | undefined, file: string): boolean {
  if (!argv1) return false;
  try {
    // npm runs bins through a symlink in node_modules/.bin, so compare real paths.
    return fs.realpathSync(argv1) === fs.realpathSync(file);
  } catch {
    return false;
  }
}

if (isDirectRun(process.argv[1], __filename)) {
  program.parse(process.argv);
}
