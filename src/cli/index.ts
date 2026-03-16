#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';

import chalk from 'chalk';
import { Command } from 'commander';

import { analyzeCommand } from './commands/analyze';
import { exportCommand } from './commands/export';
import { queryCommand } from './commands/query';
import { searchCommand } from './commands/search';
import { statsCommand } from './commands/stats';
import { tailCommand } from './commands/tail';
const pkgPath = path.resolve(__dirname, '../../..', 'package.json');
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

program.on('command:*', () => {
  console.error(
    chalk.red('Invalid command: %s\nSee --help for a list of available commands.'),
    program.args.join(' ')
  );
  process.exit(1);
});

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  program.parse(process.argv);
}
