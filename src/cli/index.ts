#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import { analyzeCommand } from './commands/analyze';
import { tailCommand } from './commands/tail';
import { statsCommand } from './commands/stats';
import { searchCommand } from './commands/search';
import { exportCommand } from './commands/export';

import path from 'path';
const pkgPath = path.resolve(__dirname, '../../..', 'package.json');
let pkg: any = {};
try { pkg = require(pkgPath); } catch (e) { pkg = { version: '0.0.0' }; }

const program = new Command();
program
  .name('logixia')
  .description('Logixia CLI for log management and analysis')
  .version(pkg.version || '0.0.0');

program.addCommand(analyzeCommand);
program.addCommand(tailCommand);
program.addCommand(statsCommand);
program.addCommand(searchCommand);
program.addCommand(exportCommand);

program.on('command:*', () => {
  console.error(chalk.red('Invalid command: %s\nSee --help for a list of available commands.'), program.args.join(' '));
  process.exit(1);
});

if (require.main === module) {
  program.parse(process.argv);
}
