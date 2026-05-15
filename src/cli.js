#!/usr/bin/env node
'use strict';

const path = require('path');
const fs = require('fs');
const ShieldWall = require('./index');

const args = process.argv.slice(2);
const command = args[0];

if (!command || command === '--help' || command === '-h') {
  console.log(`
🛡️ ShieldWall CLI

Usage:
  shieldwall <command> [options]

Commands:
  test <file|json>   Run security check against a raw request JSON or log file
  lint <dir>        Validate .shield rules in a directory
  dashboard [port]  Start a standalone monitoring dashboard
  version           Show version

Options:
  --rules <dir>     Path to rules directory (default: ./rules)
  --mode <block|log> WAF mode (default: log)
  `);
  process.exit(0);
}

const rulesDir = getArg('--rules') || path.join(process.cwd(), 'rules');
const mode = getArg('--mode') || 'log';

async function run() {
  switch (command) {
    case 'version':
      const pkg = require('../package.json');
      console.log(`ShieldWall v${pkg.version}`);
      break;

    case 'lint':
      const targetDir = args[1] || rulesDir;
      console.log(`🔍 Linting rules in: ${targetDir}`);
      try {
        const { loadRulesFromDir } = require('./core/rule-parser');
        const rules = loadRulesFromDir(targetDir);
        console.log(`✅ Successfully parsed ${rules.length} rules.`);
      } catch (e) {
        console.error(`❌ Rule Parse Error: ${e.message}`);
        process.exit(1);
      }
      break;

    case 'test':
      const input = args[1];
      if (!input) { console.error('❌ Error: No input file or JSON string provided.'); process.exit(1); }
      
      let reqData;
      try {
        reqData = fs.existsSync(input) ? JSON.parse(fs.readFileSync(input, 'utf8')) : JSON.parse(input);
      } catch (e) {
        console.error('❌ Error: Input must be a valid JSON file or string.');
        process.exit(1);
      }

      const engine = new ShieldWall.Engine({ rulesDir, mode: 'log', silent: false });
      const verdict = await engine.analyze(reqData);
      
      console.log('\n🛡️ TEST VERDICT:');
      console.log(`━━━━━━━━━━━━━━━━━━━━`);
      console.log(`Blocked: ${verdict.blocked ? '🔴 YES' : '🟢 NO'}`);
      console.log(`Risk Score: ${verdict.riskScore}`);
      console.log(`Highest Severity: ${verdict.highestSeverity.toUpperCase()}`);
      console.log(`Matches: ${verdict.matches.length}`);
      verdict.matches.forEach(m => console.log(` • [${m.severity}] ${m.rule}: ${m.description}`));
      console.log(`━━━━━━━━━━━━━━━━━━━━\n`);
      break;

    case 'dashboard':
      const port = parseInt(args[1]) || 9090;
      const standaloneEngine = new ShieldWall.Engine({ rulesDir, mode: 'log' });
      const Dashboard = require('./dashboard/server');
      const db = new Dashboard({ port, engine: standaloneEngine });
      db.start();
      console.log(`🚀 Standalone Dashboard started at http://localhost:${port}`);
      break;

    default:
      console.error(`❌ Unknown command: ${command}`);
      process.exit(1);
  }
}

function getArg(name) {
  const idx = args.indexOf(name);
  return idx !== -1 ? args[idx + 1] : null;
}

run().catch(e => {
  console.error(`❌ Fatal Error: ${e.message}`);
  process.exit(1);
});
