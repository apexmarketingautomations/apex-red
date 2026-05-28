#!/usr/bin/env node
import { parseArgs } from 'node:util';

const { values, positionals } = parseArgs({
  args: process.argv.slice(2),
  options: {
    target:  { type: 'string',  short: 't', multiple: true },
    type:    { type: 'string',  short: 'T', default: 'domain' },
    depth:   { type: 'string',  short: 'd', default: 'standard' },
    name:    { type: 'string',  short: 'n' },
    api:     { type: 'string',  short: 'a', default: 'http://localhost:4000' },
    wifi:    { type: 'boolean', short: 'w', default: false },
    pentest: { type: 'boolean', short: 'p', default: true },
    help:    { type: 'boolean', short: 'h', default: false },
  },
  allowPositionals: true,
});

const cmd = positionals[0] ?? 'help';

if (values.help || cmd === 'help') {
  console.log(`
  Apex Red CLI — Autonomous Red Team Platform

  Usage:
    apex-red start -t <target> [options]
    apex-red list
    apex-red status <scan-id>
    apex-red report <scan-id>

  Options:
    -t, --target   Target value (repeatable: -t a.com -t b.com)
    -T, --type     Target type: domain|ip|cidr|url|company|email|github_org|wifi_ssid
    -d, --depth    Scan depth: surface|standard|deep  (default: standard)
    -n, --name     Scan name
    -a, --api      API base URL  (default: http://localhost:4000)
    -w, --wifi     Enable WiFi phase
    -p, --pentest  Enable AI pentest (Shannon)  (default: true)

  Examples:
    apex-red start -t apexmarketingautomations.com
    apex-red start -t 192.168.1.0/24 -T cidr -d deep
    apex-red start -t "Apex Marketing" -T company
    apex-red start -t targetcorp.com -t 10.0.0.0/8 -w
  `);
  process.exit(0);
}

if (cmd === 'start') {
  const targets = (values.target as string[] | undefined) ?? positionals.slice(1);
  if (!targets.length) {
    console.error('Error: at least one --target required');
    process.exit(1);
  }

  const body = {
    name: values.name ?? `Scan ${new Date().toLocaleDateString()} ${targets[0]}`,
    targets: targets.map(v => ({ type: values.type, value: v })),
    depth: values.depth,
    phases: {
      recon:       true,
      vulnScan:    true,
      pentest:     values.pentest,
      postExploit: false,
      adMapping:   false,
      wifi:        values.wifi,
    },
    maxHosts: 200,
    maxDuration: 480,
    reportFormat: 'json',
  };

  console.log(`\n  🎯  Apex Red — Starting scan\n`);
  console.log(`  Targets : ${targets.join(', ')}`);
  console.log(`  Depth   : ${values.depth}`);
  console.log(`  Phases  : recon → nuclei${values.pentest ? ' → shannon' : ''}${values.wifi ? ' → wifi' : ''} → report\n`);

  const res = await fetch(`${values.api}/api/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }).catch(e => { console.error(`  ✗  Cannot reach API at ${values.api}`); process.exit(1); });

  const data = await res.json();
  console.log(`  ✓  Scan started: ${data.scanId}`);
  console.log(`  Dashboard: ${values.api.replace(':4000', ':3000')}/scans/${data.scanId}\n`);

} else if (cmd === 'list') {
  const res = await fetch(`${values.api}/api/scans`);
  const scans = await res.json();
  if (!scans.length) { console.log('  No scans found.'); process.exit(0); }

  console.log('\n  ID                                    NAME                  STATUS      FINDINGS');
  console.log('  ' + '─'.repeat(80));
  for (const s of scans) {
    const id    = s.id.substring(0, 8) + '...';
    const name  = (s.name ?? '').substring(0, 20).padEnd(20);
    const status = (s.status ?? '').padEnd(10);
    const finds = (s.finding_count ?? 0).toString().padStart(4);
    console.log(`  ${id}  ${name}  ${status}  ${finds}`);
  }
  console.log();

} else if (cmd === 'status') {
  const scanId = positionals[1];
  if (!scanId) { console.error('Usage: apex-red status <scan-id>'); process.exit(1); }
  const res = await fetch(`${values.api}/api/scans/${scanId}`);
  const scan = await res.json();
  console.log('\n  Scan:', scan.name);
  console.log('  Status:', scan.status);
  console.log('  Findings:', scan.findings?.length ?? 0);
  console.log('  Critical:', scan.findings?.filter((f: any) => f.severity === 'critical').length ?? 0);
  console.log('  High:', scan.findings?.filter((f: any) => f.severity === 'high').length ?? 0);
  console.log();

} else if (cmd === 'report') {
  const scanId = positionals[1];
  if (!scanId) { console.error('Usage: apex-red report <scan-id>'); process.exit(1); }
  console.log(`  Report: ${values.api}/api/scans/${scanId}/report?format=html`);
  console.log(`  JSON:   ${values.api}/api/scans/${scanId}/report?format=json\n`);

} else {
  console.error(`Unknown command: ${cmd}. Run apex-red help`);
  process.exit(1);
}
