import {
  proxyActivities,
  sleep,
  condition,
  defineSignal,
  setHandler,
  workflowInfo,
} from '@temporalio/workflow';
import type * as activities from '../activities/index.js';
import type { ScanConfig, PhaseType } from '../../../shared/src/types/index.js';

const {
  runRecon,
  runNuclei,
  runShannon,
  runWifi,
  runOsint,
  updatePhase,
  saveFinding,
  finalizeReport,
  notifyProgress,
} = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '5 minutes',
});

export const pauseSignal = defineSignal('pause');
export const resumeSignal = defineSignal('resume');

export async function apexRedScan(config: ScanConfig): Promise<string> {
  const { workflowId } = workflowInfo();
  let paused = false;

  setHandler(pauseSignal, () => { paused = true; });
  setHandler(resumeSignal, () => { paused = false; });

  const waitIfPaused = async () => {
    if (paused) await condition(() => !paused);
  };

  await notifyProgress(workflowId, 'scan_started', { name: config.name });

  // ── Phase 1: Recon ─────────────────────────────────────────────
  if (config.phases.recon) {
    await waitIfPaused();
    await updatePhase(workflowId, 'recon', 'running');
    const reconResults = await runRecon(workflowId, config.targets, config.depth);
    await updatePhase(workflowId, 'recon', 'completed', reconResults);
    await notifyProgress(workflowId, 'recon_done', {
      hostsFound: reconResults.hosts.length,
      subdomains: reconResults.subdomains.length,
    });
  }

  // ── Phase 2: Vuln Scan ─────────────────────────────────────────
  if (config.phases.vulnScan) {
    await waitIfPaused();
    await updatePhase(workflowId, 'vuln_scan', 'running');
    const nucleiResults = await runNuclei(workflowId, config.depth);
    await updatePhase(workflowId, 'vuln_scan', 'completed', nucleiResults);
    await notifyProgress(workflowId, 'vuln_scan_done', {
      findings: nucleiResults.findings.length,
    });
  }

  // ── Phase 3: AI Pentest (Shannon) ──────────────────────────────
  if (config.phases.pentest) {
    await waitIfPaused();
    await updatePhase(workflowId, 'pentest', 'running');
    const shannonResults = await runShannon(workflowId, config);
    await updatePhase(workflowId, 'pentest', 'completed', shannonResults);
    await notifyProgress(workflowId, 'pentest_done', {
      exploits: shannonResults.findings.filter(f => f.proof).length,
    });
  }

  // ── Phase 4: OSINT ─────────────────────────────────────────────
  await waitIfPaused();
  await updatePhase(workflowId, 'recon', 'running');
  const osintResults = await runOsint(workflowId, config.targets);
  await notifyProgress(workflowId, 'osint_done', {
    emails: osintResults.emails?.length ?? 0,
    leaks: osintResults.leaks?.length ?? 0,
  });

  // ── Phase 5: WiFi (optional) ───────────────────────────────────
  if (config.phases.wifi) {
    await waitIfPaused();
    await updatePhase(workflowId, 'recon', 'running');
    const wifiResults = await runWifi(workflowId);
    await notifyProgress(workflowId, 'wifi_done', {
      networks: wifiResults.networks?.length ?? 0,
    });
  }

  // ── Phase 6: Report ────────────────────────────────────────────
  await waitIfPaused();
  const reportPath = await finalizeReport(workflowId, config.reportFormat);
  await notifyProgress(workflowId, 'scan_completed', { reportPath });

  return reportPath;
}
