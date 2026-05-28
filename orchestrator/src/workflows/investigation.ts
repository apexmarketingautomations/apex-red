import {
  proxyActivities,
  condition,
  defineSignal,
  setHandler,
  workflowInfo,
} from '@temporalio/workflow';
import type * as activities from '../activities/index.js';

const {
  runRecon, runOsint, runCodeIntel, runCloud,
  runVulns, runRiskScoring, runAiAnalyst,
  updateModuleStatus, postEvent, getSeeds,
} = proxyActivities<typeof activities>({
  startToCloseTimeout: '2 hours',
  heartbeatTimeout: '10 minutes',
});

export const pauseSignal  = defineSignal('pause');
export const resumeSignal = defineSignal('resume');

export interface InvestigationInput {
  investigationId: string;
  depth: 'surface' | 'standard' | 'deep';
  modules: {
    recon: boolean;
    osint: boolean;
    codeIntel: boolean;
    cloud: boolean;
    vulns: boolean;
  };
}

export async function apexRedInvestigation(input: InvestigationInput) {
  const { investigationId, depth, modules } = input;
  let paused = false;

  setHandler(pauseSignal,  () => { paused = true;  });
  setHandler(resumeSignal, () => { paused = false; });

  const wait = async () => { if (paused) await condition(() => !paused); };

  await postEvent(investigationId, 'investigation_started', { investigationId });

  // Load seed entities from DB
  const seeds = await getSeeds(investigationId);

  // ── Module 1: Recon ───────────────────────────────────────────────────
  if (modules.recon) {
    await wait();
    await updateModuleStatus(investigationId, 'recon', 'running');
    const r = await runRecon(investigationId, seeds);
    await updateModuleStatus(investigationId, 'recon', 'completed', { entities: r.discovered });
  }

  // ── Module 2: OSINT ───────────────────────────────────────────────────
  if (modules.osint) {
    await wait();
    await updateModuleStatus(investigationId, 'osint', 'running');
    // Run on seeds + any newly discovered entities
    const allEntities = await getSeeds(investigationId); // includes discovered
    const r = await runOsint(investigationId, allEntities);
    await updateModuleStatus(investigationId, 'osint', 'completed', { entities: r.discovered });
  }

  // ── Module 3: Code Intel ──────────────────────────────────────────────
  if (modules.codeIntel) {
    await wait();
    await updateModuleStatus(investigationId, 'code_intel', 'running');
    const allEntities = await getSeeds(investigationId);
    const r = await runCodeIntel(investigationId, allEntities);
    await updateModuleStatus(investigationId, 'code_intel', 'completed', { entities: r.discovered });
  }

  // ── Module 4: Cloud ───────────────────────────────────────────────────
  if (modules.cloud) {
    await wait();
    await updateModuleStatus(investigationId, 'cloud', 'running');
    const allEntities = await getSeeds(investigationId);
    const r = await runCloud(investigationId, allEntities);
    await updateModuleStatus(investigationId, 'cloud', 'completed', { entities: r.discovered });
  }

  // ── Module 5: Vuln Engine ─────────────────────────────────────────────
  if (modules.vulns) {
    await wait();
    await updateModuleStatus(investigationId, 'vuln_engine', 'running');
    const allEntities = await getSeeds(investigationId);
    const r = await runVulns(investigationId, allEntities, depth);
    await updateModuleStatus(investigationId, 'vuln_engine', 'completed', { entities: r.discovered });
  }

  // ── Module 6: Risk Scoring ─────────────────────────────────────────────
  await wait();
  await updateModuleStatus(investigationId, 'risk_scoring', 'running');
  await runRiskScoring(investigationId);
  await updateModuleStatus(investigationId, 'risk_scoring', 'completed');

  // ── Module 7: AI Analyst ───────────────────────────────────────────────
  await wait();
  await updateModuleStatus(investigationId, 'ai_analyst', 'running');
  await runAiAnalyst(investigationId);
  await updateModuleStatus(investigationId, 'ai_analyst', 'completed');

  await postEvent(investigationId, 'investigation_completed', { investigationId });
}
