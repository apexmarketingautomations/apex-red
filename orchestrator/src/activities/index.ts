export { runRecon }         from './recon.js';
export { runOsint }         from './osint.js';
export { runCodeIntel }     from './code.js';
export { runCloud }         from './cloud.js';
export { runVulns }         from './vulns.js';
export { runRiskScoring }   from './risk.js';
export { runAiAnalyst }     from './analyst.js';
export { updateModuleStatus, postEvent } from '../utils/graph.js';

import { db } from '../utils/db.js';

/** Load all entities for an investigation (seeds + discovered) */
export async function getSeeds(investigationId: string) {
  const { rows } = await db.query(
    `SELECT * FROM entities WHERE investigation_id = $1`,
    [investigationId]
  );
  return rows;
}
