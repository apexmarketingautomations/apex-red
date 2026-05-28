import { heartbeat } from '@temporalio/activity';
import Anthropic from '@anthropic-ai/sdk';
import { db } from '../utils/db.js';
import { postEvent } from '../utils/graph.js';

const client = new Anthropic();

export async function runAiAnalyst(investigationId: string): Promise<string> {
  heartbeat('AI Analyst: gathering context');

  const [inv, entities, findings, scores] = await Promise.all([
    db.query(`SELECT * FROM investigations WHERE id=$1`, [investigationId]),
    db.query(`SELECT type, value, label, confidence FROM entities WHERE investigation_id=$1 AND is_seed=false LIMIT 100`, [investigationId]),
    db.query(
      `SELECT f.title, f.severity, f.category, f.description, f.proof, f.remediation, f.tool, e.type as entity_type, e.value as entity_value
       FROM findings f
       LEFT JOIN entities e ON e.id = f.entity_id
       WHERE f.investigation_id=$1
       ORDER BY CASE f.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`,
      [investigationId]
    ),
    db.query(
      `SELECT e.type, e.value, r.overall, r.factors
       FROM risk_scores r
       JOIN entities e ON e.id = r.entity_id
       WHERE r.investigation_id=$1 AND r.overall > 40
       ORDER BY r.overall DESC LIMIT 10`,
      [investigationId]
    ),
  ]);

  const summary = {
    name: inv.rows[0]?.name,
    entitiesDiscovered: entities.rows.length,
    findings: {
      critical: findings.rows.filter((f: any) => f.severity === 'critical').length,
      high:     findings.rows.filter((f: any) => f.severity === 'high').length,
      medium:   findings.rows.filter((f: any) => f.severity === 'medium').length,
      low:      findings.rows.filter((f: any) => f.severity === 'low').length,
    },
    topRisks: scores.rows,
  };

  heartbeat('AI Analyst: generating report');

  const response = await client.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 4000,
    system: `You are a senior security analyst writing an executive-grade attack surface intelligence report.
Be direct. Lead with what matters. Use markdown formatting.
Structure: Executive Summary → Critical Findings → Attack Chains → Risk Breakdown → Remediation Roadmap.
Avoid filler. Every sentence must carry information.`,
    messages: [{
      role: 'user',
      content: `Write a security report for investigation: "${summary.name}"

DISCOVERY SUMMARY:
${summary.entitiesDiscovered} entities discovered
${summary.findings.critical} critical, ${summary.findings.high} high, ${summary.findings.medium} medium, ${summary.findings.low} low findings

TOP RISK ENTITIES:
${scores.rows.map((r: any) => `- ${r.type}: ${r.value} (risk: ${r.overall}/100) — ${JSON.parse(r.factors ?? '[]').join(', ')}`).join('\n')}

CRITICAL AND HIGH FINDINGS:
${findings.rows.filter((f: any) => ['critical','high'].includes(f.severity)).map((f: any) =>
  `[${f.severity.toUpperCase()}] ${f.title}\n  Entity: ${f.entity_type} ${f.entity_value}\n  ${f.description}${f.proof ? `\n  Proof: ${f.proof}` : ''}`
).join('\n\n')}

Write the full report now.`,
    }],
  });

  const report = response.content[0].type === 'text' ? response.content[0].text : '';

  await db.query(`UPDATE investigations SET ai_report=$1 WHERE id=$2`, [report, investigationId]);
  await postEvent(investigationId, 'ai_report_ready', { investigationId });

  return report;
}
