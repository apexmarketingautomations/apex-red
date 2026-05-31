import Anthropic from '@anthropic-ai/sdk';
import { pool } from './db.js';

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

export async function generateReport(invId: string): Promise<string> {
  const [inv, entities, findings, modules] = await Promise.all([
    pool.query(`SELECT * FROM investigations WHERE id=$1`, [invId]),
    pool.query(`SELECT * FROM entities WHERE investigation_id=$1`, [invId]),
    pool.query(`SELECT * FROM findings WHERE investigation_id=$1 ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END`, [invId]),
    pool.query(`SELECT * FROM module_runs WHERE investigation_id=$1`, [invId]),
  ]);

  if (!inv.rows.length) throw new Error('Investigation not found');

  const investigation = inv.rows[0];
  const criticalFindings = findings.rows.filter((f: any) => f.severity === 'critical');
  const highFindings = findings.rows.filter((f: any) => f.severity === 'high');

  const prompt = `You are a senior red team security analyst. Generate a comprehensive security assessment report in Markdown format based on the following investigation data.

Investigation: ${investigation.name}
Status: ${investigation.status}
Seeds: ${JSON.stringify(JSON.parse(investigation.config ?? '{}').seeds ?? [])}

Entities discovered (${entities.rows.length} total):
${entities.rows.slice(0, 50).map((e: any) => `- ${e.type}: ${e.value}`).join('\n')}

Findings (${findings.rows.length} total, ${criticalFindings.length} critical, ${highFindings.length} high):
${findings.rows.slice(0, 30).map((f: any) => `- [${f.severity.toUpperCase()}] ${f.title}: ${f.description}`).join('\n')}

Modules run: ${modules.rows.map((m: any) => `${m.module} (${m.status})`).join(', ')}

Generate a professional report with:
1. Executive Summary
2. Attack Surface Overview
3. Critical & High Findings (with remediation steps)
4. Entity Relationship Summary
5. Risk Score & Recommendations
6. Conclusion

Be specific, actionable, and prioritize findings by exploitability and impact.`;

  const message = await client.messages.create({
    model: 'claude-opus-4-8',
    max_tokens: 4096,
    messages: [{ role: 'user', content: prompt }],
  });

  const report = (message.content[0] as any).text as string;
  await pool.query(`UPDATE investigations SET ai_report=$1 WHERE id=$2`, [report, invId]);
  return report;
}
