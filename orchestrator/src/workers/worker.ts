import { Worker, NativeConnection } from '@temporalio/worker';
import * as activities from '../activities/index.js';
import { fileURLToPath } from 'node:url';
import { resolve, dirname } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function run() {
  const connection = await NativeConnection.connect({
    address: process.env.TEMPORAL_ADDRESS ?? 'localhost:7233',
  });

  const worker = await Worker.create({
    connection,
    namespace: 'default',
    taskQueue: 'apex-red',
    workflowsPath: resolve(__dirname, '../workflows/scan.js'),
    activities,
    maxConcurrentActivityTaskExecutions: 5,
  });

  console.log('Apex Red worker started on queue: apex-red');
  await worker.run();
}

run().catch(err => {
  console.error('Worker crashed:', err);
  process.exit(1);
});
