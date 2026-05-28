import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export async function execDocker(
  container: string,
  cmd: string[],
  stdin?: string
): Promise<string> {
  const escaped = cmd.map(c => `'${c.replace(/'/g, "'\\''")}'`).join(' ');

  let command: string;
  if (stdin) {
    const stdinEscaped = stdin.replace(/'/g, "'\\''");
    command = `echo '${stdinEscaped}' | docker exec -i ${container} ${escaped}`;
  } else {
    command = `docker exec ${container} ${escaped}`;
  }

  const { stdout, stderr } = await execAsync(command, {
    maxBuffer: 50 * 1024 * 1024, // 50MB
    timeout: 30 * 60 * 1000,     // 30 min max per command
  });

  return stdout;
}
