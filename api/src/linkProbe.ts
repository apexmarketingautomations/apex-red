export async function probeLink(url: string): Promise<any> {
  const flags: string[] = [];
  let finalUrl = url;
  let status = 0;
  let contentType = '';
  let safe = true;

  const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.download', '.zip'];
  const suspiciousPatterns = [/bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly/i, /login|signin|verify|secure|account|update/i, /paypal|amazon|apple|microsoft|google/i];

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    const res = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'Mozilla/5.0 (compatible; ApexRed/1.0)' },
    });
    clearTimeout(timeout);

    status = res.status;
    finalUrl = res.url;
    contentType = res.headers.get('content-type') ?? '';

    if (finalUrl !== url) flags.push(`Redirects to: ${finalUrl}`);
    if (contentType.includes('application/') && !contentType.includes('json')) {
      flags.push('Downloads a file');
      safe = false;
    }
    if (status >= 400) flags.push(`HTTP ${status}`);
  } catch (err: any) {
    flags.push(`Connection failed: ${err.message}`);
    safe = false;
  }

  const urlLower = url.toLowerCase();
  if (suspiciousTLDs.some(tld => urlLower.includes(tld))) {
    flags.push('Suspicious TLD');
    safe = false;
  }
  if (suspiciousPatterns[0].test(url)) flags.push('URL shortener');
  if (suspiciousPatterns[1].test(urlLower) && suspiciousPatterns[2].test(urlLower)) {
    flags.push('Possible phishing: brand name + action keyword');
    safe = false;
  }

  return { url, finalUrl, status, contentType, safe, flags, probedAt: new Date().toISOString() };
}
