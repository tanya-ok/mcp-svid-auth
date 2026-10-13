// Synthetic WebAuthn acceptance client. Never use this authenticator for a human account.
const readline = require('node:readline');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE_PATH || 'playwright');

(async () => {
  const browser = await chromium.launch({
    headless: true,
    ...(process.env.PLAYWRIGHT_CHROME_PATH
      ? { executablePath: process.env.PLAYWRIGHT_CHROME_PATH }
      : {}),
  });
  const context = await browser.newContext();
  const page = await context.newPage();
  const port = process.env.SVID_IDENTITY_PROFILE === 'isolated' ? 4567 : 4467;
  await page.goto(`http://localhost:${port}/ui/v2/login/healthy`, { timeout: 15000 });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true,
    },
  });
  process.stdout.write('{"ready":true}\n');
  const input = readline.createInterface({ input: process.stdin, terminal: false });
  try {
    for await (const line of input) {
      try {
        const request = JSON.parse(line);
        if (request.operation === 'verification') {
          await cdp.send('WebAuthn.setUserVerified', {
            authenticatorId, isUserVerified: request.verified === true,
          });
          process.stdout.write('{"updated":true}\n');
          continue;
        }
        if (!['register', 'authenticate'].includes(request.operation)) throw new Error();
        const result = await page.evaluate(async ({ operation, options }) => {
          const publicKey = { ...options, timeout: 10000 };
          const decode = value => Uint8Array.from(
            atob(value.replace(/-/g, '+').replace(/_/g, '/')), char => char.charCodeAt(0),
          );
          publicKey.challenge = decode(publicKey.challenge);
          if (publicKey.user) publicKey.user = { ...publicKey.user, id: decode(publicKey.user.id) };
          for (const name of ['allowCredentials', 'excludeCredentials']) {
            if (publicKey[name]) publicKey[name] = publicKey[name].map(
              credential => ({ ...credential, id: decode(credential.id) }),
            );
          }
          const credential = operation === 'register'
            ? await navigator.credentials.create({ publicKey })
            : await navigator.credentials.get({ publicKey });
          return credential.toJSON();
        }, request);
        process.stdout.write(JSON.stringify({ credential: result }) + '\n');
      } catch {
        process.stdout.write('{"error":"credential_failed"}\n');
      }
    }
  } finally {
    await browser.close();
  }
})().catch(() => {
  process.stdout.write('{"error":"browser_unavailable"}\n');
  process.exitCode = 1;
});
