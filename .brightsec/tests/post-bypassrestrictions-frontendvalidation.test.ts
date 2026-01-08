import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /bypassrestrictions/frontendvalidation', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['csrf', 'xss', 'sqli'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: "lsndr/WebGoat:main",
        databases: ["SQL"],
        user_roles: {
          roles: ["user", "admin", "power-user", "super-user"]
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/BypassRestrictions/frontendValidation`,
      body: {
        field1: 'abc',
        field2: '123',
        field3: 'abc123',
        field4: 'one',
        field5: '12345',
        field6: '12345-6789',
        field7: '234-567-8901',
        error: '0'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});