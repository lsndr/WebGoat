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

test('GET /files?uploadSuccess=true', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'lfi', 'xss', 'csrf', 'id_enumeration'],
      attackParamLocations: [AttackParamLocation.QUERY],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/files?uploadSuccess=true`,
      headers: { 'Content-Type': 'application/json' }
    });
});