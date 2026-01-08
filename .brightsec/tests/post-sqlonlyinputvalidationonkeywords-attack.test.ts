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

test('POST /sqlonlyinputvalidationonkeywords/attack', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'full_path_disclosure', 'xss'],
      attackParamLocations: [AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'lsndr/WebGoat:main',
        databases: ['SQL'],
        user_roles: {
          roles: ['user', 'admin', 'power-user', 'super-user']
        }
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/SqlOnlyInputValidationOnKeywords/attack`,
      body: {
        userid_sql_only_input_validation_on_keywords: 'EXAMPLE_USER_ID'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});