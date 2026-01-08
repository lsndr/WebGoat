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

test('POST /SqlInjectionAdvanced/quiz', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['sqli', 'csrf'],
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
      url: `${baseUrl}/SqlInjectionAdvanced/quiz`,
      body: {
        question_0_solution: 'Solution 4',
        question_1_solution: 'Solution 3',
        question_2_solution: 'Solution 2',
        question_3_solution: 'Solution 3',
        question_4_solution: 'Solution 4'
      },
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
});