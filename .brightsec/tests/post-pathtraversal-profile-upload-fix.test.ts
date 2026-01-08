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

test('POST /pathtraversal/profile-upload-fix', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['file_upload', 'lfi'],
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
      url: `${baseUrl}/PathTraversal/profile-upload-fix`,
      headers: { 'Content-Type': 'multipart/form-data' },
      body: `--boundary\r\nContent-Disposition: form-data; name="uploadedFileFix"; filename="example.txt"\r\nContent-Type: text/plain\r\n\r\nThis is the content of the file.\r\n--boundary\r\nContent-Disposition: form-data; name="fullNameFix"\r\n\r\nJohn Doe\r\n--boundary--`
    });
});