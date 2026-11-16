/**
 * Fake credentials for tests.
 *
 * Every value is assembled from pieces at runtime so the source never contains
 * a complete vendor-shaped token. Otherwise secret scanners (GitHub push
 * protection, gitleaks, trufflehog) flag this repository's own test data.
 *
 * None of these are real. When adding a fixture, keep the vendor prefix split
 * from the body, e.g. join('hf', '_', 'abc…').
 */
const join = (...parts: string[]) => parts.join('')

const slackWebhookPath = join('T00000000', '/', 'B00000000', '/', 'XXXXXXXXXXXXXXXXXXXXXXXX')

export const FAKE = {
  awsAccessKeyId: join('AKIA', 'IOSFODNN7EXAMPLE'), // AWS's documented example key
  githubPat: join('ghp', '_', '16C7e42F292c6912E7710c838347Ae178B4a'),
  stripeLive: join('sk', '_live_', '4eC39HqLyjWDarjtT1zdp7dc'),
  slackBot: join('xo', 'xb-', '12345678-12345678-abcdefghijklmnop'),
  openaiProject: join('sk', '-proj-', 'AbCdEf1234567890_xyzXYZ-abcdefgh'),
  anthropic: join('sk', '-ant-', 'api03-AbCdEf1234567890_xyzXYZ-abcdefgh'),
  googleApiKey: join('AI', 'za', 'SyD-abcdefghijklmnopqrstuvwxyz12345'),
  huggingFace: join('hf', '_', 'abcdefghijklmnopqrstuvwxyzABCDEFGH'),
  gitlabPat: join('gl', 'pat-', 'AbCdEfGhIjKlMnOpQrSt'),
  slackWebhookPath,
  slackWebhookUrl: join('https://hooks', '.slack.com/services/', slackWebhookPath),
}
