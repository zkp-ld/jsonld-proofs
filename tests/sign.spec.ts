import disclosed0 from '../example/disclosed0.json';
import keypair0 from '../example/keypair0.json';
import vcDraft0 from '../example/vc0.json';
import { sign, verify } from '../src/api';
import { vcDiff } from '../src/utils';

console.log(`vcDraft0: ${JSON.stringify(vcDraft0, null, 2)}`);
console.log(`keypair0: ${JSON.stringify(keypair0, null, 2)}`);

describe('Proofs', () => {
  test('sign and verify', async () => {
    const vc0 = await sign(vcDraft0, keypair0);
    console.log(`vc0: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verified = await verify(vc0, keypair0);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('json-diff', () => {
    console.log(vcDiff(vcDraft0, disclosed0));
  });
});
