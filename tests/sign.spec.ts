import disclosed0 from '../example/disclosed0.json';
import keypair0 from '../example/keypair0.json';
import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0.json';
import { sign, verify, deriveProof } from '../src/api';

describe('Proofs', () => {
  test('sign and verify', async () => {
    const vc0 = await sign(vcDraft0, keypair0);
    console.log(`vc0: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verified = await verify(vc0, keypair0);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof', async () => {
    const vc0 = await sign(vcDraft0, keypair0);
    const nonce = 'abcde';
    await deriveProof([{ vc: vc0, disclosed: disclosed0 }], nonce, keypairs);
  });
});
