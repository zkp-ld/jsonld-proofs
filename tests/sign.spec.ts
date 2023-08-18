import disclosed0 from '../example/disclosed0.json';
import disclosed1 from '../example/disclosed1.json';
import keypair0 from '../example/keypair0.json';
import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0.json';
import vcDraft1 from '../example/vc1.json';
import { sign, verify, deriveProof } from '../src/api';

describe('Proofs', () => {
  test('sign and verify', async () => {
    const vc0 = await sign(vcDraft0, keypair0);
    console.log(`vc0: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verified0 = await verify(vc0, keypair0);
    console.log(`verified0: ${JSON.stringify(verified0, null, 2)}`);
    expect(verified0.verified).toBeTruthy();

    const vc1 = await sign(vcDraft1, keypairs);
    console.log(`vc1: ${JSON.stringify(vc1, null, 2)}`);
    expect(vc1).toBeDefined();

    const verified1 = await verify(vc1, keypairs);
    console.log(`verified1: ${JSON.stringify(verified1, null, 2)}`);
    expect(verified1.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof', async () => {
    const vc0 = await sign(vcDraft0, keypair0);
    const vc1 = await sign(vcDraft1, keypairs);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [
        { vc: vc0, disclosed: disclosed0 },
        { vc: vc1, disclosed: disclosed1 },
      ],
      nonce,
      keypairs,
    );
    console.log(`vp:${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');
  });
});
