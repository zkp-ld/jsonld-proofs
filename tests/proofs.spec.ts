import * as jsonld from 'jsonld';
import disclosed0 from '../example/disclosed0.json';
import disclosed1 from '../example/disclosed1.json';
import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0.json';
import vcDraft1 from '../example/vc1.json';
import _vpContext from '../example/vpContext.json';
import { sign, verify, deriveProof, verifyProof, keyGen } from '../src/api';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

describe('Proofs', () => {
  test('keyGen', async () => {
    const keypair = await keyGen();
    console.log(`keypair: ${JSON.stringify(keypair, null, 2)}`);

    expect(keypair.secretKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
  });

  test('sign and verify', async () => {
    const vc0 = await sign(vcDraft0, keypairs);
    console.log(`vc0: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verified0 = await verify(vc0, keypairs);
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
    const vc0 = await sign(vcDraft0, keypairs);
    const vc1 = await sign(vcDraft1, keypairs);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [
        { vc: vc0, disclosed: disclosed0 },
        { vc: vc1, disclosed: disclosed1 },
      ],
      nonce,
      keypairs,
      vpContext,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, nonce, keypairs);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });
});
