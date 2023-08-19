import * as jsonld from 'jsonld';
import disclosed0 from '../example/disclosed0-a.json';
import disclosed1 from '../example/disclosed1-a.json';
import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0-a.json';
import vcDraft1 from '../example/vc1.json';
import vp from '../example/vp.json';
import _vpContext from '../example/vpContext.json';
import { sign, deriveProof, verifyProof } from '../src/api';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

describe('Proofs2', () => {
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

  test('verifyProof', async () => {
    const nonce = 'abcde';
    const verified = await verifyProof(vp, nonce, keypairs);
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });
});
