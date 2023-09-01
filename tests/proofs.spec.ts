import * as jsonld from 'jsonld';
import disclosed0 from '../example/disclosed0.json';
import disclosed0HiddenLiteral from '../example/disclosed0_hidden_literals.json';
import disclosed1 from '../example/disclosed1.json';
import disclosed2 from '../example/disclosed2.json';
import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0.json';
import vc0HiddenLiteral from '../example/vc0_hidden_literals.json';
import vcDraft1 from '../example/vc1.json';
import vcDraft2 from '../example/vc2.json';
import vp from '../example/vp.json';
import _vpContext from '../example/vpContext.json';
import { sign, deriveProof, verifyProof } from '../src/api';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

describe('Proofs', () => {
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

  test('deriveProof and verifyProof with hidden literal', async () => {
    const vc0 = await sign(vc0HiddenLiteral, keypairs);
    const vc1 = await sign(vcDraft1, keypairs);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [
        { vc: vc0, disclosed: disclosed0HiddenLiteral },
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

  test('deriveProof and verifyProof with hidden literal (2)', async () => {
    const vc2 = await sign(vcDraft2, keypairs);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [{ vc: vc2, disclosed: disclosed2 }],
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
