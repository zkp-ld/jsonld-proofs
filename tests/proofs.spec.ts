import * as jsonld from 'jsonld';
import { sign, deriveProof, verifyProof } from '../src/api';
import { localDocumentLoader, remoteDocumentLoader } from './documentLoader';
import disclosed0 from './example/disclosed0.json';
import disclosed0HiddenLiteral from './example/disclosed0_hidden_literals.json';
import disclosed1 from './example/disclosed1.json';
import disclosed2 from './example/disclosed2.json';
import disclosed3 from './example/disclosed3.json';
import keypairs from './example/keypairs.json';
import vcDraft0 from './example/vc0.json';
import vc0HiddenLiteral from './example/vc0_hidden_literals.json';
import vcDraft1 from './example/vc1.json';
import vcDraft2 from './example/vc2.json';
import vcDraft3 from './example/vc3.json';
import vp from './example/vp.json';
import _vpContext from './example/vpContext.json';
import _vpContext3 from './example/vpContext3.json';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;
const vpContext3 = _vpContext3 as unknown as jsonld.ContextDefinition;

describe('Proofs', () => {
  test('deriveProof and verifyProof', async () => {
    const vc0 = await sign(vcDraft0, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      vpContext,
      localDocumentLoader,
      challenge,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      keypairs,
      localDocumentLoader,
      challenge,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with remote context', async () => {
    const vc3 = await sign(vcDraft3, keypairs, remoteDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [{ original: vc3, disclosed: disclosed3 }],
      keypairs,
      vpContext3,
      remoteDocumentLoader,
      challenge,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      keypairs,
      remoteDocumentLoader,
      challenge,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('verifyProof', async () => {
    const challenge = 'abcde';
    const verified = await verifyProof(
      vp,
      keypairs,
      localDocumentLoader,
      challenge,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with hidden literal', async () => {
    const vc0 = await sign(vc0HiddenLiteral, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0HiddenLiteral },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      vpContext,
      localDocumentLoader,
      challenge,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      keypairs,
      localDocumentLoader,
      challenge,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with hidden literal (2)', async () => {
    const vc2 = await sign(vcDraft2, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [{ original: vc2, disclosed: disclosed2 }],
      keypairs,
      vpContext,
      localDocumentLoader,
      challenge,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      keypairs,
      localDocumentLoader,
      challenge,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });
});
