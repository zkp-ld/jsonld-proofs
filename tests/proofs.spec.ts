import * as jsonld from 'jsonld';
import { RemoteDocument, Url } from 'jsonld/jsonld-spec';

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
import { CONTEXTS } from './contexts';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

const localDocumentLoader = async (
  url: Url,
  _callback: (err: Error, remoteDoc: RemoteDocument) => void,
  // eslint-disable-next-line @typescript-eslint/require-await
): Promise<RemoteDocument> => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      documentUrl: url, // this is the actual context URL after redirects
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      document: CONTEXTS[url], // this is the actual document that was loaded
    } as RemoteDocument;
  }

  // call the default documentLoader
  //return nodeDocumentLoader(url);
  return {
    contextUrl: undefined,
    documentUrl: url,
    document: {},
  } as RemoteDocument;
};

describe('Proofs', () => {
  test('deriveProof and verifyProof', async () => {
    const vc0 = await sign(vcDraft0, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      nonce,
      keypairs,
      vpContext,
      localDocumentLoader,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      nonce,
      keypairs,
      localDocumentLoader,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('verifyProof', async () => {
    const nonce = 'abcde';
    const verified = await verifyProof(
      vp,
      nonce,
      keypairs,
      localDocumentLoader,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with hidden literal', async () => {
    const vc0 = await sign(vc0HiddenLiteral, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0HiddenLiteral },
        { original: vc1, disclosed: disclosed1 },
      ],
      nonce,
      keypairs,
      vpContext,
      localDocumentLoader,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      nonce,
      keypairs,
      localDocumentLoader,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with hidden literal (2)', async () => {
    const vc2 = await sign(vcDraft2, keypairs, localDocumentLoader);
    const nonce = 'abcde';
    const vp = await deriveProof(
      [{ original: vc2, disclosed: disclosed2 }],
      nonce,
      keypairs,
      vpContext,
      localDocumentLoader,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(
      vp,
      nonce,
      keypairs,
      localDocumentLoader,
    );
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });
});
