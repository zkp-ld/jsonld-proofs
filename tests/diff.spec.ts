import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import { RemoteDocument, Url } from 'jsonld/jsonld-spec';
import disclosed0HiddenLiteral from '../example/disclosed0_hidden_literal.json';
import vcDraft0 from '../example/vc0.json';
import { CONTEXTS } from '../src/contexts';

const customLoader = async (
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

describe('Diff', () => {
  test('deriveProof and verifyProof with hidden literal', async () => {
    // diff between compact VCs
    console.log(`VC0:\n${JSON.stringify(vcDraft0, null, 2)}`);
    console.log(
      `disclosed0:\n${JSON.stringify(disclosed0HiddenLiteral, null, 2)}`,
    );
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const diffObj = diff(vcDraft0, disclosed0HiddenLiteral);
    console.log(`diff(compact): ${JSON.stringify(diffObj, null, 2)}`);

    // diff between expanded VCs
    const expandedVC0 = await jsonld.expand(vcDraft0, {
      documentLoader: customLoader,
    });
    console.log(`expandedVC0:\n${JSON.stringify(expandedVC0, null, 2)}`);
    const expandedDisclosed0 = await jsonld.expand(disclosed0HiddenLiteral, {
      documentLoader: customLoader,
    });
    console.log(
      `expandedDisclosed0:\n${JSON.stringify(expandedDisclosed0, null, 2)}`,
    );
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const expandedDiffObj = diff(expandedVC0, expandedDisclosed0);
    console.log(`diff(expand): ${JSON.stringify(expandedDiffObj, null, 2)}`);
  });
});
