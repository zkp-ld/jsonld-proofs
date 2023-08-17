import {
  sign as signWasm,
  verify as verifyWasm,
  initializeWasm,
  VerifyResult,
} from '@zkp-ld/rdf-proofs-wasm';
import { JsonLdDocument, NodeObject, toRDF } from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { CONTEXTS } from './contexts';

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

export const sign = async (
  unsecuredDocument: JsonLdDocument,
  proofConfig: JsonLdDocument,
  documentLoader: JsonLdDocument,
): Promise<JsonLdDocument> => {
  await initializeWasm();

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const output: NodeObject = JSON.parse(JSON.stringify(unsecuredDocument));
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const outputProof: NodeObject = JSON.parse(JSON.stringify(proofConfig));

  const doc = (await toRDF(unsecuredDocument, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;
  const proof = (await toRDF(proofConfig, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;
  const docLoader = (await toRDF(documentLoader, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;

  const signature = signWasm(doc, proof, docLoader);

  output.proof = outputProof;
  output.proof.proofValue = signature;

  return output;
};

export const verify = async (
  vc: JsonLdDocument,
  documentLoader: JsonLdDocument,
): Promise<VerifyResult> => {
  await initializeWasm();

  if (!('proof' in vc)) {
    return { verified: false, error: 'VC must have proof' };
  }
  const proofConfig = vc.proof as NodeObject;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const document: NodeObject = JSON.parse(JSON.stringify(vc));
  delete document.proof;

  const doc = (await toRDF(document, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;
  const proof = (await toRDF(proofConfig, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;
  const docLoader = (await toRDF(documentLoader, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;

  const verified = verifyWasm(doc, proof, docLoader);

  return verified;
};
