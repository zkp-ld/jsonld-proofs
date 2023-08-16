import { toRDF } from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { deriveProof, keyGen, sign as signWasm, verify, verifyProof, initializeWasm } from '@zkp-ld/rdf-proofs-wasm';
import { CONTEXTS } from './contexts';

const customLoader = async (url: Url, callback: (err: Error, remoteDoc: RemoteDocument) => void): Promise<RemoteDocument> => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      documentUrl: url, // this is the actual context URL after redirects
      document: CONTEXTS[url], // this is the actual document that was loaded
    } as RemoteDocument;
  }
  // call the default documentLoader
  //return nodeDocumentLoader(url);
  return {
    contextUrl: undefined,
    documentUrl: url,
    document: {},
  } as RemoteDocument
};

export const sign = async (unsecuredDocument: any, proofConfig: any, documentLoader: any): Promise<any> => {
  await initializeWasm();

  const doc = await toRDF(unsecuredDocument, { format: 'application/n-quads', documentLoader: customLoader }) as unknown as string;
  const proof = await toRDF(proofConfig, { format: 'application/n-quads', documentLoader: customLoader }) as unknown as string;
  const docLoader = await toRDF(documentLoader, { format: 'application/n-quads', documentLoader: customLoader }) as unknown as string;

  console.log(`doc: ${doc}`);
  console.log(`proof: ${proof}`);
  console.log(`docLoader: ${docLoader}`);

  const signature = signWasm(doc, proof, docLoader);

  delete proofConfig[`@context`];
  unsecuredDocument.proof = proofConfig;
  unsecuredDocument.proof.proofValue = signature;

  return unsecuredDocument;
}
