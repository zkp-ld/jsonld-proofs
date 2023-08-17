import { JsonLdDocument, NodeObject, toRDF } from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { CONTEXTS, DATA_INTEGRITY_CONTEXT } from './contexts';

export const customLoader = async (
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

export const jsonld2rdf = async (jsonldDoc: JsonLdDocument) =>
  (await toRDF(jsonldDoc, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;

export const splitDocAndProof = (vc: JsonLdDocument) => {
  if (!('proof' in vc)) {
    return { error: 'VC must have proof' };
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const document: NodeObject = JSON.parse(JSON.stringify(vc));
  const proof = document.proof as NodeObject;
  delete document.proof;

  if (!('@context' in proof)) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  return { document, proof };
};

export const vc2rdf = async (
  vc: JsonLdDocument,
  documentLoader: JsonLdDocument,
) => {
  const documentAndProof = splitDocAndProof(vc);
  if ('error' in documentAndProof) {
    return { error: documentAndProof.error };
  }
  const { document, proof } = documentAndProof;

  const documentRDF = await jsonld2rdf(document);
  const proofRDF = await jsonld2rdf(proof);
  const documentLoaderRDF = await jsonld2rdf(documentLoader);

  return { document, documentRDF, proof, proofRDF, documentLoaderRDF };
};
