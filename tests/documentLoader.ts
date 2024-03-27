import * as jsonld from 'jsonld';
import { RemoteDocument, Url } from 'jsonld/jsonld-spec';
import { CONTEXTS } from './contexts';

export const localDocumentLoader = async (
  url: Url,
  // eslint-disable-next-line @typescript-eslint/require-await
): Promise<RemoteDocument> => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      document: CONTEXTS[url], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    } as RemoteDocument;
  }

  // return empty document if `url` is not in local contexts
  return {
    contextUrl: undefined,
    documentUrl: url,
    document: {},
  } as RemoteDocument;
};

// grab the built-in Node.js document loader
const nodeDocumentLoader = jsonld.documentLoaders.node();

export const remoteDocumentLoader = async (
  url: Url,
): Promise<RemoteDocument> => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      document: CONTEXTS[url], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    } as RemoteDocument;
  }

  // call the default documentLoader
  const res = await nodeDocumentLoader(url);

  return res;
};

