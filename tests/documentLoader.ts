import * as jsonld from 'jsonld';
import { CONTEXTS } from './contexts';
import { DocumentLoader } from '../src/types';

export const localDocumentLoader: DocumentLoader = async (
  url
  // eslint-disable-next-line @typescript-eslint/require-await
) => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      document: CONTEXTS[url], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    }
  }

  // return empty document if `url` is not in local contexts
  return {
    contextUrl: undefined,
    documentUrl: url,
    document: {},
  }
};

// grab the built-in Node.js document loader
const nodeDocumentLoader = jsonld.documentLoaders.node();

export const remoteDocumentLoader: DocumentLoader = async (
  url
) => {
  if (url in CONTEXTS) {
    return {
      contextUrl: undefined, // this is for a context via a link header
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      document: CONTEXTS[url], // this is the actual document that was loaded
      documentUrl: url, // this is the actual context URL after redirects
    }
  }

  // call the default documentLoader
  const res = await nodeDocumentLoader(url);

  return res;
};
