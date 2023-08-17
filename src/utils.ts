import { diff } from 'json-diff';
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

export const vcDiff = (vc: JsonLdDocument, disclosed: JsonLdDocument) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const diffObj = diff(vc, disclosed);

  const deanonMap = new Map();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const explorer = (node: any): { error?: string } => {
    if (Array.isArray(node)) {
      const before: string[] = [];
      const after: string[] = [];
      node.forEach((item) => {
        if (!Array.isArray(item)) {
          return { error: 'internal error due to json diff' };
        }
        if (item[0] === '-') {
          before.push(item[1] as string);
        }
        if (item[0] === '+') {
          after.push(item[1] as string);
        }
      });
      if (before.length !== after.length) {
        return {
          error:
            'Ambiguity prevents matching pseudonymous parts in disclosed VC to their original values',
        };
      }
      before.forEach((orig, i) => {
        if (!isBlankNode(after[i])) {
          return {
            error:
              'replaced identifier must be blank node; it must start with `_:`',
          };
        }
        deanonMap.set(after[i], orig);
      });
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
        if (node.hasOwnProperty(key)) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
          if (node[key].hasOwnProperty('__new')) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
            const masked = node[key]['__new'];

            // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
            if (!isBlankNode(masked)) {
              return {
                error:
                  'replaced identifier must be blank node; it must start with `_:`',
              };
            }

            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
            const orig = node[key]['__old'];
            deanonMap.set(masked, orig);
          } else {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const result = explorer(node[key]);
            if ('error' in result) {
              return { error: result.error };
            }
          }
        }
      }
    }

    return {};
  };

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const result = explorer(diffObj);
  if ('error' in result) {
    return { error: result.error };
  }

  return deanonMap;
};

const isBlankNode = (key: string) => {
  return key.startsWith('_:');
};
