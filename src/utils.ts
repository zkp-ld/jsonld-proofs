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

export const jsonldToRDF = async (jsonldDoc: JsonLdDocument) =>
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

export const vcToRDF = async (vc: JsonLdDocument) => {
  const documentAndProof = splitDocAndProof(vc);
  if ('error' in documentAndProof) {
    return { error: documentAndProof.error };
  }
  const { document, proof } = documentAndProof;

  const documentRDF = await jsonldToRDF(document);
  const proofRDF = await jsonldToRDF(proof);

  return { document, documentRDF, proof, proofRDF };
};

export const vcDiff = (vc: JsonLdDocument, disclosed: JsonLdDocument) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const diffObj = diff(vc, disclosed);

  const deanonMap = new Map<string, string>();

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
        deanonMap.set(after[i], orig);
      });
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
        if (node.hasOwnProperty(key)) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
          if (node[key].hasOwnProperty('__new')) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const masked = node[key]['__new'] as string;
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const orig = node[key]['__old'] as string;
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

  const isBlank = (v: string) => v.startsWith('_:');
  const _makeBlank = (v: string) => (isBlank(v) ? v : `_:${v}`);

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const result = explorer(diffObj);
  if ('error' in result) {
    return { error: result.error };
  }

  return deanonMap;
};

const SKOLEM_PREFIX = 'urn:bnid:';
const SKOLEM_REGEX = /[<"]urn:bnid:([^>"]+)[>"]/g;

export const replaceMaskWithSkolemID = (
  vc: JsonLdDocument,
  deanonMap: Map<string, string>,
) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const output = JSON.parse(JSON.stringify(vc));

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _replace = (item: any) =>
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument
    deanonMap.has(item) ? `${SKOLEM_PREFIX}${item}` : item;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _recursiveReplace = (node: any) => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => {
        if (typeof item === 'object' && item !== null) {
          _recursiveReplace(item);
        } else {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          node[i] = _replace(item);
        }
      });
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
        if (node.hasOwnProperty(key)) {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          if (typeof node[key] === 'object' && node[key] !== null) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            _recursiveReplace(node[key]);
          } else {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
            node[key] = _replace(node[key]);
          }
        }
      }
    }

    return {};
  };

  _recursiveReplace(output);

  return output as JsonLdDocument;
};

export const deskolemizeNQuads = (nquads: string) =>
  nquads.replace(SKOLEM_REGEX, '_:$1');
