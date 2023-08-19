import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import { CONTEXTS, DATA_INTEGRITY_CONTEXT } from './contexts';

const nanoid = customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 10);

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

export const jsonldToRDF = async (jsonldDoc: jsonld.JsonLdDocument) =>
  (await jsonld.toRDF(jsonldDoc, {
    format: 'application/n-quads',
    documentLoader: customLoader,
  })) as unknown as string;

export const splitDocAndProof = (vc: jsonld.JsonLdDocument) => {
  if (!('proof' in vc)) {
    return { error: 'VC must have proof' };
  }

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const document: jsonld.NodeObject = JSON.parse(JSON.stringify(vc));
  const proof = document.proof as jsonld.NodeObject;
  delete document.proof;

  if (!('@context' in proof)) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  return { document, proof };
};

export const vcToRDF = async (vc: jsonld.JsonLdDocument) => {
  const documentAndProof = splitDocAndProof(vc);
  if ('error' in documentAndProof) {
    return { error: documentAndProof.error };
  }
  const { document, proof } = documentAndProof;

  const documentRDF = await jsonldToRDF(document);
  const proofRDF = await jsonldToRDF(proof);

  return { document, documentRDF, proof, proofRDF };
};

export const vcDiff = (
  vc: jsonld.JsonLdDocument,
  disclosed: jsonld.JsonLdDocument,
) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const diffObj = diff(vc, disclosed);

  console.log(`diff: ${JSON.stringify(diffObj, null, 2)}`);

  const deanonMap = new Map<string, string>();
  const skolemIDMap = new Map<string[], string>();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _recurse = (node: any, path: string[]): { error?: string } => {
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
          if (key === '__new') {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const masked = node['__new'] as string;
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const orig = node['__old'] as string;
            deanonMap.set(masked, orig);
          } else if (key === '@id__deleted' || key === 'id__deleted') {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const value = node[key] as string;
            if (value.startsWith(SKOLEM_PREFIX)) {
              skolemIDMap.set(path, value);
            } else {
              // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
              const masked = nanoid();
              deanonMap.set(masked, value);
              skolemIDMap.set(path, masked);
            }
          } else {
            const updatedPath = path.concat([key]);
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const result = _recurse(node[key], updatedPath);
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
  const result = _recurse(diffObj, []);
  if ('error' in result) {
    return { error: result.error };
  }

  return { deanonMap, skolemIDMap };
};

const SKOLEM_PREFIX = 'urn:bnid:';
const SKOLEM_REGEX = /[<"]urn:bnid:([^>"]+)[>"]/g;

export const skolemizeJSONLD = (vc: jsonld.JsonLdDocument) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const output = JSON.parse(JSON.stringify(vc));

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _recurse = (node: any) => {
    if (Array.isArray(node)) {
      node.forEach((item) => {
        if (typeof item === 'object' && item !== null) {
          _recurse(item);
        }
      });
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
        if (node.hasOwnProperty(key)) {
          if (
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            typeof node[key] === 'object' &&
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            node[key] !== null &&
            // context object should not be skolemized
            key !== '@context'
          ) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            _recurse(node[key]);
          }
        }
      }
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call, no-prototype-builtins
      if (!node.hasOwnProperty('id') && !node.hasOwnProperty('@id')) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        node['@id'] = `${SKOLEM_PREFIX}${nanoid()}`;
      }
    }
  };

  _recurse(output);

  return output as jsonld.JsonLdDocument;
};

export const replaceMaskWithSkolemID = (
  vc: jsonld.JsonLdDocument,
  deanonMap: Map<string, string>,
) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const output = JSON.parse(JSON.stringify(vc));

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _replace = (item: any) =>
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-argument
    deanonMap.has(item) ? `${SKOLEM_PREFIX}${item}` : item;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const _recurse = (node: any) => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => {
        if (typeof item === 'object' && item !== null) {
          _recurse(item);
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
            _recurse(node[key]);
          } else {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
            node[key] = _replace(node[key]);
          }
        }
      }
    }
  };

  _recurse(output);

  return output as jsonld.JsonLdDocument;
};

export const deskolemizeNQuads = (nquads: string) =>
  nquads.replace(SKOLEM_REGEX, '_:$1');

export const jsonldVPFromRDF = async (
  vpRDF: string,
  context: jsonld.ContextDefinition,
) => {
  const vp_frame: jsonld.JsonLdDocument = {
    type: 'VerifiablePresentation',
    proof: {},
    verifiableCredential: [
      {
        type: 'VerifiableCredential',
      },
    ],
  };
  vp_frame['@context'] = context;

  const vpRDFObj = vpRDF as unknown as object;
  const expandedJsonld = await jsonld.fromRDF(vpRDFObj, {
    format: 'application/n-quads',
  });

  const out = await jsonld.frame(expandedJsonld, vp_frame);

  return out;
};
