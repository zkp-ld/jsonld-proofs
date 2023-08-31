import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import { CONTEXTS, DATA_INTEGRITY_CONTEXT } from './contexts';

const PROOF = 'https://w3id.org/security#proof';
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
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const document = JSON.parse(JSON.stringify(vc)) as jsonld.JsonLdDocument;

  if (!('proof' in vc)) {
    return { error: 'VC must have proof' };
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  const proof = document.proof as jsonld.JsonLdDocument;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  delete document.proof;

  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  return { document, proof };
};

export const vcToRDF = async (vc: jsonld.JsonLdDocument) => {
  const documentAndProof = splitDocAndProof(vc);
  if ('error' in documentAndProof) {
    return { error: documentAndProof.error };
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  const { document, proof } = documentAndProof;

  if (!('@context' in proof)) {
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  const documentRDF = await jsonldToRDF(document);
  const proofRDF = await jsonldToRDF(proof);

  return { document, documentRDF, proof, proofRDF };
};

export const splitExpandedDocAndProof = (vc: jsonld.JsonLdDocument) => {
  const document = JSON.parse(JSON.stringify(vc)) as jsonld.JsonLdDocument;

  // TODO: fix me
  if (!(Array.isArray(document) && PROOF in document[0])) {
    return { error: 'VC must have proof' };
  }
  // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
  const proof = document[0][PROOF][0]['@graph'] as jsonld.JsonLdDocument;
  delete document[0][PROOF];

  return { document, proof };
};

export const expandedVCToRDF = async (vc: jsonld.JsonLdDocument) => {
  const documentAndProof = splitExpandedDocAndProof(vc);
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

  const deanonMap = new Map<string, string>();
  const skolemIDMap = new Map<(string | number)[], string>();
  const maskedIDMap = new Map<(string | number)[], string>();
  const maskedLiteralMap = new Map<(string | number)[], string>();

  const _recurse = (
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    node: any,
    path: (string | number)[],
  ): { error?: string } => {
    if (Array.isArray(node)) {
      node.forEach((item, i) => {
        const updatedPath = path.concat([i]);

        if (!Array.isArray(item) || item.length !== 2) {
          return { error: 'json-diff error' };
        }
        if (item[0] === '~') {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
          const result = _recurse(item[1], updatedPath);
          if ('error' in result) {
            return { error: result.error };
          }
        }
      });
    } else if (typeof node === 'object' && node !== null) {
      for (const key in node) {
        if (key === '@id') {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          const oldAndNew = node[key];
          if (
            typeof oldAndNew === 'object' &&
            '__old' in oldAndNew &&
            '__new' in oldAndNew
          ) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const masked = oldAndNew['__new'] as string;
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const orig = oldAndNew['__old'] as string;
            deanonMap.set(`_:${masked}`, `<${orig}>`);
            maskedIDMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          } else {
            return {
              error: 'json-diff error: __old or __new do not exist',
            };
          }
        } else if (key === '@value') {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          const oldAndNew = node[key];
          if (
            typeof oldAndNew === 'object' &&
            '__old' in oldAndNew &&
            '__new' in oldAndNew
          ) {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const masked = oldAndNew['__new'] as string;
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const orig = oldAndNew['__old'] as string;
            deanonMap.set(`_:${masked}`, `"${orig}"`);
            maskedLiteralMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          } else {
            return {
              error: 'json-diff error: __old or __new do not exist',
            };
          }
        } else if (key === '@id__deleted') {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
          const value = node[key] as string;
          if (value.startsWith(SKOLEM_PREFIX)) {
            skolemIDMap.set(path, value);
          } else {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const masked = nanoid();
            deanonMap.set(`_:${masked}`, `<${value}>`);
            skolemIDMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          }
        } else if (key.endsWith('__deleted')) {
          continue;
        } else {
          const updatedPath = path.concat([key]);
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          const value = node[key];
          if (typeof value === 'object') {
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const result = _recurse(value, updatedPath);
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

  return { deanonMap, skolemIDMap, maskedIDMap, maskedLiteralMap };
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
