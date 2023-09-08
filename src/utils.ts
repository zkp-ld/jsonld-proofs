import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import { Url, RemoteDocument } from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import { CONTEXTS, DATA_INTEGRITY_CONTEXT } from './contexts';
import { JsonValue, VC, VCDocument } from './types';

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
    safe: true,
  })) as unknown as string;

export const vcToRDF = async (vc: VC) => {
  const clonedVC = JSON.parse(JSON.stringify(vc)) as VC;

  const proof = clonedVC.proof;
  const document = clonedVC as VCDocument;
  delete document.proof;

  if (!('@context' in proof)) {
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  const documentRDF = await jsonldToRDF(document);
  const proofRDF = await jsonldToRDF(proof);

  return { document, documentRDF, proof, proofRDF };
};

export const expandedVCToRDF = async (vc: jsonld.NodeObject[]) => {
  const clonedVC = JSON.parse(JSON.stringify(vc)) as jsonld.NodeObject[];

  if (
    !(PROOF in clonedVC[0]) ||
    !Array.isArray(clonedVC[0][PROOF]) ||
    typeof clonedVC[0][PROOF][0] !== 'object' ||
    clonedVC[0][PROOF][0] === null ||
    !('@graph' in clonedVC[0][PROOF][0]) ||
    !Array.isArray(clonedVC[0][PROOF][0]['@graph'])
  ) {
    throw new TypeError('VC must have proof');
  }

  if (clonedVC[0][PROOF][0]['@graph'].length > 1) {
    throw new TypeError('VC must have single proof');
  }

  const proof = clonedVC[0][PROOF][0]['@graph'][0];

  if (typeof proof !== 'object' || proof === null || Array.isArray(proof)) {
    throw new TypeError('invalid VC');
  }
  delete clonedVC[0][PROOF];

  const documentRDF = await jsonldToRDF(clonedVC);
  const proofRDF = await jsonldToRDF(proof);

  return { documentRDF, proofRDF };
};

const _diffJSONLD = (
  node: JsonValue,
  path: (string | number)[],
  deanonMap: Map<string, string>,
  skolemIDMap: Map<(string | number)[], string>,
  maskedIDMap: Map<(string | number)[], string>,
  maskedLiteralMap: Map<(string | number)[], string>,
) => {
  if (Array.isArray(node)) {
    node.forEach((item, i) => {
      const updatedPath = path.concat([i]);

      if (!Array.isArray(item) || item.length !== 2) {
        throw new TypeError('json-diff error');
      }
      if (item[0] === '~') {
        _diffJSONLD(
          item[1],
          updatedPath,
          deanonMap,
          skolemIDMap,
          maskedIDMap,
          maskedLiteralMap,
        );
      }
    });
  } else if (typeof node === 'object' && node !== null) {
    for (const key in node) {
      if (key === '@id') {
        const oldAndNew = node[key];
        if (
          typeof oldAndNew === 'object' &&
          oldAndNew !== null &&
          '__old' in oldAndNew &&
          '__new' in oldAndNew
        ) {
          const orig = oldAndNew['__old'] as string;
          let masked = oldAndNew['__new'] as string;
          // remove prefix `_:` if exist
          if (masked.startsWith('_:')) {
            masked = masked.substring(2);
          }
          maskedIDMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          deanonMap.set(`_:${masked}`, `<${orig}>`);
        } else {
          throw new TypeError('json-diff error: __old or __new do not exist');
        }
      } else if (key === '@value') {
        const oldAndNew = node[key];
        if (
          typeof oldAndNew === 'object' &&
          oldAndNew !== null &&
          '__old' in oldAndNew &&
          '__new' in oldAndNew
        ) {
          const orig = oldAndNew['__old'] as string;
          let masked = oldAndNew['__new'] as string;
          // remove prefix `_:` if exist
          if (masked.startsWith('_:')) {
            masked = masked.substring(2);
          }
          maskedLiteralMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          deanonMap.set(`_:${masked}`, `"${orig}"`);
        } else {
          throw new TypeError('json-diff error: __old or __new do not exist');
        }
      } else if (key === '@id__deleted') {
        const value = node[key] as string;
        if (value.startsWith(SKOLEM_PREFIX)) {
          skolemIDMap.set(path, value);
        } else {
          const masked = nanoid();
          skolemIDMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          deanonMap.set(`_:${masked}`, `<${value}>`);
        }
      } else if (key.endsWith('__deleted')) {
        continue;
      } else {
        const updatedPath = path.concat([key]);
        const value = node[key];
        if (typeof value === 'object') {
          _diffJSONLD(
            value,
            updatedPath,
            deanonMap,
            skolemIDMap,
            maskedIDMap,
            maskedLiteralMap,
          );
        }
      }
    }
  }

  return {};
};

export const diffVC = (
  vc: jsonld.JsonLdDocument,
  disclosed: jsonld.JsonLdDocument,
) => {
  const diffObj = diff(vc, disclosed) as JsonValue;
  const deanonMap = new Map<string, string>();
  const skolemIDMap = new Map<(string | number)[], string>();
  const maskedIDMap = new Map<(string | number)[], string>();
  const maskedLiteralMap = new Map<(string | number)[], string>();

  _diffJSONLD(
    diffObj,
    [],
    deanonMap,
    skolemIDMap,
    maskedIDMap,
    maskedLiteralMap,
  );

  return { deanonMap, skolemIDMap, maskedIDMap, maskedLiteralMap };
};

const SKOLEM_PREFIX = 'urn:bnid:';
const SKOLEM_REGEX = /[<"]urn:bnid:([^>"]+)[>"]/g;

const _skolemizeJSONLD = (node: JsonValue) => {
  if (Array.isArray(node)) {
    node.forEach((item) => {
      if (typeof item === 'object' && item !== null) {
        _skolemizeJSONLD(item);
      }
    });
  } else if (typeof node === 'object' && node !== null) {
    for (const key in node) {
      if (
        typeof node[key] === 'object' &&
        node[key] !== undefined &&
        key !== '@context'
      ) {
        _skolemizeJSONLD(node[key]);
      }
    }
    if (!('id' in node || '@id' in node)) {
      node['@id'] = `${SKOLEM_PREFIX}${nanoid()}`;
    }
  }
};

export const skolemizeVC = (vc: VC) => {
  const output = JSON.parse(JSON.stringify(vc)) as VC;
  _skolemizeJSONLD(output as JsonValue);

  return output;
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
    safe: true,
  });

  const out = await jsonld.frame(expandedJsonld, vp_frame, {
    documentLoader: customLoader,
    safe: true,
  });

  return out;
};

export const traverseJSON = (root: JsonValue, path: (string | number)[]) => {
  let node = root;

  for (const item of path) {
    if (Array.isArray(node)) {
      if (typeof item !== 'number') {
        throw new Error(
          'internal error when injecting skolem IDs to disclosed VC',
        );
      }
      node = node[item];
    } else if (typeof node === 'object' && node !== null) {
      if (typeof item !== 'string') {
        throw new Error(
          'internal error when injecting skolem IDs to disclosed VC',
        );
      }
      node = node[item];
    } else {
      throw new Error(
        'internal error when injecting skolem IDs to disclosed VC',
      );
    }
  }

  if (typeof node !== 'object' || node === null || Array.isArray(node)) {
    throw new Error('internal error when injecting skolem IDs to disclosed VC');
  }

  return node;
};
