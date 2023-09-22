import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import * as jsonldSpec from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import { DocumentLoader, JsonValue, VC, VCDocument } from './types';

const PROOF = 'https://w3id.org/security#proof';
const DATA_INTEGRITY_CONTEXT = 'https://www.w3.org/ns/data-integrity/v1';

const nanoid = customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 10);

export const jsonldToRDF = async (
  jsonldDoc: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
) =>
  (await jsonld.toRDF(jsonldDoc, {
    format: 'application/n-quads',
    documentLoader,
    safe: true,
  })) as unknown as string;

export const vcToRDF = async (vc: VC, documentLoader: DocumentLoader) => {
  const clonedVC = JSON.parse(JSON.stringify(vc)) as VC;

  const proof = clonedVC.proof;
  const document = clonedVC as VCDocument;
  delete document.proof;

  if (!('@context' in proof)) {
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  const documentRDF = await jsonldToRDF(document, documentLoader);
  const proofRDF = await jsonldToRDF(proof, documentLoader);

  return { document, documentRDF, proof, proofRDF };
};

export const expandedVCToRDF = async (
  vc: jsonld.NodeObject[],
  documentLoader: DocumentLoader,
) => {
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

  const documentRDF = await jsonldToRDF(clonedVC, documentLoader);
  const proofRDF = await jsonldToRDF(proof, documentLoader);

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
          const masked = oldAndNew['__new'] as string;
          if (!masked.startsWith('_:')) {
            throw new TypeError(
              `json-diff error: replacement value \`${masked}\` must start with \`_:\``,
            );
          }
          maskedIDMap.set(path, `${SKOLEM_PREFIX}${masked.substring(2)}`);
          deanonMap.set(masked, `<${orig}>`);
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
          const masked = oldAndNew['__new'] as string;
          if (!masked.startsWith('_:')) {
            throw new TypeError(
              `json-diff error: replacement value \`${masked}\` must start with \`_:\``,
            );
          }
          maskedLiteralMap.set(path, `${SKOLEM_PREFIX}${masked.substring(2)}`);
          deanonMap.set(masked, `"${orig}"`);
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
    if (!('@value' in node || '@id' in node)) {
      node['@id'] = `${SKOLEM_PREFIX}${nanoid()}`;
    }
  }
};

export const skolemizeVC = (vc: jsonldSpec.JsonLdArray) => {
  const output = JSON.parse(JSON.stringify(vc)) as JsonValue;
  _skolemizeJSONLD(output);

  return output as jsonldSpec.JsonLdArray;
};

export const deskolemizeNQuads = (nquads: string) =>
  nquads.replace(SKOLEM_REGEX, '_:$1');

export const jsonldProofFromRDF = async (
  proofRDF: string,
  documentLoader: DocumentLoader,
) => {
  const proofFrame: jsonld.JsonLdDocument = {
    '@context': DATA_INTEGRITY_CONTEXT,
    type: 'DataIntegrityProof',
  };

  const proofRDFObj = proofRDF as unknown as object;
  const expandedJsonld = await jsonld.fromRDF(proofRDFObj, {
    format: 'application/n-quads',
    safe: true,
  });

  const out = await jsonld.frame(expandedJsonld, proofFrame, {
    documentLoader,
    safe: true,
  });

  return out;
};

export const jsonldVPFromRDF = async (
  vpRDF: string,
  context: jsonld.ContextDefinition,
  documentLoader: DocumentLoader,
) => {
  const vpFrame: jsonld.JsonLdDocument = {
    type: 'VerifiablePresentation',
    proof: {},
    verifiableCredential: [
      {
        type: 'VerifiableCredential',
      },
    ],
  };
  vpFrame['@context'] = context;

  const vpRDFObj = vpRDF as unknown as object;
  const expandedJsonld = await jsonld.fromRDF(vpRDFObj, {
    format: 'application/n-quads',
    safe: true,
  });

  const out = await jsonld.frame(expandedJsonld, vpFrame, {
    documentLoader,
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
