import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import * as jsonldSpec from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import { DocumentLoader, JsonValue, VC, VCDocument, VcPair } from './types';

const PROOF = 'https://w3id.org/security#proof';
const DATA_INTEGRITY_CONTEXT = 'https://www.w3.org/ns/data-integrity/v1';
const SKOLEM_PREFIX = 'urn:bnid:';
const SKOLEM_REGEX = /[<"]urn:bnid:([^>"]+)[>"]/g;

const nanoid = customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 10);

export const deskolemizeString = (s: string) => s.replace(SKOLEM_PREFIX, '_:');
export const deskolemizeTerm = (t: string) => t.replace(SKOLEM_REGEX, '_:$1');

export const jsonldToRDF = async (
  jsonldDoc: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
) =>
  (await jsonld.toRDF(jsonldDoc, {
    format: 'application/n-quads',
    documentLoader,
    safe: true,
  })) as unknown as string;

const skolemizeJSONLD = (node: JsonValue, includeOmittedId: boolean) => {
  if (Array.isArray(node)) {
    node.forEach((item) => {
      if (typeof item === 'object' && item !== null) {
        skolemizeJSONLD(item, includeOmittedId);
      }
    });
  } else if (typeof node === 'object' && node !== null) {
    for (const key in node) {
      if (
        typeof node[key] === 'object' &&
        node[key] !== undefined &&
        key !== '@context'
      ) {
        skolemizeJSONLD(node[key], includeOmittedId);
      } else {
        const value = node[key];
        if (typeof value === 'string' && value.startsWith('_:')) {
          node[key] = `${SKOLEM_PREFIX}${value.slice(2)}`;
        }
      }
    }
    if (
      includeOmittedId &&
      !('@value' in node || '@id' in node || '@list' in node)
    ) {
      node['@id'] = `${SKOLEM_PREFIX}${nanoid()}`;
    }
  }
};

// input `vc` must be *expanded* JSON-LD
const skolemizeVC = (
  vc: jsonldSpec.JsonLdArray | jsonld.JsonLdDocument,
  includeOmittedId?: boolean,
) => {
  const output = JSON.parse(JSON.stringify(vc)) as JsonValue;
  skolemizeJSONLD(
    output,
    includeOmittedId === undefined ? true : includeOmittedId,
  );

  return output as jsonldSpec.JsonLdArray;
};

const skolemizeAndExpandVcPair = async (
  vcPair: VcPair,
  documentLoader: DocumentLoader,
) => {
  const expandedOriginalVC = await jsonld.expand(vcPair.original, {
    documentLoader,
    safe: true,
  });
  const expandedDisclosedVC = await jsonld.expand(vcPair.disclosed, {
    documentLoader,
    safe: true,
  });

  return {
    original: skolemizeVC(expandedOriginalVC),
    disclosed: skolemizeVC(expandedDisclosedVC, false),
  };
};

export const getPredicatesRDF = (
  predicates: jsonld.JsonLdDocument[],
  documentLoader: DocumentLoader,
) =>
  predicates.map(async (predicate) => {
    const expandedPredicate = await jsonld.expand(predicate, {
      documentLoader,
      safe: true,
    });
    const skolemizedAndExpandedPredicate = skolemizeVC(expandedPredicate);
    const skolemizedAndExpandedPredicateRDF = await jsonldToRDF(
      skolemizedAndExpandedPredicate,
      documentLoader,
    );

    return deskolemizeTerm(skolemizedAndExpandedPredicateRDF);
  });

const diffJSONLD = (
  node: JsonValue,
  path: (string | number)[],
  deanonMap: Map<string, string>,
  skolemIDMap: Map<(string | number)[], string>,
  maskedLiteralPaths: (string | number)[][],
) => {
  if (Array.isArray(node)) {
    node.forEach((item, i) => {
      const updatedPath = path.concat([i]);

      if (!Array.isArray(item)) {
        throw new TypeError('json-diff error');
      }
      if (item[0] === '~') {
        diffJSONLD(
          item[1],
          updatedPath,
          deanonMap,
          skolemIDMap,
          maskedLiteralPaths,
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
          // eslint-disable-next-line @typescript-eslint/dot-notation
          const orig = oldAndNew['__old'] as string;
          // eslint-disable-next-line @typescript-eslint/dot-notation
          const masked = oldAndNew['__new'] as string;
          if (!masked.startsWith(SKOLEM_PREFIX)) {
            throw new TypeError(
              `json-diff error: replacement value \`${masked}\` must start with \`_:\``,
            );
          }
          deanonMap.set(deskolemizeString(masked), `<${orig}>`);
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
          // eslint-disable-next-line @typescript-eslint/dot-notation
          const orig = oldAndNew['__old'] as string;
          // eslint-disable-next-line @typescript-eslint/dot-notation
          const masked = oldAndNew['__new'] as string;
          if (!masked.startsWith(SKOLEM_PREFIX)) {
            throw new TypeError(
              `json-diff error: replacement value \`${masked}\` must start with \`_:\``,
            );
          }
          maskedLiteralPaths.push(path);
          deanonMap.set(deskolemizeString(masked), `"${orig}"`);
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
      } else if (!key.endsWith('__deleted')) {
        const updatedPath = path.concat([key]);
        const value = node[key];
        if (typeof value === 'object') {
          diffJSONLD(
            value,
            updatedPath,
            deanonMap,
            skolemIDMap,
            maskedLiteralPaths,
          );
        }
      }
    }
  }

  return {};
};

const diffVC = (
  vc: jsonld.JsonLdDocument,
  disclosed: jsonld.JsonLdDocument,
) => {
  const diffObj = diff(vc, disclosed) as JsonValue;
  const deanonMap = new Map<string, string>();
  const skolemIDMap = new Map<(string | number)[], string>();
  const maskedLiteralPaths: (string | number)[][] = [];

  diffJSONLD(diffObj, [], deanonMap, skolemIDMap, maskedLiteralPaths);

  return { deanonMap, skolemIDMap, maskedLiteralPaths };
};

const traverseJSON = (root: JsonValue, path: (string | number)[]) => {
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

const expandedVCToRDF = async (
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

export const getRDFAndDeanonMaps = async (
  vcPairs: VcPair[],
  documentLoader: DocumentLoader,
) => {
  const skolemizedAndExpandedVcPairs = await Promise.all(
    vcPairs.map((vcPair) => skolemizeAndExpandVcPair(vcPair, documentLoader)),
  );

  // compare VC and disclosed VC to get local deanon map and skolem ID map
  const diffObjs = skolemizedAndExpandedVcPairs.map(({ original, disclosed }) =>
    diffVC(original, disclosed),
  );

  // aggregate deanon maps
  const deanonMap = new Map<string, string>();
  diffObjs.forEach(({ deanonMap: localDeanonMap }) => {
    localDeanonMap.forEach((value, key) => {
      if (deanonMap.has(key) && deanonMap.get(key) !== value) {
        throw new Error(
          `pseudonym \`${key}\` corresponds to multiple values: \`${JSON.stringify(
            value,
          )}\` and \`${JSON.stringify(deanonMap.get(key))}\``,
        );
      }
      deanonMap.set(key, value);
    });
  });

  // update disclosed VCs
  skolemizedAndExpandedVcPairs.forEach(({ disclosed }, i) => {
    // copy Skolem IDs from original VC into disclosed VC
    diffObjs[i].skolemIDMap.forEach((skolemID, path) => {
      const node = traverseJSON(disclosed as JsonValue, path);
      node['@id'] = skolemID;
    });

    // inject masked Literal into disclosed VC
    diffObjs[i].maskedLiteralPaths.forEach((path) => {
      const node = traverseJSON(disclosed as JsonValue, path);

      const value = node['@value'];
      if (typeof value !== 'string') {
        throw new TypeError('invalid disclosed VC'); // TODO: more detail message
      }

      const typ = node['@type'];

      // replace value node with id node
      node['@id'] = value;
      delete node['@type'];
      delete node['@value'];

      const deskolemizedValue = deskolemizeString(value);
      const deanonMapEntry = deanonMap.get(deskolemizedValue);
      if (deanonMapEntry === undefined) {
        throw new Error(`deanonMap[${value}] has no value`);
      }

      if (typeof typ === 'string') {
        deanonMap.set(deskolemizedValue, `${deanonMapEntry}^^<${typ}>`);
      } else if (typ === undefined) {
        deanonMap.set(deskolemizedValue, `${deanonMapEntry}`);
      } else {
        throw new TypeError('invalid disclosed VC'); // TODO: more detail message
      }
    });
  });

  const vcPairsRDF = await Promise.all(
    skolemizedAndExpandedVcPairs.map(async ({ original, disclosed }) => {
      // convert VC to N-Quads
      const {
        documentRDF: skolemizedDocumentRDF,
        proofRDF: skolemizedProofRDF,
      } = await expandedVCToRDF(original, documentLoader);

      // convert disclosed VC to N-Quads
      const {
        documentRDF: skolemizedDisclosedDocumentRDF,
        proofRDF: skolemizedDisclosedProofRDF,
      } = await expandedVCToRDF(disclosed, documentLoader);

      // deskolemize N-Quads
      const [
        originalDocument,
        originalProof,
        disclosedDocument,
        disclosedProof,
      ] = [
        skolemizedDocumentRDF,
        skolemizedProofRDF,
        skolemizedDisclosedDocumentRDF,
        skolemizedDisclosedProofRDF,
      ].map(deskolemizeTerm);

      return {
        originalDocument,
        originalProof,
        disclosedDocument,
        disclosedProof,
      };
    }),
  );

  return { vcPairsRDF, deanonMap };
};

export const vcToRDF = async (vc: VC, documentLoader: DocumentLoader) => {
  const clonedVC = JSON.parse(JSON.stringify(vc)) as VC;

  const { proof } = clonedVC;
  const document = clonedVC as VCDocument;
  delete document.proof;

  if (!('@context' in proof)) {
    proof['@context'] = DATA_INTEGRITY_CONTEXT;
  }

  const documentRDF = await jsonldToRDF(document, documentLoader);
  const proofRDF = await jsonldToRDF(proof, documentLoader);

  return { document, documentRDF, proof, proofRDF };
};

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
    predicate: [
      {
        type: 'Predicate',
      },
    ],
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
    omitDefault: true,
    safe: true,
  });

  return out;
};
