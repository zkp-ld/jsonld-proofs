import { diff } from 'json-diff';
import * as jsonld from 'jsonld';
import * as jsonldSpec from 'jsonld/jsonld-spec';
import { customAlphabet } from 'nanoid';
import {
  DiffVCResult,
  DocumentLoader,
  ExpandedJsonldPair,
  JsonLdContextHeader,
  JsonObject,
  JsonValue,
  VC,
  VCDocument,
  VCPair,
  VCPairsWithDeanonMap,
  VCRDF,
} from './types';

const PROOF = 'https://w3id.org/security#proof';
const VC_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
const DATA_INTEGRITY_CONTEXT = 'https://www.w3.org/ns/data-integrity/v1';
const ZKPLD_CONTEXT = 'https://zkp-ld.org/context.jsonld';
const SKOLEM_PREFIX = 'urn:bnid:';
const SKOLEM_REGEX = /[<"]urn:bnid:([^>"]+)[>"]/g;
const nanoid = customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 10);

const deskolemizeString = (s: string): string => s.replace(SKOLEM_PREFIX, '_:');
const deskolemizeTerm = (t: string): string => t.replace(SKOLEM_REGEX, '_:$1');

/**
 * Converts a JSON-LD document to RDF format.
 * @param jsonldDoc The JSON-LD document to convert.
 * @param documentLoader The document loader used to resolve external references.
 * @returns A Promise that resolves to the RDF representation of the JSON-LD document.
 */
export const jsonldToRDF = async (
  jsonldDoc: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<string> =>
  (await jsonld.toRDF(jsonldDoc, {
    format: 'application/n-quads',
    documentLoader,
    safe: true,
  })) as string;

const skolemizeJSONLD = (
  json: JsonValue,
  includeOmittedId: boolean,
): JsonValue => {
  let newJson = JSON.parse(JSON.stringify(json)) as JsonValue; // create a copy of the input JSON

  if (Array.isArray(newJson)) {
    newJson = newJson.map((item: JsonValue) =>
      typeof item === 'object' && item != null
        ? skolemizeJSONLD(item, includeOmittedId)
        : item,
    );
  } else if (typeof newJson === 'object' && newJson != null) {
    const obj: JsonObject = newJson;
    Object.keys(obj).forEach((key) => {
      if (
        key !== '@context' &&
        typeof obj[key] === 'object' &&
        obj[key] != null
      ) {
        obj[key] = skolemizeJSONLD(obj[key], includeOmittedId);
      } else {
        const value: JsonValue = obj[key];
        if (typeof value === 'string' && value.startsWith('_:')) {
          obj[key] = `${SKOLEM_PREFIX}${value.slice(2)}`;
        }
      }
    });
    if (
      includeOmittedId &&
      !('@value' in newJson || '@id' in newJson || '@list' in newJson)
    ) {
      newJson['@id'] = `${SKOLEM_PREFIX}${nanoid()}`;
    }
  }

  return newJson; // Return the modified copy of the input JSON
};

const skolemizeExpandedVC = (
  expandedVC: jsonldSpec.JsonLdArray | jsonld.JsonLdDocument,
  includeOmittedId?: boolean,
) => {
  const output = JSON.parse(JSON.stringify(expandedVC)) as JsonValue;
  const skolemizedOutput = skolemizeJSONLD(
    output,
    includeOmittedId === undefined ? true : includeOmittedId,
  );

  return skolemizedOutput as jsonldSpec.JsonLdArray;
};

const skolemizeAndExpandVcPair = async (
  vcPair: VCPair,
  documentLoader: DocumentLoader,
): Promise<ExpandedJsonldPair> => {
  const expandedOriginalVC = await jsonld.expand(vcPair.original, {
    documentLoader,
    safe: true,
  });
  const skolemizedAndExpandedOriginalVC =
    skolemizeExpandedVC(expandedOriginalVC);

  const expandedDisclosedVC = await jsonld.expand(vcPair.disclosed, {
    documentLoader,
    safe: true,
  });
  const skolemizedAndExpandedDisclosedVC = skolemizeExpandedVC(
    expandedDisclosedVC,
    false,
  );

  return {
    original: skolemizedAndExpandedOriginalVC,
    disclosed: skolemizedAndExpandedDisclosedVC,
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
    const skolemizedAndExpandedPredicate =
      skolemizeExpandedVC(expandedPredicate);
    const skolemizedAndExpandedPredicateRDF = await jsonldToRDF(
      skolemizedAndExpandedPredicate,
      documentLoader,
    );

    return deskolemizeTerm(skolemizedAndExpandedPredicateRDF);
  });

const diffJSONLD = (
  json: JsonValue,
  path: (string | number)[],
  deanonMap: Map<string, string>,
  skolemIDMap: Map<(string | number)[], string>,
  maskedLiteralPaths: (string | number)[][],
) => {
  if (Array.isArray(json)) {
    json.forEach((item, i) => {
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
  } else if (typeof json === 'object' && json != null) {
    Object.keys(json).forEach((key) => {
      if (key === '@id') {
        const oldAndNew = json[key];
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
        const oldAndNew = json[key];
        if (
          typeof oldAndNew === 'object' &&
          oldAndNew != null &&
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
        const value = json[key] as string;
        if (value.startsWith(SKOLEM_PREFIX)) {
          skolemIDMap.set(path, value);
        } else {
          const masked = nanoid();
          skolemIDMap.set(path, `${SKOLEM_PREFIX}${masked}`);
          deanonMap.set(`_:${masked}`, `<${value}>`);
        }
      } else if (!key.endsWith('__deleted')) {
        const updatedPath = path.concat([key]);
        const value = json[key];
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
    });
  }

  return {};
};

const diffVC = (
  vc: jsonld.JsonLdDocument,
  disclosed: jsonld.JsonLdDocument,
): DiffVCResult => {
  const diffObj = diff(vc, disclosed) as JsonValue;
  const deanonMap = new Map<string, string>();
  const skolemIDMap = new Map<(string | number)[], string>();
  const maskedLiteralPaths: (string | number)[][] = [];

  diffJSONLD(diffObj, [], deanonMap, skolemIDMap, maskedLiteralPaths);

  return { deanonMap, skolemIDMap, maskedLiteralPaths };
};

const traverseJSON = (root: JsonValue, path: (string | number)[]) => {
  let node = root;

  path.forEach((pathItem) => {
    if (Array.isArray(node) && typeof pathItem === 'number') {
      node = node[pathItem];
    } else if (
      !Array.isArray(node) &&
      typeof node === 'object' &&
      node != null &&
      typeof pathItem === 'string'
    ) {
      node = node[pathItem];
    } else {
      throw new Error('internal error when processing disclosed VC');
    }
  });

  if (typeof node !== 'object' || node === null || Array.isArray(node)) {
    throw new Error('internal error when processing disclosed VC');
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

const aggregateLocalDeanonMaps = (diffObjs: DiffVCResult[]) => {
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

  return deanonMap;
};

/**
 * Retrieves RDF representations of VC pairs and generates a deanon map.
 * @param vcPairs - An array of VC pairs.
 * @param documentLoader - The document loader used for resolving JSON-LD documents.
 * @returns A promise that resolves to an object containing the RDF representations of VC pairs and the deanon map.
 */
export const getRDFAndDeanonMaps = async (
  vcPairs: VCPair[],
  documentLoader: DocumentLoader,
): Promise<VCPairsWithDeanonMap> => {
  // skolemize and expand VCs
  const skolemizedAndExpandedVcPairs = await Promise.all(
    vcPairs.map((vcPair) => skolemizeAndExpandVcPair(vcPair, documentLoader)),
  );

  // compare VC and disclosed VC to get local deanon map and skolem ID map
  const diffObjs = skolemizedAndExpandedVcPairs.map(({ original, disclosed }) =>
    diffVC(original, disclosed),
  );

  // aggregate local deanon maps
  const deanonMap = aggregateLocalDeanonMaps(diffObjs);

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

  const vcPairRDFs = await Promise.all(
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

  return { vcPairRDFs, deanonMap };
};

/**
 * Converts a Verifiable Credential (VC) object to RDF format.
 * @param vc The Verifiable Credential object to convert.
 * @param documentLoader The document loader used to resolve external JSON-LD documents.
 * @returns A Promise that resolves to an object containing the original VC, its RDF representation, the proof object, and its RDF representation.
 */
export const vcToRDF = async (
  vc: VC,
  documentLoader: DocumentLoader,
): Promise<VCRDF> => {
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

/**
 * Converts a proof in RDF format to a JSON-LD proof object.
 * @param proofRDF The proof in RDF format.
 * @param documentLoader The document loader used for resolving external resources during JSON-LD processing.
 * @returns A Promise that resolves to the JSON-LD proof object.
 */
export const jsonldProofFromRDF = async (
  proofRDF: string,
  documentLoader: DocumentLoader,
): Promise<jsonld.NodeObject> => {
  const proofFrame: jsonld.JsonLdDocument = {
    '@context': DATA_INTEGRITY_CONTEXT,
    type: 'DataIntegrityProof',
  };

  const expandedJsonld = await jsonld.fromRDF(proofRDF, {
    format: 'application/n-quads',
    safe: true,
  });

  const out = await jsonld.frame(expandedJsonld, proofFrame, {
    documentLoader,
    safe: true,
  });

  return out;
};

/**
 * Converts RDF data representing a Verifiable Presentation (VP) into a JSON-LD Node Object.
 * @param vpRDF The RDF data representing the Verifiable Presentation.
 * @param documentLoader The document loader used for resolving external resources.
 * @param context The JSON-LD context definition to be used in the output JSON-LD VP object.
 * @returns A Promise that resolves to the JSON-LD Node Object representing the Verifiable Presentation.
 */
export const jsonldVPFromRDF = async (
  vpRDF: string,
  documentLoader: DocumentLoader,
  context?: JsonLdContextHeader,
): Promise<jsonld.NodeObject> => {
  const defaultContext: (string | jsonld.ContextDefinition)[] = [
    VC_CONTEXT,
    DATA_INTEGRITY_CONTEXT,
    ZKPLD_CONTEXT,
  ];
  if (Array.isArray(context)) {
    defaultContext.push(...context);
  } else if (context !== undefined) {
    defaultContext.push(context);
  }

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
  vpFrame['@context'] = defaultContext;

  const expandedJsonld = await jsonld.fromRDF(vpRDF, {
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
