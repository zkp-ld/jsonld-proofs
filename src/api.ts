import {
  keyGen as keyGenWasm,
  sign as signWasm,
  verify as verifyWasm,
  deriveProof as deriveProofWasm,
  verifyProof as verifyProofWasm,
  initializeWasm,
  VerifyResult,
  KeyPair,
} from '@zkp-ld/rdf-proofs-wasm';
import * as jsonld from 'jsonld';
import { DocumentLoader, JsonValue, VC, VcPair } from './types';
import {
  deskolemizeNQuads,
  jsonldToRDF,
  diffVC,
  skolemizeVC,
  jsonldVPFromRDF,
  expandedVCToRDF,
  vcToRDF,
  traverseJSON,
} from './utils';

export const keyGen = async (): Promise<KeyPair> => {
  await initializeWasm();

  const keypair = keyGenWasm();

  return keypair;
};

export const sign = async (
  vc: VC,
  keyPair: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc, documentLoader);
  const { document, proof, documentRDF, proofRDF } = vcRDF;

  const keyPairRDF = await jsonldToRDF(keyPair, documentLoader);

  const signature = signWasm(documentRDF, proofRDF, keyPairRDF);

  proof.proofValue = signature;
  document.proof = proof;

  return document as VC;
};

export const verify = async (
  vc: VC,
  publicKey: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc, documentLoader);
  const { documentRDF, proofRDF } = vcRDF;

  const publicKeyRDF = await jsonldToRDF(publicKey, documentLoader);

  const verified = verifyWasm(documentRDF, proofRDF, publicKeyRDF);

  return verified;
};

export const deriveProof = async (
  vcPairs: VcPair[],
  nonce: string,
  publicKeys: jsonld.JsonLdDocument,
  context: jsonld.ContextDefinition,
  documentLoader: DocumentLoader,
): Promise<jsonld.JsonLdDocument> => {
  await initializeWasm();

  const vcPairsRDF = [];
  const deanonMap = new Map<string, string>();
  const publicKeysRDF = await jsonldToRDF(publicKeys, documentLoader);

  for (const { original, disclosed } of vcPairs) {
    const skolemizedVC = skolemizeVC(original);

    const expandedVC = await jsonld.expand(skolemizedVC, {
      documentLoader,
      safe: true,
    });
    const expandedDisclosedVC = await jsonld.expand(disclosed, {
      documentLoader,
      safe: true,
    });

    // compare VC and disclosed VC to get local deanon map and skolem ID map
    const vcDiffResult = diffVC(expandedVC, expandedDisclosedVC);
    const {
      deanonMap: localDeanonMap,
      skolemIDMap,
      maskedIDMap,
      maskedLiteralMap,
    } = vcDiffResult;

    // update global deanonMap
    for (const [k, v] of localDeanonMap.entries()) {
      if (deanonMap.has(k) && deanonMap.get(k) !== v) {
        throw new Error(
          `pseudonym \`${k}\` corresponds to multiple values: \`${JSON.stringify(
            v,
          )}\` and \`${JSON.stringify(deanonMap.get(k))}\``,
        );
      }
      deanonMap.set(k, v);
    }

    // inject Skolem IDs into disclosed VC
    for (const [path, skolemID] of skolemIDMap) {
      const node = traverseJSON(expandedDisclosedVC as JsonValue, path);
      node['@id'] = skolemID;
    }

    // inject masked ID into disclosed VC
    for (const [path, masked] of maskedIDMap) {
      const node = traverseJSON(expandedDisclosedVC as JsonValue, path);
      node['@id'] = masked;
    }

    // inject masked Literal into disclosed VC
    for (const [path, masked] of maskedLiteralMap) {
      const node = traverseJSON(expandedDisclosedVC as JsonValue, path);

      let value = node['@value'];
      if (typeof value !== 'string') {
        throw new TypeError('invalid disclosed VC'); // TODO: more detail message
      }
      // add prefix `_:` if not exist
      if (!value.startsWith('_:')) {
        value = `_:${value}`;
      }

      const typ = node['@type'];

      node['@id'] = masked;
      delete node['@type'];
      delete node['@value'];

      const deanonMapEntry = deanonMap.get(value);
      if (deanonMapEntry == undefined) {
        throw new Error(`deanonMap[${value}] has no value`);
      }

      if (typeof typ == 'string') {
        deanonMap.set(value, `${deanonMapEntry}^^<${typ}>`);
      } else if (typ === undefined) {
        deanonMap.set(value, `${deanonMapEntry}`);
      } else {
        throw new TypeError('invalid disclosed VC'); // TODO: more detail message
      }
    }

    // convert VC to N-Quads
    const { documentRDF: skolemizedDocumentRDF, proofRDF: skolemizedProofRDF } =
      await expandedVCToRDF(expandedVC, documentLoader);

    // convert disclosed VC to N-Quads
    const {
      documentRDF: skolemizedDisclosedDocumentRDF,
      proofRDF: skolemizedDisclosedProofRDF,
    } = await expandedVCToRDF(expandedDisclosedVC, documentLoader);

    // deskolemize N-Quads
    const [
      originalDocumentRDF,
      originalProofRDF,
      disclosedDocumentRDF,
      disclosedProofRDF,
    ] = [
      skolemizedDocumentRDF,
      skolemizedProofRDF,
      skolemizedDisclosedDocumentRDF,
      skolemizedDisclosedProofRDF,
    ].map(deskolemizeNQuads);

    vcPairsRDF.push({
      originalDocument: originalDocumentRDF,
      originalProof: originalProofRDF,
      disclosedDocument: disclosedDocumentRDF,
      disclosedProof: disclosedProofRDF,
    });
  }

  const vp = deriveProofWasm({
    vcPairs: vcPairsRDF,
    deanonMap,
    nonce,
    keyGraph: publicKeysRDF,
  });

  const jsonldVP = jsonldVPFromRDF(vp, context, documentLoader);

  return jsonldVP;
};

export const verifyProof = async (
  vp: jsonld.JsonLdDocument,
  nonce: string,
  publicKeys: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vpRDF = await jsonldToRDF(vp, documentLoader);
  const publicKeysRDF = await jsonldToRDF(publicKeys, documentLoader);

  const verified = verifyProofWasm(vpRDF, nonce, publicKeysRDF);

  return verified;
};
