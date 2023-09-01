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
import { JsonValue, VC, VcWithDisclosed } from './types';
import {
  deskolemizeNQuads,
  jsonldToRDF,
  diffVC,
  skolemizeVC,
  jsonldVPFromRDF,
  customLoader,
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
): Promise<VC> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc);
  const { document, proof, documentRDF, proofRDF } = vcRDF;

  const keyPairRDF = await jsonldToRDF(keyPair);

  const signature = signWasm(documentRDF, proofRDF, keyPairRDF);

  proof.proofValue = signature;
  document.proof = proof;

  return document as VC;
};

export const verify = async (
  vc: VC,
  publicKey: jsonld.JsonLdDocument,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc);
  const { documentRDF, proofRDF } = vcRDF;

  const publicKeyRDF = await jsonldToRDF(publicKey);

  const verified = verifyWasm(documentRDF, proofRDF, publicKeyRDF);

  return verified;
};

export const deriveProof = async (
  vcWithDisclosedPairs: VcWithDisclosed[],
  nonce: string,
  publicKeys: jsonld.JsonLdDocument,
  context: jsonld.ContextDefinition,
): Promise<jsonld.JsonLdDocument> => {
  await initializeWasm();

  const vcWithDisclosed = [];
  const deanonMap = new Map<string, string>();
  const publicKeysRDF = await jsonldToRDF(publicKeys);

  for (const { vc, disclosed } of vcWithDisclosedPairs) {
    const skolemizedVC = skolemizeVC(vc);

    const expandedVC = await jsonld.expand(skolemizedVC, {
      documentLoader: customLoader,
    });
    const expandedDisclosedVC = await jsonld.expand(disclosed, {
      documentLoader: customLoader,
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

      const typ = node['@type'];
      const value = node['@value'];
      if (typeof typ !== 'string' || typeof value !== 'string') {
        throw new TypeError('invalid disclosed VC');
      }

      node['@id'] = masked;
      delete node['@type'];
      delete node['@value'];

      const deanonMapEntry = deanonMap.get(`_:${value}`);
      if (deanonMapEntry == undefined) {
        throw new Error(`deanonMap[_:${value}] has no value`);
      }
      deanonMap.set(`_:${value}`, `${deanonMapEntry}^^<${typ}>`);
    }

    // convert VC to N-Quads
    const { documentRDF: skolemizedDocumentRDF, proofRDF: skolemizedProofRDF } =
      await expandedVCToRDF(expandedVC);

    // convert disclosed VC to N-Quads
    const {
      documentRDF: skolemizedDisclosedDocumentRDF,
      proofRDF: skolemizedDisclosedProofRDF,
    } = await expandedVCToRDF(expandedDisclosedVC);

    // deskolemize N-Quads
    const [documentRDF, proofRDF, disclosedDocumentRDF, disclosedProofRDF] = [
      skolemizedDocumentRDF,
      skolemizedProofRDF,
      skolemizedDisclosedDocumentRDF,
      skolemizedDisclosedProofRDF,
    ].map(deskolemizeNQuads);

    vcWithDisclosed.push({
      vcDocument: documentRDF,
      vcProof: proofRDF,
      disclosedDocument: disclosedDocumentRDF,
      disclosedProof: disclosedProofRDF,
    });
  }

  const vp = deriveProofWasm({
    vcWithDisclosed,
    deanonMap,
    nonce,
    documentLoader: publicKeysRDF,
  });

  const jsonldVP = jsonldVPFromRDF(vp, context);

  return jsonldVP;
};

export const verifyProof = async (
  vp: jsonld.JsonLdDocument,
  nonce: string,
  documentLoader: jsonld.JsonLdDocument,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vpRDF = await jsonldToRDF(vp);
  const documentLoaderRDF = await jsonldToRDF(documentLoader);

  const verified = verifyProofWasm(vpRDF, nonce, documentLoaderRDF);

  return verified;
};
