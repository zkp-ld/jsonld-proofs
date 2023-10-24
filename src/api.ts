/* eslint-disable no-restricted-syntax */ // TODO: remove this
import {
  keyGen as keyGenWasm,
  sign as signWasm,
  verify as verifyWasm,
  deriveProof as deriveProofWasm,
  verifyProof as verifyProofWasm,
  requestBlindSign as requestBlindSignWasm,
  verifyBlindSignRequest as verifyBlindSignRequestWasm,
  blindSign as blindSignWasm,
  unblind as unblindWasm,
  blindVerify as blindVerifyWasm,
  initializeWasm,
  VerifyResult,
  KeyPair,
  BlindSignRequest,
} from '@zkp-ld/rdf-proofs-wasm';
import * as jsonld from 'jsonld';
import {
  DeriveProofOptions,
  DocumentLoader,
  JsonValue,
  VC,
  VcPair,
  VerifyProofOptions,
} from './types';
import {
  deskolemizeTerm,
  jsonldToRDF,
  diffVC,
  jsonldVPFromRDF,
  expandedVCToRDF,
  vcToRDF,
  traverseJSON,
  skolemizeVC,
  jsonldProofFromRDF,
  deskolemizeString,
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
  const { document, documentRDF, proofRDF } = vcRDF;

  const keyPairRDF = await jsonldToRDF(keyPair, documentLoader);

  const signedProofRDF = signWasm(documentRDF, proofRDF, keyPairRDF);
  const proof = await jsonldProofFromRDF(signedProofRDF, documentLoader);

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

export const requestBlindSign = async (
  secret: Uint8Array,
  challenge?: string,
  skipPok?: boolean,
): Promise<BlindSignRequest> => {
  await initializeWasm();

  const request = requestBlindSignWasm(secret, challenge, skipPok);

  return request;
};

export const verifyBlindSignRequest = async (
  commitment: string,
  pokForCommitment: string,
  challenge: string,
): Promise<VerifyResult> => {
  await initializeWasm();

  const verified = verifyBlindSignRequestWasm(
    commitment,
    pokForCommitment,
    challenge,
  );

  return verified;
};

export const blindSign = async (
  commitment: string,
  vc: VC,
  keyPair: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc, documentLoader);
  const { document, documentRDF, proofRDF } = vcRDF;

  const keyPairRDF = await jsonldToRDF(keyPair, documentLoader);

  const signedProofRDF = blindSignWasm(
    commitment,
    documentRDF,
    proofRDF,
    keyPairRDF,
  );
  const proof = await jsonldProofFromRDF(signedProofRDF, documentLoader);

  document.proof = proof;

  return document as VC;
};

export const unblind = async (
  vc: VC,
  blinding: string,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc, documentLoader);
  const { document, documentRDF, proofRDF } = vcRDF;

  const unblindedProofRDF = unblindWasm(documentRDF, proofRDF, blinding);
  const proof = await jsonldProofFromRDF(unblindedProofRDF, documentLoader);

  document.proof = proof;

  return document as VC;
};

export const blindVerify = async (
  secret: Uint8Array,
  vc: VC,
  publicKey: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vcRDF = await vcToRDF(vc, documentLoader);
  const { documentRDF, proofRDF } = vcRDF;

  const publicKeyRDF = await jsonldToRDF(publicKey, documentLoader);

  const verified = blindVerifyWasm(secret, documentRDF, proofRDF, publicKeyRDF);

  return verified;
};

export const deriveProof = async (
  vcPairs: VcPair[],
  publicKeys: jsonld.JsonLdDocument,
  context: jsonld.ContextDefinition,
  documentLoader: DocumentLoader,
  options?: DeriveProofOptions,
): Promise<jsonld.JsonLdDocument> => {
  await initializeWasm();

  const vcPairsRDF = [];
  const deanonMap = new Map<string, string>();
  const publicKeysRDF = await jsonldToRDF(publicKeys, documentLoader);

  const skolemizedPredicatesRDF = options?.predicates
    ? await Promise.all(
        options.predicates.map(async (predicate) => {
          const expandedPredicate = await jsonld.expand(predicate, {
            documentLoader,
            safe: true,
          });

          return jsonldToRDF(
            skolemizeVC(expandedPredicate, true),
            documentLoader,
          );
        }),
      )
    : undefined;
  const predicatesRDF = skolemizedPredicatesRDF
    ? skolemizedPredicatesRDF.map((predicate) => deskolemizeTerm(predicate))
    : undefined;

  for (const { original, disclosed } of vcPairs) {
    const expandedOriginalVC = await jsonld.expand(original, {
      documentLoader,
      safe: true,
    });
    const expandedDisclosedVC = await jsonld.expand(disclosed, {
      documentLoader,
      safe: true,
    });

    const skolemizedExpandedOriginalVC = skolemizeVC(expandedOriginalVC, true);
    const skolemizedExpandedDisclosedVC = skolemizeVC(
      expandedDisclosedVC,
      false,
    );

    // compare VC and disclosed VC to get local deanon map and skolem ID map
    const {
      deanonMap: localDeanonMap,
      skolemIDMap,
      maskedLiteralMap,
    } = diffVC(skolemizedExpandedOriginalVC, skolemizedExpandedDisclosedVC);

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
      const node = traverseJSON(
        skolemizedExpandedDisclosedVC as JsonValue,
        path,
      );
      node['@id'] = skolemID;
    }

    // inject masked Literal into disclosed VC
    for (const path of maskedLiteralMap) {
      const node = traverseJSON(
        skolemizedExpandedDisclosedVC as JsonValue,
        path,
      );

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
    }

    // convert VC to N-Quads
    const { documentRDF: skolemizedDocumentRDF, proofRDF: skolemizedProofRDF } =
      await expandedVCToRDF(skolemizedExpandedOriginalVC, documentLoader);

    // convert disclosed VC to N-Quads
    const {
      documentRDF: skolemizedDisclosedDocumentRDF,
      proofRDF: skolemizedDisclosedProofRDF,
    } = await expandedVCToRDF(skolemizedExpandedDisclosedVC, documentLoader);

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
    ].map(deskolemizeTerm);

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
    keyGraph: publicKeysRDF,
    challenge: options?.challenge,
    domain: options?.domain,
    secret: options?.secret,
    blindSignRequest: options?.blindSignRequest,
    withPpid: options?.withPpid,
    predicates: predicatesRDF,
    circuits: options?.circuits,
  });

  const jsonldVP = await jsonldVPFromRDF(vp, context, documentLoader);

  return jsonldVP;
};

export const verifyProof = async (
  vp: jsonld.JsonLdDocument,
  publicKeys: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
  options?: VerifyProofOptions,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vpRDF = await jsonldToRDF(vp, documentLoader);
  const publicKeysRDF = await jsonldToRDF(publicKeys, documentLoader);

  const verified = verifyProofWasm({
    vp: vpRDF,
    keyGraph: publicKeysRDF,
    ...options,
  });

  return verified;
};
