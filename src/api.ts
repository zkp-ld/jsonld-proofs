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
  VC,
  VcPair,
  VerifyProofOptions,
} from './types';
import {
  jsonldToRDF,
  jsonldVPFromRDF,
  vcToRDF,
  jsonldProofFromRDF,
  getRDFAndDeanonMaps,
  getPredicatesRDF,
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

  const { vcPairsRDF, deanonMap } = await getRDFAndDeanonMaps(
    vcPairs,
    documentLoader,
  );

  const publicKeysRDF = await jsonldToRDF(publicKeys, documentLoader);

  const predicatesRDF = options?.predicates
    ? await Promise.all(getPredicatesRDF(options.predicates, documentLoader))
    : undefined;

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
