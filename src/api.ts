/**
 * This file contains the API functions for working with JSON-LD proofs.
 * These functions provide functionality for key generation, signing and verification of Verifiable Credentials (VCs),
 * blind signing, unblinding, deriving proofs, and verifying proofs.
 * The functions utilize the @zkp-ld/rdf-proofs-wasm library for low-level cryptographic operations.
 * @packageDocumentation
 */

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
  VCPair,
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

/**
 * Generates a key pair for signing and verification.
 * @returns A Promise that resolves to the generated key pair.
 */
export const keyGen = async (): Promise<KeyPair> => {
  await initializeWasm();

  const keypair = keyGenWasm();

  return keypair;
};

/**
 * Signs a Verifiable Credential (VC) using a given key pair and document loader.
 * @param vc The Verifiable Credential to sign.
 * @param keyPair The key pair used for signing.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @returns A Promise that resolves to the signed Verifiable Credential.
 */
export const sign = async (
  vc: VC,
  keyPair: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const { document, documentRDF, proofRDF } = await vcToRDF(vc, documentLoader);

  const keyPairRDF = await jsonldToRDF(keyPair, documentLoader);

  const signedProofRDF = signWasm(documentRDF, proofRDF, keyPairRDF);
  const proof = await jsonldProofFromRDF(signedProofRDF, documentLoader);

  document.proof = proof;

  return document as VC;
};

/**
 * Verifies the signature of a Verifiable Credential (VC) using a given public key and document loader.
 * @param vc The Verifiable Credential to verify.
 * @param publicKey The public key used for verification.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @returns A Promise that resolves to the verification result.
 */
export const verify = async (
  vc: VC,
  publicKey: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VerifyResult> => {
  await initializeWasm();

  const { documentRDF, proofRDF } = await vcToRDF(vc, documentLoader);

  const publicKeyRDF = await jsonldToRDF(publicKey, documentLoader);

  const verified = verifyWasm(documentRDF, proofRDF, publicKeyRDF);

  return verified;
};

/**
 * Requests a blind signature for a given secret.
 * @param secret The secret to be blind signed.
 * @param challenge (Optional) The challenge string for the blind signature.
 * @param skipPok (Optional) Whether to skip the proof of knowledge (PoK) step.
 * @returns A Promise that resolves to the blind sign request.
 */
export const requestBlindSign = async (
  secret: Uint8Array,
  challenge?: string,
  skipPok?: boolean,
): Promise<BlindSignRequest> => {
  await initializeWasm();

  const request = requestBlindSignWasm(secret, challenge, skipPok);

  return request;
};

/**
 * Verifies a blind sign request.
 * @param commitment The commitment string from the blind sign request.
 * @param pokForCommitment The proof of knowledge (PoK) for the commitment.
 * @param challenge The challenge string used in the blind sign request.
 * @returns A Promise that resolves to the verification result.
 */
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

/**
 * Performs blind signing of a Verifiable Credential (VC) using a given commitment, key pair, and document loader.
 * @param commitment The commitment string from the blind sign request.
 * @param vc The Verifiable Credential to blind sign.
 * @param keyPair The key pair used for blind signing.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @returns A Promise that resolves to the blind signed Verifiable Credential.
 */
export const blindSign = async (
  commitment: string,
  vc: VC,
  keyPair: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const { document, documentRDF, proofRDF } = await vcToRDF(vc, documentLoader);

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

/**
 * Performs unblinding of a Verifiable Credential (VC) using a given blinding factor and document loader.
 * @param vc The Verifiable Credential to unblind.
 * @param blinding The blinding factor used for unblinding.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @returns A Promise that resolves to the unblinded Verifiable Credential.
 */
export const unblind = async (
  vc: VC,
  blinding: string,
  documentLoader: DocumentLoader,
): Promise<VC> => {
  await initializeWasm();

  const { document, documentRDF, proofRDF } = await vcToRDF(vc, documentLoader);

  const unblindedProofRDF = unblindWasm(documentRDF, proofRDF, blinding);
  const proof = await jsonldProofFromRDF(unblindedProofRDF, documentLoader);

  document.proof = proof;

  return document as VC;
};

/**
 * Verifies a blind signature of a Verifiable Credential (VC) using a given secret, public key, and document loader.
 * @param secret The secret used for blind verification.
 * @param vc The Verifiable Credential to blind verify.
 * @param publicKey The public key used for blind verification.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @returns A Promise that resolves to the verification result.
 */
export const blindVerify = async (
  secret: Uint8Array,
  vc: VC,
  publicKey: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
): Promise<VerifyResult> => {
  await initializeWasm();

  const { documentRDF, proofRDF } = await vcToRDF(vc, documentLoader);

  const publicKeyRDF = await jsonldToRDF(publicKey, documentLoader);

  const verified = blindVerifyWasm(secret, documentRDF, proofRDF, publicKeyRDF);

  return verified;
};

/**
 * Derives a Verifiable Presentation (VP) from a set of Verifiable Credential (VC) pairs using a given set of public keys, context, and document loader.
 * @param vcPairs The array of Verifiable Credential (VC) pairs, where each pair is an array of two VCs: the original VC and the partially-anonymized VC.
 * @param publicKeys The public keys used for deriving the proof.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @param options (Optional) Additional options for deriving the proof.
 * @returns A Promise that resolves to the derived proof as a JSON-LD document.
 */
export const deriveProof = async (
  vcPairs: VCPair[],
  publicKeys: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
  options?: DeriveProofOptions,
): Promise<jsonld.JsonLdDocument> => {
  await initializeWasm();

  const { vcPairRDFs, deanonMap } = await getRDFAndDeanonMaps(
    vcPairs,
    documentLoader,
  );

  const publicKeysRDF =
    Object.keys(publicKeys).length === 0 // if publicKeys is empty
      ? ''
      : await jsonldToRDF(publicKeys, documentLoader);

  const predicatesRDF = options?.predicates
    ? await Promise.all(getPredicatesRDF(options.predicates, documentLoader))
    : undefined;

  const vp = deriveProofWasm({
    vcPairs: vcPairRDFs,
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

  const jsonldVP = await jsonldVPFromRDF(vp, documentLoader, options?.context);

  return jsonldVP;
};

/**
 * Verifies a Verifiable Presentation (VP) using a given set of public keys, document loader, and additional options.
 * @param vp The Verifiable Presentation (VP) to verify.
 * @param publicKeys The public keys used for verification.
 * @param documentLoader The document loader used for resolving JSON-LD documents.
 * @param options (Optional) Additional options for verifying the proof.
 * @returns A Promise that resolves to the verification result.
 */
export const verifyProof = async (
  vp: jsonld.JsonLdDocument,
  publicKeys: jsonld.JsonLdDocument,
  documentLoader: DocumentLoader,
  options?: VerifyProofOptions,
): Promise<VerifyResult> => {
  await initializeWasm();

  const vpRDF = await jsonldToRDF(vp, documentLoader);

  const publicKeysRDF =
    Object.keys(publicKeys).length === 0 // if publicKeys is empty
      ? ''
      : await jsonldToRDF(publicKeys, documentLoader);

  const verified = verifyProofWasm({
    vp: vpRDF,
    keyGraph: publicKeysRDF,
    ...options,
  });

  return verified;
};
