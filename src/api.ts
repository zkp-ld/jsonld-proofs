import {
  sign as signWasm,
  verify as verifyWasm,
  deriveProof as deriveProofWasm,
  initializeWasm,
  VerifyResult,
} from '@zkp-ld/rdf-proofs-wasm';
import { JsonLdDocument } from 'jsonld';
import {
  deskolemizeNQuads,
  jsonldToRDF,
  replaceMaskWithSkolemID,
  vcToRDF,
  vcDiff,
} from './utils';

export interface VcWithDisclosed {
  readonly vc: JsonLdDocument;
  readonly disclosed: JsonLdDocument;
}

export const sign = async (
  vc: JsonLdDocument,
  documentLoader: JsonLdDocument,
): Promise<JsonLdDocument> => {
  await initializeWasm();

  const rdf = await vcToRDF(vc);
  if ('error' in rdf) {
    return { error: rdf.error };
  }
  const { document, documentRDF, proof, proofRDF } = rdf;

  const documentLoaderRDF = await jsonldToRDF(documentLoader);

  const signature = signWasm(documentRDF, proofRDF, documentLoaderRDF);

  proof.proofValue = signature;
  document.proof = proof;

  return document;
};

export const verify = async (
  vc: JsonLdDocument,
  documentLoader: JsonLdDocument,
): Promise<VerifyResult> => {
  await initializeWasm();

  const rdf = await vcToRDF(vc);
  if ('error' in rdf) {
    return { verified: false, error: rdf.error };
  }
  const { documentRDF, proofRDF } = rdf;

  const documentLoaderRDF = await jsonldToRDF(documentLoader);

  const verified = verifyWasm(documentRDF, proofRDF, documentLoaderRDF);

  return verified;
};

export const deriveProof = async (
  vcWithDisclosedPairs: VcWithDisclosed[],
  nonce: string,
  documentLoader: JsonLdDocument,
): Promise<JsonLdDocument> => {
  await initializeWasm();

  const vcWithDisclosed = [];
  const deanonMap = new Map<string, string>();
  const documentLoaderRDF = await jsonldToRDF(documentLoader);

  for (const { vc, disclosed } of vcWithDisclosedPairs) {
    const localDeanonMap = vcDiff(vc, disclosed);
    if ('error' in localDeanonMap) {
      return { error: localDeanonMap.error };
    }
    for (const [k, v] of localDeanonMap.entries()) {
      if (deanonMap.has(k) && deanonMap.get(k) !== v) {
        return {
          error: `pseudonym ${k} corresponds to multiple values: ${v} and ${deanonMap.get(
            k,
          )}`,
        };
      }
      deanonMap.set(k, v);
    }

    const skolemizedDisclosed = replaceMaskWithSkolemID(
      disclosed,
      localDeanonMap,
    );

    const rdf = await vcToRDF(vc);
    if ('error' in rdf) {
      return { error: rdf.error };
    }
    const { documentRDF, proofRDF } = rdf;

    const skolemizedDisclosedRDF = await vcToRDF(skolemizedDisclosed);
    if ('error' in skolemizedDisclosedRDF) {
      return { error: skolemizedDisclosedRDF.error };
    }
    const {
      documentRDF: skolemizedDisclosedDocumentRDF,
      proofRDF: skolemizedDisclosedProofRDF,
    } = skolemizedDisclosedRDF;

    const [disclosedDocumentRDF, disclosedProofRDF] = [
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

  console.log('vcWithDisclosed:');
  for (const {
    vcDocument,
    vcProof,
    disclosedDocument,
    disclosedProof,
  } of vcWithDisclosed) {
    console.log('vcDocument:');
    console.log(vcDocument);
    console.log('vcProof:');
    console.log(vcProof);
    console.log('disclosedDocument:');
    console.log(disclosedDocument);
    console.log('disclosedProof:');
    console.log(disclosedProof);
  }
  console.log(deanonMap);

  const vp = deriveProofWasm({
    vcWithDisclosed,
    deanonMap,
    nonce,
    documentLoader: documentLoaderRDF,
  });

  console.log(`vp: ${vp}`);

  // TODO: dummy
  return {};
};
