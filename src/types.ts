import { BlindSignRequest, CircuitString } from '@zkp-ld/rdf-proofs-wasm';
import * as jsonld from 'jsonld';
import { JsonLdArray, RemoteDocument, Url } from 'jsonld/jsonld-spec';

export type VCDocument = jsonld.NodeObject;
export type VCProof = jsonld.NodeObject;

export interface VC extends VCDocument {
  proof: VCProof;
}

export interface VCPair {
  readonly original: VC;
  readonly disclosed: VC;
}

export interface ExpandedJsonldPair {
  readonly original: JsonLdArray;
  readonly disclosed: JsonLdArray;
}

export interface DiffVCResult {
  readonly deanonMap: Map<string, string>;
  readonly skolemIDMap: Map<(string | number)[], string>;
  readonly maskedLiteralPaths: (string | number)[][];
}

export interface VCPairRDF {
  readonly originalDocument: string;
  readonly originalProof: string;
  readonly disclosedDocument: string;
  readonly disclosedProof: string;
}

export interface VCPairsWithDeanonMap {
  readonly vcPairRDFs: VCPairRDF[];
  readonly deanonMap: Map<string, string>;
}

export interface VCRDF {
  readonly document: jsonld.NodeObject;
  readonly documentRDF: string;
  readonly proof: jsonld.NodeObject;
  readonly proofRDF: string;
}

export type JsonPrimitive = string | number | boolean | null;
export interface JsonArray extends Array<JsonValue> {}
export interface JsonObject {
  [key: string]: JsonValue;
}
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

export type DocumentLoader = (url: Url) => Promise<RemoteDocument>;

export interface DeriveProofOptions {
  readonly challenge?: string;
  readonly domain?: string;
  readonly secret?: Uint8Array;
  readonly blindSignRequest?: BlindSignRequest;
  readonly withPpid?: boolean;
  readonly predicates?: jsonld.JsonLdDocument[];
  readonly circuits?: Map<string, CircuitString>;
}

export interface VerifyProofOptions {
  readonly challenge?: string;
  readonly domain?: string;
  readonly snarkVerifyingKeys?: Map<string, string>;
}
