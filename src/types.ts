import * as jsonld from 'jsonld';

export type VCDocument = jsonld.NodeObject;
export type VCProof = jsonld.NodeObject;

export interface VC extends VCDocument {
  proof: VCProof;
}

export interface VcWithDisclosed {
  readonly vc: VC;
  readonly disclosed: VC;
}

export type JsonPrimitive = string | number | boolean | null;
export interface JsonArray extends Array<JsonValue> {}
export interface JsonObject {
  [key: string]: JsonValue;
}
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;
