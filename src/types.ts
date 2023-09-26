import * as jsonld from 'jsonld';
import { RemoteDocument, Url } from 'jsonld/jsonld-spec';

export type VCDocument = jsonld.NodeObject;
export type VCProof = jsonld.NodeObject;

export interface VC extends VCDocument {
  proof: VCProof;
}

export interface VcPair {
  readonly original: VC;
  readonly disclosed: VC;
}

export type JsonPrimitive = string | number | boolean | null;
export interface JsonArray extends Array<JsonValue> {}
export interface JsonObject {
  [key: string]: JsonValue;
}
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

export type DocumentLoader =
  | ((
      url: Url,
      callback: (err: Error, remoteDoc: RemoteDocument) => void,
    ) => Promise<RemoteDocument>)
  | undefined;
