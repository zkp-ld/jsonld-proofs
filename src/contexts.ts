import credentialV1Context from './contexts/credentials_v1.json';
import dataIntegrityContext from './contexts/data-integrity-v1.json';
import bbsTermwiseContext from './contexts/bbs-termwise-2021.json';
import schemaOrgContext from './contexts/schemaorg.json';
import multikeyV1Context from './contexts/multikey-v1.json';
import didV1Context from './contexts/did-v1.json';

export const CONTEXTS: Record<string, any> = {
  'https://www.w3.org/2018/credentials/v1': credentialV1Context,
  'https://w3id.org/security/data-integrity/v1': dataIntegrityContext,
  'https://zkp-ld.org/bbs-termwise-2021.jsonld': bbsTermwiseContext,
  'https://schema.org': schemaOrgContext,
  'https://w3id.org/security/multikey/v1': multikeyV1Context,
  'https://www.w3.org/ns/did/v1': didV1Context,
};
