import * as jsonld from 'jsonld';
import {
  blindSignRequest,
  blindSign,
  unblind,
  blindVerify,
  verify,
  sign,
  deriveProof,
  verifyProof,
} from '../src/api';
import { localDocumentLoader } from './documentLoader';
import disclosedBound0 from './example/disclosed0_bound.json';
import disclosed1 from './example/disclosed1.json';
import keypairs from './example/keypairs.json';
import vcDraft0WithoutCryptosuite from './example/vc0_without_cryptosuite.json';
import vcDraft1 from './example/vc1.json';
import _vpContext from './example/vpContext.json';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;

describe('Blind Signatures', () => {
  test('blind sign and verify', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const nonce = 'abcde';

    const { request, blinding } = await blindSignRequest(secret, nonce);
    expect(request).toBeDefined();

    const blindedVC = await blindSign(
      request,
      nonce,
      vcDraft0WithoutCryptosuite,
      keypairs,
      localDocumentLoader,
    );
    console.log(`blindedVC: ${JSON.stringify(blindedVC, null, 2)}`);
    expect(blindedVC).toBeDefined();

    const verifiedBlindedVCWithoutSecret = await verify(
      blindedVC,
      keypairs,
      localDocumentLoader,
    );
    expect(verifiedBlindedVCWithoutSecret.verified).toBeFalsy();

    const verifiedBlindedVC = await blindVerify(
      secret,
      blindedVC,
      keypairs,
      localDocumentLoader,
    );
    expect(verifiedBlindedVC.verified).toBeFalsy();

    const vc0 = await unblind(blindedVC, blinding, localDocumentLoader);
    console.log(`vc: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verifiedWithoutSecret = await verify(
      vc0,
      keypairs,
      localDocumentLoader,
    );
    expect(verifiedWithoutSecret.verified).toBeFalsy();

    const verified = await blindVerify(
      secret,
      vc0,
      keypairs,
      localDocumentLoader,
    );
    expect(verified.verified).toBeTruthy();

    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosedBound0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      nonce,
      keypairs,
      vpContext,
      localDocumentLoader,
      secret,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const proofVerified = await verifyProof(
      vp,
      nonce,
      keypairs,
      localDocumentLoader,
    );
    expect(proofVerified.verified).toBeTruthy();
  });

  test('blind sign and verify without secret', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const nonce = 'abcde';

    const { request, blinding } = await blindSignRequest(secret, nonce);

    const blindedVC = await blindSign(
      request,
      nonce,
      vcDraft0WithoutCryptosuite,
      keypairs,
      localDocumentLoader,
    );

    const vc0 = await unblind(blindedVC, blinding, localDocumentLoader);

    await expect(
      deriveProof(
        [{ original: vc0, disclosed: disclosedBound0 }],
        nonce,
        keypairs,
        vpContext,
        localDocumentLoader,
        // secret,
      ),
    ).rejects.toThrowError('RDFProofsError(MissingSecret)');
  });
});
