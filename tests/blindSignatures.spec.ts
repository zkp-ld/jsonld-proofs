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
  verifyBlindSignRequest,
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
    const challenge_for_blind_sign = 'abcde';

    const { commitment, pokForCommitment, blinding } = await blindSignRequest(
      secret,
      challenge_for_blind_sign,
    );
    expect(commitment).toBeDefined();
    expect(pokForCommitment).toBeDefined();

    const verifiedRequest = await verifyBlindSignRequest(
      commitment,
      pokForCommitment,
      challenge_for_blind_sign,
    );
    expect(verifiedRequest.verified).toBeTruthy();

    const blindedVC = await blindSign(
      commitment,
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

    const challenge_for_derive_proof = 'xyz';
    const domain = 'example.org';

    const { vp } = await deriveProof(
      [
        { original: vc0, disclosed: disclosedBound0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      vpContext,
      localDocumentLoader,
      challenge_for_derive_proof,
      domain,
      secret,
      true,
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const proofVerified = await verifyProof(
      vp,
      keypairs,
      localDocumentLoader,
      challenge_for_derive_proof,
      domain,
    );
    expect(proofVerified.verified).toBeTruthy();
  });

  test('derive proof from bound credential without secret', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';

    const { commitment, blinding } = await blindSignRequest(secret, challenge);

    const blindedVC = await blindSign(
      commitment,
      vcDraft0WithoutCryptosuite,
      keypairs,
      localDocumentLoader,
    );

    const vc0 = await unblind(blindedVC, blinding, localDocumentLoader);

    await expect(
      deriveProof(
        [{ original: vc0, disclosed: disclosedBound0 }],
        keypairs,
        vpContext,
        localDocumentLoader,
        challenge,
        undefined,
        // secret,
      ),
    ).rejects.toThrowError('RDFProofsError(MissingSecret)');
  });
});
