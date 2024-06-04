import { describe, expect, test } from 'vitest';
import {
  requestBlindSign,
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
import vpContext from './example/vpContext.json';

describe('Blind Signatures', () => {
  test('blind sign and verify', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challengeForBlindSign = 'abcde';

    const { commitment, pokForCommitment, blinding } = await requestBlindSign(
      secret,
      challengeForBlindSign,
    );
    expect(commitment).toBeDefined();
    expect(pokForCommitment).toBeDefined();

    // type guard
    if (pokForCommitment === undefined) {
      return;
    }

    const verifiedRequest = await verifyBlindSignRequest(
      commitment,
      pokForCommitment,
      challengeForBlindSign,
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

    const blindSignRequest = await requestBlindSign(secret, undefined, true);

    const challengeForDeriveProof = 'xyz';
    const domain = 'example.org';

    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosedBound0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge: challengeForDeriveProof,
        domain,
        secret,
        blindSignRequest,
        withPpid: true,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    // PPID defined by domain = `example.org` and secret = `SECRET`
    expect(vp.holder.id).toBe(
      'ppid:uuGieOR_xSSZojovK3akZBNSQKvrDFvGto9-y70Cm_LmtO6BuMF-l_vO_kY5LhpYc',
    );

    const proofVerified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge: challengeForDeriveProof,
      domain,
    });
    expect(proofVerified.verified).toBeTruthy();
  });

  test('derive proof from bound credential with secret', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';

    const { commitment, blinding } = await requestBlindSign(secret, challenge);

    const blindedVC = await blindSign(
      commitment,
      vcDraft0WithoutCryptosuite,
      keypairs,
      localDocumentLoader,
    );

    const vc0 = await unblind(blindedVC, blinding, localDocumentLoader);

    const vp = await deriveProof(
      [{ original: vc0, disclosed: disclosedBound0 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        secret,
      },
    );
    expect(vp).not.toHaveProperty('error');
  });

  test('derive proof from bound credential without secret', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';

    const { commitment, blinding } = await requestBlindSign(secret, challenge);

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
        localDocumentLoader,
        {
          context: vpContext,
          challenge,
          // secret
        },
      ),
    ).rejects.toThrowError('RDFProofsError(MissingSecret)');
  });

  test('derive proof with blind sign request', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';

    const { commitment, blinding } = await requestBlindSign(secret, challenge);

    const blindedVC = await blindSign(
      commitment,
      vcDraft0WithoutCryptosuite,
      keypairs,
      localDocumentLoader,
    );

    const vc0 = await unblind(blindedVC, blinding, localDocumentLoader);

    const newBlindSignRequest = await requestBlindSign(secret, challenge);

    const vp = await deriveProof(
      [{ original: vc0, disclosed: disclosedBound0 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        secret,
        blindSignRequest: newBlindSignRequest,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');
  });

  test('derive proof without VC but with blind sign request', async () => {
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const challenge = 'abcde';
    const domain = 'example.org';

    const newBlindSignRequest = await requestBlindSign(secret, challenge);

    const vp = await deriveProof([], {}, localDocumentLoader, {
      challenge,
      secret,
      domain,
      blindSignRequest: newBlindSignRequest,
      withPpid: true,
    });
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');
  });
});
