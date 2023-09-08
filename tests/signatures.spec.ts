import keypairs from '../example/keypairs.json';
import vcDraft0 from '../example/vc0.json';
import vcDraft1 from '../example/vc1.json';
import _vpContext from '../example/vpContext.json';
import { sign, verify, keyGen } from '../src/api';

describe('Signatures', () => {
  test('keyGen', async () => {
    const keypair = await keyGen();
    console.log(`keypair: ${JSON.stringify(keypair, null, 2)}`);

    expect(keypair.secretKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
  });

  test('sign and verify', async () => {
    const vc0 = await sign(vcDraft0, keypairs);
    console.log(`vc0: ${JSON.stringify(vc0, null, 2)}`);
    expect(vc0).toBeDefined();

    const verified0 = await verify(vc0, keypairs);
    console.log(`verified0: ${JSON.stringify(verified0, null, 2)}`);
    expect(verified0.verified).toBeTruthy();

    const vc1 = await sign(vcDraft1, keypairs);
    console.log(`vc1: ${JSON.stringify(vc1, null, 2)}`);
    expect(vc1).toBeDefined();

    const verified1 = await verify(vc1, keypairs);
    console.log(`verified1: ${JSON.stringify(verified1, null, 2)}`);
    expect(verified1.verified).toBeTruthy();
  });

  test('empty keypairs', async () => {
    await expect(sign(vcDraft0, {})).rejects.toThrowError(
      'Safe mode validation error.',
    );
  });

  test("VC's verification method does not exist in keypairs", async () => {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const invalidVC = JSON.parse(JSON.stringify(vcDraft0));
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    invalidVC.proof.verificationMethod = 'did:example:issuer_not_exist#key';

    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
    await expect(sign(invalidVC, keypairs)).rejects.toThrowError(
      'RDFProofsError(InvalidVerificationMethod)',
    );
  });
});
