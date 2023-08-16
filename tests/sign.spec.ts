import { signBbs } from '../src/sign';
import doc0 from '../example/vc0.doc.json';
import proof0 from '../example/vc0.proof.json';
import keypair0 from '../example/keypair0.json';

describe("Proofs", () => {
  test('sign', async () => {
    console.log(`doc0: ${JSON.stringify(doc0, null, 2)}`);
    console.log(`proof0: ${JSON.stringify(proof0, null, 2)}`);
    console.log(`keypair0: ${JSON.stringify(keypair0, null, 2)}`);

    const vc = await signBbs(doc0, proof0, keypair0);
    console.log(`vc: ${JSON.stringify(vc, null, 2)}`);
    expect(vc).toBeDefined();
  });
});