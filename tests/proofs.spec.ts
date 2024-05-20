import * as jsonld from 'jsonld';
import { describe, expect, test } from 'vitest';
import { sign, deriveProof, verifyProof } from '../src/api';
import lessThanEqPrvPub64 from './circuits/less_than_eq_prv_pub_64.json';
import lessThanPrvPub64 from './circuits/less_than_prv_pub_64.json';
import lessThanPubPrv64 from './circuits/less_than_pub_prv_64.json';
import { localDocumentLoader, remoteDocumentLoader } from './documentLoader';
import disclosed0 from './example/disclosed0.json';
import disclosed0HiddenLiteral from './example/disclosed0_hidden_literals.json';
import disclosed1 from './example/disclosed1.json';
import disclosed2 from './example/disclosed2.json';
import disclosed3 from './example/disclosed3.json';
import disclosed4 from './example/disclosed4.json';
import keypairs from './example/keypairs.json';
import vcDraft0 from './example/vc0.json';
import vc0HiddenLiteral from './example/vc0_hidden_literals.json';
import vcDraft1 from './example/vc1.json';
import vcDraft2 from './example/vc2.json';
import vcDraft3 from './example/vc3.json';
import vcDraft4 from './example/vc4.json';
import _vpContext from './example/vpContext.json';
import _vpContext3 from './example/vpContext3.json';
import _vpContext4 from './example/vpContext4.json';

const vpContext = _vpContext as unknown as jsonld.ContextDefinition;
const vpContext3 = _vpContext3 as unknown as jsonld.ContextDefinition;
const vpContext4 = _vpContext4 as unknown as jsonld.ContextDefinition;

describe('Proofs', () => {
  test('deriveProof and verifyProof', async () => {
    const vc0 = await sign(vcDraft0, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0 },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with remote context', async () => {
    const vc3 = await sign(vcDraft3, keypairs, remoteDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [{ original: vc3, disclosed: disclosed3 }],
      keypairs,
      remoteDocumentLoader,
      {
        context: vpContext3,
        challenge,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, remoteDocumentLoader, {
      challenge,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with hidden literal', async () => {
    const vc0 = await sign(vc0HiddenLiteral, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0HiddenLiteral },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with @list and @set', async () => {
    const vc4 = await sign(vcDraft4, keypairs, localDocumentLoader);
    const challenge = 'abcde';
    const vp = await deriveProof(
      [{ original: vc4, disclosed: disclosed4 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext4,
        challenge,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with less-than range proof', async () => {
    const vc2 = await sign(vcDraft2, keypairs, localDocumentLoader);
    const challenge = 'abcde';

    const circuits = new Map([
      [
        lessThanPrvPub64.id,
        {
          r1cs: lessThanPrvPub64.r1cs,
          wasm: lessThanPrvPub64.wasm,
          provingKey: lessThanPrvPub64.provingKey,
        },
      ],
    ]);
    const predicates = [
      {
        '@context': 'https://zkp-ld.org/context.jsonld',
        type: 'Predicate',
        circuit: 'circ:lessThanPrvPub',
        private: [
          {
            type: 'PrivateVariable',
            var: 'lesser',
            val: '_:Y',
          },
        ],
        public: [
          {
            type: 'PublicVariable',
            var: 'greater',
            val: {
              '@value': '50000',
              '@type': 'xsd:integer',
            },
          },
        ],
      },
    ];

    const vp = await deriveProof(
      [{ original: vc2, disclosed: disclosed2 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        predicates,
        circuits,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      snarkVerifyingKeys: new Map([
        [
          'https://zkp-ld.org/circuit/lessThanPrvPub',
          lessThanPrvPub64.provingKey,
        ],
      ]),
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof with unsatisfied less-than range proof', async () => {
    const vc2 = await sign(vcDraft2, keypairs, localDocumentLoader);
    const challenge = 'abcde';

    const circuits = new Map([
      [
        lessThanPrvPub64.id,
        {
          r1cs: lessThanPrvPub64.r1cs,
          wasm: lessThanPrvPub64.wasm,
          provingKey: lessThanPrvPub64.provingKey,
        },
      ],
    ]);
    const predicates = [
      {
        '@context': 'https://zkp-ld.org/context.jsonld',
        type: 'Predicate',
        circuit: 'circ:lessThanPrvPub',
        private: [
          {
            type: 'PrivateVariable',
            var: 'lesser',
            val: '_:X',
          },
        ],
        public: [
          {
            type: 'PublicVariable',
            var: 'greater',
            val: {
              '@value': '1970-01-01',
              '@type': 'http://www.w3.org/2001/XMLSchema#date',
            },
          },
        ],
      },
    ];

    const vp = await deriveProof(
      [{ original: vc2, disclosed: disclosed2 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        predicates,
        circuits,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      snarkVerifyingKeys: new Map([
        [
          'https://zkp-ld.org/circuit/lessThanPrvPub',
          lessThanPrvPub64.provingKey,
        ],
      ]),
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeFalsy();
  });

  test('deriveProof and verifyProof with less-than-equal range proof', async () => {
    const vc2 = await sign(vcDraft2, keypairs, localDocumentLoader);
    const challenge = 'abcde';

    const circuits = new Map([
      [
        lessThanEqPrvPub64.id,
        {
          r1cs: lessThanEqPrvPub64.r1cs,
          wasm: lessThanEqPrvPub64.wasm,
          provingKey: lessThanEqPrvPub64.provingKey,
        },
      ],
    ]);
    const predicates = [
      {
        '@context': 'https://zkp-ld.org/context.jsonld',
        type: 'Predicate',
        circuit: 'circ:lessThanEqPrvPub',
        private: [
          {
            type: 'PrivateVariable',
            var: 'lesser',
            val: '_:X',
          },
        ],
        public: [
          {
            type: 'PublicVariable',
            var: 'greater',
            val: {
              '@value': '1970-01-01',
              '@type': 'http://www.w3.org/2001/XMLSchema#date',
            },
          },
        ],
      },
    ];

    const vp = await deriveProof(
      [{ original: vc2, disclosed: disclosed2 }],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        predicates,
        circuits,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      snarkVerifyingKeys: new Map([
        [
          'https://zkp-ld.org/circuit/lessThanEqPrvPub',
          lessThanEqPrvPub64.provingKey,
        ],
      ]),
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('two less-than range proofs', async () => {
    const vc0 = await sign(vc0HiddenLiteral, keypairs, localDocumentLoader);
    const vc1 = await sign(vcDraft1, keypairs, localDocumentLoader);
    const challenge = 'abcde';

    const circuits = new Map([
      [
        lessThanPrvPub64.id,
        {
          r1cs: lessThanPrvPub64.r1cs,
          wasm: lessThanPrvPub64.wasm,
          provingKey: lessThanPrvPub64.provingKey,
        },
      ],
      [
        lessThanPubPrv64.id,
        {
          r1cs: lessThanPubPrv64.r1cs,
          wasm: lessThanPubPrv64.wasm,
          provingKey: lessThanPubPrv64.provingKey,
        },
      ],
    ]);
    const predicates = [
      {
        '@context': 'https://zkp-ld.org/context.jsonld',
        type: 'Predicate',
        circuit: 'circ:lessThanPrvPub',
        private: [
          {
            type: 'PrivateVariable',
            var: 'lesser',
            val: '_:xdate',
          },
        ],
        public: [
          {
            type: 'PublicVariable',
            var: 'greater',
            val: {
              '@value': '2023-12-31T23:59:59Z',
              '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
            },
          },
        ],
      },
      {
        '@context': 'https://zkp-ld.org/context.jsonld',
        type: 'Predicate',
        circuit: 'circ:lessThanPubPrv',
        private: [
          {
            type: 'PrivateVariable',
            var: 'greater',
            val: '_:xdate',
          },
        ],
        public: [
          {
            type: 'PublicVariable',
            var: 'lesser',
            val: {
              '@value': '2020-01-01T00:00:00Z',
              '@type': 'http://www.w3.org/2001/XMLSchema#dateTime',
            },
          },
        ],
      },
    ];

    const vp = await deriveProof(
      [
        { original: vc0, disclosed: disclosed0HiddenLiteral },
        { original: vc1, disclosed: disclosed1 },
      ],
      keypairs,
      localDocumentLoader,
      {
        context: vpContext,
        challenge,
        predicates,
        circuits,
      },
    );
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      snarkVerifyingKeys: new Map([
        [
          'https://zkp-ld.org/circuit/lessThanPrvPub',
          lessThanPrvPub64.provingKey,
        ],
        [
          'https://zkp-ld.org/circuit/lessThanPubPrv',
          lessThanPubPrv64.provingKey,
        ],
      ]),
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof and verifyProof without VCs but with PPID', async () => {
    const challenge = 'abcde';
    const domain = 'example.org';
    const secret = new Uint8Array(Buffer.from('SECRET'));
    const vp = await deriveProof([], keypairs, localDocumentLoader, {
      context: vpContext,
      challenge,
      secret,
      domain,
      withPpid: true,
    });
    console.log(`vp:\n${JSON.stringify(vp, null, 2)}`);
    expect(vp).not.toHaveProperty('error');

    const verified = await verifyProof(vp, keypairs, localDocumentLoader, {
      challenge,
      domain,
    });
    console.log(`verified: ${JSON.stringify(verified, null, 2)}`);
    expect(verified.verified).toBeTruthy();
  });

  test('deriveProof without VCs nor PPID', async () => {
    const challenge = 'abcde';
    const domain = 'example.org';
    const secret = new Uint8Array(Buffer.from('SECRET'));
    await expect(
      deriveProof([], keypairs, localDocumentLoader, {
        context: vpContext,
        challenge,
        secret,
        domain,
        withPpid: false,
      }),
    ).rejects.toThrowError('RDFProofsError(MissingInputToDeriveProof)');
  });
});
