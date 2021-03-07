/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import jsigs from 'jsonld-signatures';
const {purposes: {AssertionProofPurpose}} = jsigs;

import {Ed25519VerificationKey2018} from
  '@digitalbazaar/ed25519-verification-key-2018';
import {Ed25519Signature2018} from '../';
import {credential, mockKey, controllerDoc} from './mock-data.js';

import {
  documentLoaderFactory,
  contexts,
} from '@transmute/jsonld-document-loader';

import * as ed25519 from 'ed25519-signature-2018-context';

describe('Ed25519Signature2018', () => {
  let documentLoader;

  before(async () => {
    documentLoader = documentLoaderFactory.pluginFactory
      .build({
        contexts: {
          ...contexts.W3C_Verifiable_Credentials,
          'https://w3id.org/security/ed25519-signature-2018/v1': ed25519
            .contexts.get('https://w3id.org/security/ed25519-signature-2018/v1')
        }
      })
      .addContext({
        [mockKey.controller]: controllerDoc
      })
      .buildDocumentLoader();
  });

  describe('constructor', () => {
    it('should exist', async () => {
      Ed25519Signature2018.should.exist;
    });
  });

  describe('sign() and verify()', () => {
    it('should sign a document', async () => {
      const unsignedCredential = {...credential};
      const keyPair = await Ed25519VerificationKey2018.from({...mockKey});
      const suite = new Ed25519Signature2018({key: keyPair});
      suite.date = '2010-01-01T19:23:24Z';

      const signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(signedCredential).to.have.property('proof');
      expect(signedCredential.proof.jws).to
        // eslint-disable-next-line max-len
        .equal('eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..AWYaAOHSfWc8lJzYnyJOEGFpeM1mo7Dh3ZfFAPypAR4gpE57i0xVvSMISIqxQQEKA46YhF-v8Yl3Pj-FXM0tBA');
    });
  });

  describe('verify()', () => {
    let signedCredential;

    before(async () => {
      const unsignedCredential = {...credential};
      const keyPair = await Ed25519VerificationKey2018.from({...mockKey});
      const suite = new Ed25519Signature2018({key: keyPair});
      suite.date = '2010-01-01T19:23:24Z';

      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    });

    it('should verify a document', async () => {
      const keyPair = await Ed25519VerificationKey2018.from({...mockKey});
      const suite = new Ed25519Signature2018({key: keyPair});

      const result = await jsigs.verify(signedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.true;
    });
  });
});
