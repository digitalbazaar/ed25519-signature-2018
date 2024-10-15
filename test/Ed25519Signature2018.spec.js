/*!
 * Copyright (c) 2021-2024 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import jsigs from 'jsonld-signatures';
const {purposes: {AssertionProofPurpose}} = jsigs;

import {credential, mockKeyPair} from './mock-data.js';
import {Ed25519Signature2018, suiteContext} from '../lib/index.js';
import documentLoader from './documentLoader.js';
import {Ed25519VerificationKey2018} from
  '@digitalbazaar/ed25519-verification-key-2018';

/*
mockPublicKey, controllerDoc
import didContext from 'did-context';

import {
  documentLoaderFactory,
  contexts,
} from '@transmute/jsonld-document-loader';

import * as ed25519 from 'ed25519-signature-2018-context';
*/

describe('Ed25519Signature2018', () => {

  describe('constructor', () => {
    it('should exist', async () => {
      expect(Ed25519Signature2018).to.exist;
      expect(suiteContext).to.exist;

      suiteContext.should.have.keys([
        'constants',
        'contexts',
        'appContextMap',
        'documentLoader',
        'CONTEXT_URL',
        'CONTEXT',
      ]);

      expect(Ed25519Signature2018).to.have
        .property('CONTEXT_URL', suiteContext.constants.CONTEXT_URL);

      const context = Ed25519Signature2018.CONTEXT;
      context.should.exist;
      context['@context'].id.should.equal('@id');

    });
  });

  describe('sign()', () => {
    it('should sign a document', async () => {
      const unsignedCredential = {...credential};
      const keyPair = await Ed25519VerificationKey2018.from({...mockKeyPair});
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
        .equal('eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..5MPoYFmFjaIAqgGnFDhRRaLrXJ1dMnzOO2wJRyngXhd39DyBA9ga1Pted_0WD1t_jHklX1eKvPCmM3xe3JIlDQ');
    });

    it('should throw error if "signer" is not specified', async () => {
      const unsignedCredential = {...credential};
      const suite = new Ed25519Signature2018();
      let signedCredential;
      let err;
      try {
        signedCredential = await jsigs.sign(unsignedCredential, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });
      } catch(e) {
        err = e;
      }

      expect(signedCredential).to.equal(undefined);
      expect(err.name).to.equal('Error');
      expect(err.message).to.equal('A signer API has not been specified.');
    });
  });

  describe('verify()', () => {
    let signedCredential;

    before(async () => {
      const unsignedCredential = {...credential};
      const keyPair = await Ed25519VerificationKey2018.from({...mockKeyPair});
      const suite = new Ed25519Signature2018({key: keyPair});
      suite.date = '2010-01-01T19:23:24Z';

      signedCredential = await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });
    });

    it('should verify a document', async () => {
      const suite = new Ed25519Signature2018();

      const result = await jsigs.verify(signedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      expect(result.verified).to.be.true;
    });

    it('should fail verification if "jws" is not string', async () => {
      const suite = new Ed25519Signature2018();
      const signedCredentialCopy =
        JSON.parse(JSON.stringify(signedCredential));
      // intentionally modify proofValue type to not be string
      signedCredentialCopy.proof.jws = {};

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      const {error} = result.results[0];
      expect(result.verified).to.be.false;
      expect(error.name).to.equal('TypeError');
      expect(error.message).to.equal(
        'The proof does not include a valid "jws" property.'
      );
    });

    it('should fail verification if "proofValue" is not given', async () => {
      const suite = new Ed25519Signature2018();
      const signedCredentialCopy =
        JSON.parse(JSON.stringify(signedCredential));
      // intentionally modify proofValue to be undefined
      signedCredentialCopy.proof.jws = undefined;

      const result = await jsigs.verify(signedCredentialCopy, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader
      });

      const {error} = result.results[0];

      expect(result.verified).to.be.false;
      expect(error.name).to.equal('TypeError');
      expect(error.message).to.equal(
        'The proof does not include a valid "jws" property.'
      );
    });

    it('should fail verification if proof type is not Ed25519Signature2018',
      async () => {
        const suite = new Ed25519Signature2018();
        const signedCredentialCopy =
          JSON.parse(JSON.stringify(signedCredential));

        // intentionally modify proof type to be Ed25519Signature2020
        signedCredentialCopy.proof.type = 'Ed25519Signature2020';

        const result = await jsigs.verify(signedCredentialCopy, {
          suite,
          purpose: new AssertionProofPurpose(),
          documentLoader
        });

        expect(result.error).to.exist;
        const {errors} = result.error;

        expect(result.verified).to.be.false;
        expect(errors[0].name).to.equal('NotFoundError');
        expect(errors[0].message).to
        // eslint-disable-next-line max-len
          .equal('Did not verify any proofs; insufficient proofs matched the acceptable suite(s) and required purpose(s).');

      });
  });
});
