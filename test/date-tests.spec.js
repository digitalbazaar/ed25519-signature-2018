/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
chai.should();
const {expect} = chai;

import jsigs from 'jsonld-signatures';
const {
  purposes: {AssertionProofPurpose},
} = jsigs;

import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018'; //

import {Ed25519Signature2018} from '..';
import {credential, mockKeyPair} from './mock-data.js';
import documentLoader from './documentLoader';

describe('Document date behavior', () => {

  it('should sign when issuanceDate is valid', async () => {
    const unsignedCredential = {...credential};
    const keyPair = await Ed25519VerificationKey2018.from({...mockKeyPair});
    const suite = new Ed25519Signature2018({
      key: keyPair,
    });

    const signedCredential = await jsigs.sign(unsignedCredential, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader,
    });
    expect(signedCredential).to.have.property('proof');
  });

  it('should catch error when issuanceDate is object', async () => {
    // const ISSUED_ON = new Date("1996-09-29T15:01:23.456Z").getTime();
    // Produced from moment(ISSUED_ON).toObject()
    const dateObj = {
      years: 1996,
      months: 8,
      date: 30,
      hours: 0,
      minutes: 1,
      seconds: 23,
      milliseconds: 456,
    };

    const unsignedCredential = {...credential};
    unsignedCredential.issuanceDate = dateObj;

    const keyPair = await Ed25519VerificationKey2018.from({...mockKeyPair});
    const suite = new Ed25519Signature2018({
      key: keyPair,
    });

    let err;

    try {
      await jsigs.sign(unsignedCredential, {
        suite,
        purpose: new AssertionProofPurpose(),
        documentLoader,
      });
    } catch(e) {
      err = e;
    }

    err.should.exist;
  });

});
