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
import didContext from 'did-context';
const credentialsContext = require('credentials-context');

const context = {
  [didContext.constants.DID_CONTEXT_URL]: //
  didContext.contexts.get(didContext.constants.DID_CONTEXT_URL),
  [credentialsContext.constants.CONTEXT_URL]: //
  credentialsContext.contexts.get(credentialsContext.constants.CONTEXT_URL),
  'https://www.w3.org/2018/credentials/examples/v1': //
  require('./contexts/example-v1.json'),
  'https://www.w3.org/ns/odrl.jsonld': require('./contexts/odrl-v1.json')
};

const documentLoader = async iri => {

  if(context[iri]) {
    return {document: context[iri]};
  }

  throw new Error('Could not find: ', iri);
};

describe('Suite date behavior', () => {

  it('should sign a document when date is valid', async () => {
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

  it('should fail to sign a document when date is object', async () => {
    //const ISSUED_ON = new Date("1996-09-29T15:01:23.456Z").getTime();
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
    const keyPair = await Ed25519VerificationKey2018.from({...mockKeyPair});
    const suite = new Ed25519Signature2018({
      key: keyPair,
    });

    unsignedCredential.issuanceDate = dateObj;
    const signedCredential = await jsigs.sign(unsignedCredential, {
      suite,
      purpose: new AssertionProofPurpose(),
      documentLoader,
    });
    expect(signedCredential).to.have.property('proof');
  });

});
