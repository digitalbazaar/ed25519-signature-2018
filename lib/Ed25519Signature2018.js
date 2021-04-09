/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */

import {JwsLinkedDataSignature} from '@digitalbazaar/jws-linked-data-signature';
import {
  Ed25519VerificationKey2018
} from '@digitalbazaar/ed25519-verification-key-2018';

import suiteContext from 'ed25519-signature-2018-context';
// 'https://w3id.org/security/suites/ed25519-2018/v1'
const SUITE_CONTEXT_URL = suiteContext.constants.CONTEXT_URL;

export class Ed25519Signature2018 extends JwsLinkedDataSignature {
  /**
   * @param {object} options - Options hashmap.
   *
   * Either a `key` OR at least one of `signer`/`verifier` is required:
   *
   * @param {object} [options.key] - An optional key object (containing an
   *   `id` property, and either `signer` or `verifier`, depending on the
   *   intended operation. Useful for when the application is managing keys
   *   itself (when using a KMS, you never have access to the private key,
   *   and so should use the `signer` param instead).
   * @param {Function} [options.signer] - Signer function that returns an
   *   object with an async sign() method. This is useful when interfacing
   *   with a KMS (since you don't get access to the private key and its
   *   `signer()`, the KMS client gives you only the signer function to use).
   * @param {Function} [options.verifier] - Verifier function that returns
   *   an object with an async `verify()` method. Useful when working with a
   *   KMS-provided verifier function.
   *
   * Advanced optional parameters and overrides:
   *
   * @param {object} [options.proof] - A JSON-LD document with options to use
   *   for the `proof` node (e.g. any other custom fields can be provided here
   *   using a context different from security-v2).
   * @param {string|Date} [options.date] - Signing date to use if not passed.
   * @param {boolean} [options.useNativeCanonize] - Whether to use a native
   *   canonize algorithm.
   */
  constructor({key, signer, verifier, proof, date, useNativeCanonize} = {}) {
    super({type: 'Ed25519Signature2018', alg: 'EdDSA',
      LDKeyClass: Ed25519VerificationKey2018, contextUrl: SUITE_CONTEXT_URL,
      key, signer, verifier, proof, date, useNativeCanonize
    });
    this.requiredKeyType = 'Ed25519VerificationKey2018';
  }
}

Ed25519Signature2018.CONTEXT_URL = SUITE_CONTEXT_URL;
Ed25519Signature2018.CONTEXT = suiteContext.contexts.get(SUITE_CONTEXT_URL);
