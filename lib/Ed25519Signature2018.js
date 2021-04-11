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
    super({
      type: 'Ed25519Signature2018', alg: 'EdDSA',
      LDKeyClass: Ed25519VerificationKey2018, contextUrl: SUITE_CONTEXT_URL,
      key, signer, verifier, proof, date, useNativeCanonize
    });
    this.requiredKeyType = 'Ed25519VerificationKey2018';
  }

  /**
   * Ensures the document to be signed contains the required signature suite
   * specific `@context`, by either adding it (if `addSuiteContext` is true),
   * or throwing an error if it's missing.
   * @override
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.document - JSON-LD document to be signed.
   * @param {boolean} options.addSuiteContext - Add suite context?
   */
  ensureSuiteContext({document, addSuiteContext}) {
    if(_includesCompatibleContext({document})) {
      return;
    }

    super.ensureSuiteContext({document, addSuiteContext});
  }

  /**
   * Checks whether a given proof exists in the document.
   * @override
   *
   * @param {object} options - Options hashmap.
   * @param {object} options.proof
   * @param {object} options.document
   * @param {ProofPurpose} options.purpose - jsonld-signatures ProofPurpose
   *  instance (e.g. AssertionProofPurpose, AuthenticationProofPurpose, etc).
   * @param {function} documentLoader  - A secure document loader (it is
   *   recommended to use one that provides static known documents, instead of
   *   fetching from the web) for returning contexts, controller documents,
   *   keys, and other relevant URLs needed for the proof.
   * @param {function} [options.expansionMap] - A custom expansion map that is
   *   passed to the JSON-LD processor; by default a function that will throw
   *   an error when unmapped properties are detected in the input, use `false`
   *   to turn this off and allow unmapped properties to be dropped or use a
   *   custom function.
   *
   * @returns {Promise<boolean>} Whether a match for the proof was found.
   */
  async matchProof({proof, document, purpose, documentLoader, expansionMap}) {
    if(!_includesCompatibleContext({document})) {
      return false;
    }
    return super.matchProof({
      proof, document, purpose, documentLoader, expansionMap
    });
  }
}

function _includesCompatibleContext({document}) {
  // Handle the unfortunate Ed25519Signature2018 / credentials/v1 collision
  const CRED_CONTEXT = 'https://www.w3.org/2018/credentials/v1';
  const hasEd2018 = _includesContext({
    document, contextUrl: SUITE_CONTEXT_URL
  });
  const hasCred = _includesContext({document, contextUrl: CRED_CONTEXT});

  if(hasEd2018 && hasCred) {
    // Warn if both are present
    console.warn('Warning: The ed25519-2018/v1 and credentials/v1 ' +
      'contexts are incompatible.');
    console.warn('For VCs using Ed25519Signature2018 suite,' +
      ' using the credentials/v1 context is sufficient.');
    return false;
  }
  // Either one by itself is fine, for this suite
  return hasEd2018 || hasCred;
}

/**
 * Tests whether a provided JSON-LD document includes a context url in its
 * `@context` property.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.document - A JSON-LD document.
 * @param {string} options.contextUrl - A context url.
 *
 * @returns {boolean} Returns true if document includes context.
 */
function _includesContext({document, contextUrl}) {
  const context = document['@context'];
  return context === contextUrl ||
    (Array.isArray(context) && context.includes(contextUrl));
}

Ed25519Signature2018.CONTEXT_URL = SUITE_CONTEXT_URL;
Ed25519Signature2018.CONTEXT = suiteContext.contexts.get(SUITE_CONTEXT_URL);
