/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
export const controller = 'https://example.edu/issuers/565049';

export const mockPublicKey = {
  '@context': [
    'https://w3id.org/security/suites/ed25519-2018/v1'
  ],
  // eslint-disable-next-line max-len
  id: 'https://example.edu/issuers/565049#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG',
  type: 'Ed25519VerificationKey2018',
  controller: 'https://example.edu/issuers/565049',
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq'
};

export const mockKeyPair = {
  type: 'Ed25519VerificationKey2018',
  controller,
  id: controller + '#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG',
  publicKeyBase58: 'GycSSui454dpYRKiFdsQ5uaE8Gy3ac6dSMPcAoQsk8yq',
  privateKeyBase58:
    '3Mmk4UzTRJTEtxaKk61LxtgUxAa2Dg36jF6VogPtRiKvfpsQWKPCLesKSV182RMmvM' +
    'JKk6QErH3wgdHp8itkSSiF'
};

export const controllerDoc = {
  '@context': [
    'https://www.w3.org/ns/did/v1',
    'https://w3id.org/security/suites/ed25519-2018/v1'
  ],
  id: 'https://example.edu/issuers/565049',
  assertionMethod: [mockPublicKey]
};

export const credential = {
  '@context': [
    'https://www.w3.org/2018/credentials/v1',
    'https://www.w3.org/2018/credentials/examples/v1'
  ],
  id: 'http://example.edu/credentials/1872',
  type: ['VerifiableCredential', 'AlumniCredential'],
  issuer: 'https://example.edu/issuers/565049',
  issuanceDate: '2010-01-01T19:23:24Z',
  credentialSubject: {
    id: 'https://example.edu/students/alice',
    alumniOf: 'Example University'
  }
};
