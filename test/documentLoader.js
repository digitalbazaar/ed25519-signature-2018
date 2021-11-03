import didContext from 'did-context';
import * as ed25519 from 'ed25519-signature-2018-context';
import {
  mockPublicKey, controllerDoc
} from './mock-data.js';

const credentialsContext = require('credentials-context');

const context = {
  [didContext.constants.DID_CONTEXT_URL]: //
  didContext.contexts.get(didContext.constants.DID_CONTEXT_URL),
  [credentialsContext.constants.CONTEXT_URL]: //
  credentialsContext.contexts.get(credentialsContext.constants.CONTEXT_URL),
  [ed25519.constants.CONTEXT_URL]: //
  ed25519.contexts.get(ed25519.constants.CONTEXT_URL),
  'https://www.w3.org/2018/credentials/examples/v1': //
  require('./contexts/example-v1.json'),
  'https://www.w3.org/ns/odrl.jsonld': //
  require('./contexts/odrl-v1.json'),
  // eslint-disable-next-line max-len
  'https://example.edu/issuers/565049#z6MkjLrk3gKS2nnkeWcmcxiZPGskmesDpuwRBorgHxUXfxnG': //
  mockPublicKey,
  'https://example.edu/issuers/565049': controllerDoc
};

const documentLoader = async iri => {

  if(context[iri]) {
    return {document: context[iri]};
  }

  throw new Error('[DOCUMENTLOADER ERROR] Could not find: ', iri);
};

export default documentLoader;
