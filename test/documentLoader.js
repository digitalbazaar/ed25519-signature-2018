import * as ed25519 from 'ed25519-signature-2018-context';
import * as exampleV1 from './contexts/example-v1.js';
import * as odrlV1 from './contexts/odrl-v1.js';
import {controllerDoc, mockPublicKey} from './mock-data.js';

import credentialsContext from 'credentials-context';
import didContext from 'did-context';

const context = {
  [didContext.constants.DID_CONTEXT_URL]: //
    didContext.contexts.get(didContext.constants.DID_CONTEXT_URL),
  [credentialsContext.constants.CONTEXT_URL]: //
    credentialsContext.contexts.get(credentialsContext.constants.CONTEXT_URL),
  [ed25519.constants.CONTEXT_URL]: //
    ed25519.contexts.get(ed25519.constants.CONTEXT_URL),
  [exampleV1.constants.CONTEXT_URL]: //
    exampleV1.contexts.get(exampleV1.constants.CONTEXT_URL),
  [odrlV1.constants.CONTEXT_URL]: //
    odrlV1.contexts.get(odrlV1.constants.CONTEXT_URL),
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
