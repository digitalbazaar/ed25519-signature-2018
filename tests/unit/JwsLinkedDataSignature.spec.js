/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
import dirtyChai from 'dirty-chai';
chai.use(dirtyChai);
chai.should();
const {expect} = chai;

import {Ed25519Signature2018} from '../../';

describe('Ed25519Signature2018', () => {
  describe('constructor', () => {
    it('should exist', async () => {
      const ex = new Ed25519Signature2018();

      expect(ex).to.exist();
    });
  });
});
