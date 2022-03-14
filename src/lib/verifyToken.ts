import { VerifyToken } from '@sawala-tech/tokenize'

import * as crypt from '../../lib/crypto-js'
import { DEFAULT_EXPIRATION, SECRET } from '../constants'

export const verifyToken: VerifyToken = (token, expired = DEFAULT_EXPIRATION) => {
  const decryptedTimestamp = parseInt(crypt.AES.decrypt(token, SECRET).toString(crypt.enc.Utf8) || '');
  const time = Date.now()
  const expiration = decryptedTimestamp + expired

  if(expiration > time) {
    return true
  } else {
    return false
  }
}