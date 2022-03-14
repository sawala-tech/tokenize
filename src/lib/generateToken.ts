import { GenerateToken } from '@sawala-tech/tokenize'

import * as crypt from '../../lib/crypto-js'
import { SECRET } from '../constants'

export const generateToken: GenerateToken = () => {
  const timestamp = Date.now()
  return crypt.AES.encrypt(timestamp?.toString(), SECRET).toString()
}