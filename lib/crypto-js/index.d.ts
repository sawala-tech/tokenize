interface Mode {
  /**
   * Processes the data block at offset.
   *
   * @param words The data words to operate on.
   * @param offset The offset where the block starts.
   *
   * @example
   *
   *     mode.processBlock(data.words, offset);
   */
  processBlock(words: number[], offset: number): void;
}

interface Padding {
  /**
   * Pads data using the algorithm defined in PKCS #5/7.
   *
   * @param data The data to pad.
   * @param blockSize The multiple that the data should be padded to.
   *
   * @example
   *
   *     CryptoJS.pad.Pkcs7.pad(wordArray, 4);
   */
  pad(data: WordArray, blockSize: number): void;

  /**
   * Unpads data that had been padded using the algorithm defined in PKCS #5/7.
   *
   * @param data The data to unpad.
   *
   * @example
   *
   *     CryptoJS.pad.Pkcs7.unpad(wordArray);
   */
  unpad(data: WordArray): void;
}

interface Encoder {
  /**
   * Converts a word array to a hex string.
   *
   * @param wordArray The word array.
   *
   * @return The hex string.
   *
   * @example
   *
   *     var hexString = CryptoJS.enc.Hex.stringify(wordArray);
   */
  stringify(wordArray: WordArray): string;
  /**
   * Converts a hex string to a word array.
   *
   * @param hexStr The hex string.
   *
   * @return The word array.
   *
   * @example
   *
   *     var wordArray = CryptoJS.enc.Hex.parse(hexString);
   */
  parse(str: string): WordArray;
}

interface CipherParams {
  /**
   * The raw ciphertext.
   */
  ciphertext: WordArray;
  /**
   * The key to this ciphertext.
   */
  key: WordArray;
  /**
   * The IV used in the ciphering operation.
   */
  iv: WordArray;
  /**
   * The salt used with a key derivation function.
   */
  salt: WordArray;
  /**
   * The cipher algorithm.
   */
  algorithm: CipherStatic;
  /**
   * The block mode used in the ciphering operation.
   */
  mode: Mode;
  /**
   * The padding scheme used in the ciphering operation.
   */
  padding: Padding;
  /**
   * The block size of the cipher.
   */
  blockSize: number;
  /**
   * The default formatting strategy to convert this cipher params object to a string.
   */
  formatter: Format;
  /**
   * Converts this cipher params object to a string.
   *
   * @param formatter (Optional) The formatting strategy to use.
   *
   * @return The stringified cipher params.
   *
   * @throws Error If neither the formatter nor the default formatter is set.
   *
   * @example
   *
   *     var string = cipherParams + '';
   *     var string = cipherParams.toString();
   *     var string = cipherParams.toString(CryptoJS.format.OpenSSL);
   */
  toString(formatter?: Format): string;
}
interface Format {
  /**
   * Converts a cipher params object to an OpenSSL-compatible string.
   *
   * @param cipherParams The cipher params object.
   *
   * @return The OpenSSL-compatible string.
   *
   * @example
   *
   *     var openSSLString = CryptoJS.format.OpenSSL.stringify(cipherParams);
   */
  stringify(cipherParams: CipherParams): string;

  /**
   * Converts an OpenSSL-compatible string to a cipher params object.
   *
   * @param openSSLStr The OpenSSL-compatible string.
   *
   * @return The cipher params object.
   *
   * @example
   *
   *     var cipherParams = CryptoJS.format.OpenSSL.parse(openSSLString);
   */
  parse(str: string): CipherParams;
}

interface Cipher {
  /**
   * This cipher's key size. Default: 4 (128 bits)
   */
  keySize: number;
  /**
   * This cipher's IV size. Default: 4 (128 bits)
   */
  ivSize: number;
  /**
   * A constant representing encryption mode.
   */
  readonly _ENC_XFORM_MODE: number;
  /**
   * A constant representing decryption mode.
   */
  readonly _DEV_XFORM_MODE: number;

  /**
   * Resets this cipher to its initial state.
   *
   * @example
   *
   *     cipher.reset();
   */
  reset(): void;

  /**
   * Adds data to be encrypted or decrypted.
   *
   * @param dataUpdate The data to encrypt or decrypt.
   *
   * @return The data after processing.
   *
   * @example
   *
   *     var encrypted = cipher.process('data');
   *     var encrypted = cipher.process(wordArray);
   */
  process(dataUpdate: WordArray | string): WordArray;

  /**
   * Finalizes the encryption or decryption process.
   * Note that the finalize operation is effectively a destructive, read-once operation.
   *
   * @param dataUpdate The final data to encrypt or decrypt.
   *
   * @return The data after final processing.
   *
   * @example
   *
   *     var encrypted = cipher.finalize();
   *     var encrypted = cipher.finalize('data');
   *     var encrypted = cipher.finalize(wordArray);
   */
  finalize(dataUpdate?: WordArray | string): WordArray;
}

interface WordArray {
  /**
   * The array of 32-bit words.
   */
  words: number[];
  /**
   * The number of significant bytes in this word array.
   */
  sigBytes: number;
  /**
   * Converts this word array to a string.
   *
   * @param encoder (Optional) The encoding strategy to use. Default: CryptoJS.enc.Hex
   *
   * @return The stringified word array.
   *
   * @example
   *
   *     var string = wordArray + '';
   *     var string = wordArray.toString();
   *     var string = wordArray.toString(CryptoJS.enc.Utf8);
   */
  toString(encoder?: Encoder): string;

  /**
   * Concatenates a word array to this word array.
   *
   * @param wordArray The word array to append.
   *
   * @return This word array.
   *
   * @example
   *
   *     wordArray1.concat(wordArray2);
   */
  concat(wordArray: WordArray): this;

  /**
   * Removes insignificant bits.
   *
   * @example
   *
   *     wordArray.clamp();
   */
  clamp(): void;

  /**
   * Creates a copy of this word array.
   *
   * @return The clone.
   *
   * @example
   *
   *     var clone = wordArray.clone();
   */
  clone(): WordArray;
}

interface CipherOption {
  /**
   * The IV to use for this operation.
   */
  iv?: WordArray | undefined;
  format?: Format | undefined;
  [key: string]: any;
}

interface CipherStatic {
  /**
   * Creates this cipher in encryption mode.
   *
   * @param key The key.
   * @param cfg (Optional) The configuration options to use for this operation.
   *
   * @return A cipher instance.
   *
   * @example
   *
   *     var cipher = CryptoJS.algo.AES.createEncryptor(keyWordArray, { iv: ivWordArray });
   */
  createEncryptor(key: WordArray, cfg?: CipherOption): Cipher;

  /**
   * Creates this cipher in decryption mode.
   *
   * @param key The key.
   * @param cfg (Optional) The configuration options to use for this operation.
   *
   * @return A cipher instance.
   *
   * @example
   *
   *     var cipher = CryptoJS.algo.AES.createDecryptor(keyWordArray, { iv: ivWordArray });
   */
  createDecryptor(key: WordArray, cfg?: CipherOption): Cipher;

  /**
   * Initializes a newly created cipher.
   *
   * @param xformMode Either the encryption or decryption transormation mode constant.
   * @param key The key.
   * @param cfg (Optional) The configuration options to use for this operation.
   *
   * @example
   *
   *     var cipher = CryptoJS.algo.AES.create(CryptoJS.algo.AES._ENC_XFORM_MODE, keyWordArray, { iv: ivWordArray });
   */
  create(xformMode: number, key: WordArray, cfg?: CipherOption): Cipher;
}

interface CipherHelper {
  encrypt(message: WordArray | string, key: WordArray | string, cfg?: CipherOption): CipherParams;
  decrypt(ciphertext: CipherParams | string, key: WordArray | string, cfg?: CipherOption): WordArray;
}


export const AES: CipherHelper
export const enc: {
  Utf8: Encoder
}