"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_EXPIRATION = exports.SECRET = void 0;
exports.SECRET = process.env.TOKENIZE_SECRET || 'ABCD123';
exports.DEFAULT_EXPIRATION = 5 * 60 * 1000;
