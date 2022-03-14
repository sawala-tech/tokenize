declare module '@sawala-tech/tokenize' {
  export type VerifyToken = (
    token: string,
    expired?: number
  ) => boolean
  export type GenerateToken = () => string
  export const verifyToken: VerifyToken
  export const generateToken: GenerateToken
}