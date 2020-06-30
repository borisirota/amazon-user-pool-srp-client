
declare module 'amazon-user-pool-srp-client' {
  export interface SRPClient {
    poolName: string
    N: string
    k: string
    g: string
    infoBits: string
    constructor(poolName: string)
    generateRandomSmallA(): string 
    calculateA(a: string): string 
    calculateU(A: string, B: string): string
    getPasswordAuthenticationKey(
      username: string,
      password: string,
      serverBValue: string,
      salt: string
    ): string
    padHex(bigInt: string): string
    hash(str: string): string
    hexHash(str: string): string
    computehkdf(ikm: string, salt: string): string
  }

  export function calculateSignature (
    hkdf: string,
    userPoolId: string,
    username: string,
    secretBlock: string,
    dateNow: string
  ): string 

  export function getNowString(): string
}
