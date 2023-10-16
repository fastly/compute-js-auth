/// <reference types="@fastly/js-compute" />
import * as jose from 'jose'
import { generateRandomStr } from './util'

// Retrieves a JWK from the Config Store.
function getJWK (jwks, kid) {
  const jwk = jwks.keys?.find(k => k.kid === kid)
  if (!jwk) {
    throw new Error(`No matching JWK found for identifier ${kid} .`)
  }
  return jwk
}

// Validates a JWT and verifies its claims.
// Params:
// tokenString: string, required – base64-encoded JWT
// verificationOptions: object, optional - additional verification options for standard claims in the JWT payload
//  e.g, { issuer: 'urn:example:issuer', audience: 'urn:example:audience' }
// Returns: decoded payload, if the JWT is valid.
export async function validateToken (jwks, tokenString, verificationOptions) {
  // 1. Retrieve the key identifier (kid) from the token.
  // 2. Retrieve the key matching the key identifier from the config store.
  // 3. Verify the token signature using the key.
  // 4. Verify any additional claims in the token payload, if verificationOptions are provided.

  // Peek at the token metadata before verification and retrieve the key identifier,
  // in order to pick the right key out of the config store.
  const header = jose.decodeProtectedHeader(tokenString)

  // Retrieve the public key matching the key ID from Config Store.
  const publicKey = getJWK(jwks, header.kid)

  // Import JWK to a runtime-specific key representation (KeyLike).
  const jwk = await jose.importJWK(publicKey, header.alg)

  // Verify the token –
  // The token's signature will be verified using the public key.
  // Key expiration, start time, authentication tags, etc. are automatically verified.
  const { payload } = await jose.jwtVerify(
    tokenString,
    jwk,
    verificationOptions
  )
  return payload
}

// Creates a time-limited (nonce) JWT and encodes the passed state within its claims.
export async function generateNonceFromState (nonceSecret, state) {
  const alg = 'HS256'
  // Generate a random value (nonce).
  const nonce = generateRandomStr(30) // create
  // Create token claims valid for 5 minutes (JWT).
  const stateAndNonce = await new jose.SignJWT({ nonce })
    .setSubject(state)
    .setProtectedHeader({ alg })
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(nonceSecret)

  return {
    stateAndNonce,
    nonce
  }
}

// Verifies the nonce JWT and retrieves its subject claim, a state string.
export async function getClaimedState (nonceSecret, stateAndNonce) {
  const { payload } = await jose.jwtVerify(stateAndNonce, nonceSecret)
  return payload?.sub
}
