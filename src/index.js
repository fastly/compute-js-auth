/// <reference types="@fastly/js-compute" />
import { env } from 'fastly:env'
import pkceChallenge from 'pkce-challenge'
import * as cookie from './lib/cookie'
import * as config from './lib/config'
import * as responses from './lib/responses'
import * as util from './lib/util'
import * as jwt from './lib/jwt'

addEventListener('fetch', event => event.respondWith(handleRequest(event)))

async function handleRequest (event) {
  // Log service version.
  console.log(
    'FASTLY_SERVICE_VERSION: ',
    env('FASTLY_SERVICE_VERSION') || 'local'
  )

  const req = event.request
  const url = new URL(req.url)

  // Parse the Cookie header.
  const cookieHeader = req.headers.get('cookie')
  const cookies = cookie.parse(cookieHeader)

  // Load the service configuration, and the OpenID discovery and token signature metadata.
  const settings = await config.loadConfig()

  // Build the OAuth 2.0 redirect URL.
  let redirectUri = `${url.protocol}//${url.host}${settings.config.callbackPath}`

  // If the path matches the redirect URL path, continue the OAuth 2.0 authorization code flow.
  if (req.url.startsWith(redirectUri)) {
    // VERIFY THE AUTHORIZATION CODE AND EXCHANGE IT FOR TOKENS.

    // Check existence of the code verifier and state from the cookie.
    if (!cookies.state?.length || !cookies.code_verifier?.length) {
      return responses.unauthorized('State cookies not found.')
    }

    // Query string parameters from the IdP's response.
    const qs = url.searchParams

    // Authenticate the state token returned by the IdP, and verify that the state we stored matches its subject claim.
    try {
      const claimedState = await jwt.getClaimedState(
        settings.config.nonceSecret,
        qs.get('state')
      )
      if (claimedState !== cookies.state) {
        return responses.unauthorized('State mismatch.')
      }
    } catch (err) {
      const msg = 'Could not verify state.'
      console.error(msg, err)
      return responses.unauthorized(msg)
    }

    // Exchange the authorization code for tokens.
    const exchangeRes = await fetch(
      settings.openidConfiguration.token_endpoint,
      {
        method: 'POST',
        body: new URLSearchParams({
          client_id: settings.config.clientId,
          client_secret: settings.config.clientSecret,
          code: qs.get('code'),
          code_verifier: cookies.code_verifier,
          grant_type: 'authorization_code',
          redirect_uri: redirectUri
        }),
        backend: 'idp'
      }
    )

    // If the exchange is successful, proceed with the original request.
    if (exchangeRes.ok) {
      // Strip the random state from the state cookie value to get the original request.
      const originalReqPath = cookies.state.slice(
        0,
        -settings.config.stateParameterLength
      )

      // Parse the response body from the authorize step.
      const auth = await exchangeRes.json()

      // Replay the original request, setting the tokens as cookies.
      return responses.temporaryRedirect(originalReqPath, {
        accessTokenCookie: cookie.persistent(
          'access_token',
          auth.access_token,
          auth.expires_in
        ),
        idTokenCookie: cookie.persistent(
          'id_token',
          auth.id_token,
          auth.expires_in
        )
      })
    } else {
      // Otherwise, surface any errors from the Identity Provider.
      return responses.unauthorized(exchangeRes.body)
    }
  }

  // Verify any tokens stored as a result of a complete OAuth 2.0 authorization code flow.

  if (cookies.access_token && cookies.id_token) {
    if (settings.config.introspectAccessToken) {
      // Validate the access token using the OpenID userinfo endpoint; bearer authentication supports opaque, JWT and other token types (PASETO, Hawk),depending on your Identity Provider configuration.
      const userInfoRes = await fetch(
        settings.openidConfiguration.userinfo_endpoint,
        {
          headers: new Headers({
            Authorization: `Bearer ${cookies.access_token}`
          }),
          backend: 'idp'
        }
      )
      // Surface any errors and respond early.
      if (!userInfoRes.ok) {
        return responses.unauthorized(userInfoRes.body)
      }
    } else if (settings.config.jwtAccessToken) {
      // Validate the JWT access token at the edge.
      try {
        await jwt.validateToken(settings.jwks, cookies.access_token, {
          issuer: settings.openidConfiguration.issuer,
          audience: settings.config.clientId
        })
      } catch (err) {
        const msg = 'Access token invalid.'
        console.error(msg, err)
        return responses.unauthorized(msg)
      }
    }

    // Validate the JWT ID token.
    try {
      await jwt.validateToken(settings.jwks, cookies.id_token, {
        issuer: settings.openidConfiguration.issuer,
        audience: settings.config.clientId
      })
    } catch (err) {
      const msg = 'ID token invalid.'
      console.error(msg, err)
      return responses.unauthorized(msg)
    }

    // Authorization and authentication successful!

    // Modify the request before routing to the origin backend, e.g.:
    // Add an API key;
    req.headers.set('x-api-key', 'h3ll0fr0mc0mpu73@3dg3')
    // Add a custom header containing the access token;
    req.headers.set('fastly-access-token', cookies.access_token)
    // Add a custom header containing the ID token;
    req.headers.set('fastly-id-token', cookies.id_token)

    // Send the request to the origin backend.
    return fetch(req, { backend: 'origin' })
  }

  // Otherwise, start the OAuth 2.0 authorization code flow.

  // Generate the Proof Key for Code Exchange (PKCE) code verifier and code challenge.
  const pkce = await pkceChallenge()

  // Generate the OAuth 2.0 state parameter, used to prevent CSRF attacks, and store the original request path and query string.
  const randState = util.generateRandomStr(settings.config.stateParameterLength)
  const sep = url.search.length ? '?' : ''
  const state = `${url.pathname}${sep}${url.search}${randState}`

  // Generate the OpenID Connect nonce, used to mitigate replay attacks. This is a random value with a twist: it is a time limited token (JWT) that encodes the nonce and the state within its claims.
  const { stateAndNonce, nonce } = await jwt.generateNonceFromState(
    settings.config.nonceSecret,
    state
  )

  // Build the IdP authorization request URL.
  const authReqUrl = new URL(
    settings.openidConfiguration.authorization_endpoint
  )
  authReqUrl.searchParams.set('client_id', settings.config.clientId)
  authReqUrl.searchParams.set('code_challenge', pkce.code_challenge)
  authReqUrl.searchParams.set(
    'code_challenge_method',
    settings.config.codeChallengeMethod
  )
  authReqUrl.searchParams.set('redirect_uri', redirectUri)
  authReqUrl.searchParams.set('response_type', 'code')
  authReqUrl.searchParams.set('scope', settings.config.scope)
  authReqUrl.searchParams.set('state', stateAndNonce)
  authReqUrl.searchParams.set('nonce', nonce)

  // Redirect to the Identity Provider's login and authorization prompt.
  return responses.temporaryRedirect(authReqUrl.toString(), {
    codeVerifierCookie: cookie.persistent('code_verifier', pkce.code_verifier),
    stateCookie: cookie.persistent('state', state)
  })
}
