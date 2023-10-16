/// <reference types="@fastly/js-compute" />
import * as cookie from './cookie'

export const unauthorized = body => {
  const res = new Response(body, {
    status: 401
  })
  res.headers.append('Set-Cookie', cookie.expired('access_token'))
  res.headers.append('Set-Cookie', cookie.expired('id_token'))
  res.headers.append('Set-Cookie', cookie.expired('code_verifier'))
  res.headers.append('Set-Cookie', cookie.expired('state'))
  return res
}

export const temporaryRedirect = (
  location,
  {
    accessTokenCookie = cookie.expired('access_token'),
    idTokenCookie = cookie.expired('id_token'),
    codeVerifierCookie = cookie.expired('code_verifier'),
    stateCookie = cookie.expired('state')
  } = {}
) => {
  const res = new Response(`Redirecting to ${location}`, {
    status: 307
  })
  res.headers.set('Location', location)
  res.headers.append('Set-Cookie', accessTokenCookie)
  res.headers.append('Set-Cookie', idTokenCookie)
  res.headers.append('Set-Cookie', codeVerifierCookie)
  res.headers.append('Set-Cookie', stateCookie)
  return res
}
