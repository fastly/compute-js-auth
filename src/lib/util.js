// Generates a random string of a given length.
export function generateRandomStr (length) {
  const values = new Uint8Array(length)
  crypto.getRandomValues(values)
  return Array.from(values, byte => byte.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, length)
}
