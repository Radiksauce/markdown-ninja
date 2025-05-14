export default function deepClone<T>(input: T): T {
  // TODO: improve: error: Proxy object could not be cloned
  // return structuredClone(input);
  return JSON.parse(JSON.stringify(input))
}
