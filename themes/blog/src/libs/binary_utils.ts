export function base64ToUint8Array(input: string): Uint8Array {
  return Uint8Array.from(atob(input), (char) => char.charCodeAt(0));
}

export function uint8ArrayToString(input: Uint8Array): string {
  return new TextDecoder().decode(input);
}
