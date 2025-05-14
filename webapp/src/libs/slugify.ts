/// <reference lib="es2021" />

export function slugify(input: string): string {
  let output = input.toLowerCase();
  output = output.replaceAll(' ', '-');
  output = output.replaceAll('.', '-');
  output = output.replaceAll('_', '-');
  output = output.replaceAll('--', '-');
  output = output.trim();
  return output;
}
