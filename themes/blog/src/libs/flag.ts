// offset between uppercase ascii and regional indicator symbols
const OFFSET = 127397;


// see https://github.com/thekelvinliu/country-code-emoji/blob/main/src/index.js
// https://flagcdn.com/pr.svg
// https://github.com/WillowHayward/unicode-flag-finder/blob/master/flags.ts
// https://github.com/risan/country-flag-emoji
// https://restcountries.com/v3.1/all
// https://github.com/apilayer/restcountries
export function getCountryFlag(countryCode: String): string {
  if (countryCode === "XX") {
    return '';
  }
  const codePoints = [...countryCode.toUpperCase()].map(c => c.codePointAt(0)! + OFFSET);
  return String.fromCodePoint(...codePoints);
}
