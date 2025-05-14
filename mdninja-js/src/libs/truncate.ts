export default function truncate(str: string, n = 80){
  return (str.length > n) ? str.slice(0, n-1) + '...' : str;
}
