export function oneRouteUp(path: string): string {
  const upperPath = path.split("/")

  if(upperPath.length > 0) {
    upperPath.splice(upperPath.length-1)
    return upperPath.join("/");
  }

  return path;
}
