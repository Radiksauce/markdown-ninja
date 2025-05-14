// see https://dockyard.com/blog/2020/02/14/you-probably-don-t-need-moment-js-anymore
// and https://github.com/you-dont-need/You-Dont-Need-Momentjs
// and https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Intl/DateTimeFormat
export default function date(text: string, time = true) {
  const date = new Date(text);
  const options: Intl.DateTimeFormatOptions = {
    year: "numeric",
    month: "long",
    day: "numeric",
  };
  if (time) {
    options.hour = "numeric";
    options.minute = "numeric";
    options.hour12 = false;
  }
  /* @ts-ignore */
  return new Intl.DateTimeFormat("en", options).format(date)
}
