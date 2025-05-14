import type { MarkdownNinjaData } from "./app/mdninja";

declare global {
  interface Window {
    chrome?: any;
    __markdown_ninja_data?: MarkdownNinjaData | null;
    __markdown_ninja_error?: string;
  }
}
