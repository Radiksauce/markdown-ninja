import type { InitData } from "./api/model";

declare global {
  interface Window {
    chrome?: any;
    __markdown_ninja_init_data?: InitData | null;
    __markdown_ninja_error?: string;
  }
}
