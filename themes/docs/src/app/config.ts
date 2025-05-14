let config: Config | null = null;

export function createConfig(): Config {
  config = new Config();
  return config;
}

export function useConfig(): Config {
  if (!config) {
    throw new Error('Config should be created before using it');
  }
  return config!;
}

/* eslint-disable @typescript-eslint/no-non-null-assertion */
export class Config {
  env: string;

  constructor() {
    this.env = import.meta.env.VITE_ENV as string | undefined ?? 'production';
  }
}
