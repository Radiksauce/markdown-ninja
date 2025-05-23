// from https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/nprogress/index.d.ts
declare namespace nProgress {
  interface NProgressOptions {
      minimum: number;
      template: string;
      easing: string;
      speed: number;
      trickle: boolean;
      trickleSpeed: number;
      showSpinner: boolean;
      parent: string;
      positionUsing: string;
      barSelector: string;
      spinnerSelector: string;
  }

  interface NProgress {
      version: string;
      settings: NProgressOptions;
      status: number | null;

      configure(options: Partial<NProgressOptions>): NProgress;
      set(number: number): NProgress;
      isStarted(): boolean;
      start(): NProgress;
      done(force?: boolean): NProgress;
      inc(amount?: number): NProgress;
      trickle(): NProgress;

      /* Internal */

      render(fromStart?: boolean): HTMLDivElement;
      remove(): void;
      isRendered(): boolean;
      getPositioningCSS(): "translate3d" | "translate" | "margin";
  }
}

declare const nProgress: nProgress.NProgress;
export = nProgress;
