declare module "asciinema-player" {
  export type Player = {
    el: HTMLElement;
    dispose: () => void;
    getCurrentTime: () => Promise<number>;
    getDuration: () => Promise<number>;
    play: () => Promise<void>;
    pause: () => Promise<void>;
    seek: (pos: number) => Promise<void>;
    addEventListener: (name: string, callback: () => void) => unknown;
  };

  export type Options = Record<string, unknown>;

  export function create(
    src: string,
    elem: HTMLElement,
    opts?: Options,
  ): Player;
}
