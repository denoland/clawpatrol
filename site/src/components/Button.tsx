import type { ComponentChildren, JSX } from "preact";

type Variant = "normal" | "outline";
type Size = "sm" | "md" | "lg";

type CommonProps = {
  variant?: Variant;
  size?: Size;
  class?: string;
  children?: ComponentChildren;
};

type AnchorProps = CommonProps &
  Omit<JSX.HTMLAttributes<HTMLAnchorElement>, "size"> & { href: string };

type ButtonElProps = CommonProps &
  Omit<JSX.HTMLAttributes<HTMLButtonElement>, "size"> & { href?: undefined };

type ButtonProps = AnchorProps | ButtonElProps;

const base =
  "group inline-block font-sans font-semibold uppercase relative isolate z-10 " +
  "tracking-wider border cursor-pointer transition-colors outline-2 outline-navy " +
  "-outline-offset-2 disabled:opacity-50 disabled:cursor-not-allowed";

const sizes: Record<Size, string> = {
  sm: "px-2 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-7 py-3.5 text-base",
};

const variants: Record<Variant, string> = {
  normal: "border-2 border-navy text-navy relative",
  outline: "border-2 border-navy text-text-muted " + "hover:bg-canvas-muted",
};

function Background() {
  return (
    <div class="w-[calc(100%+4px)] h-[calc(100%+4px)] absolute left-1 top-1 bg-rust -z-10 group-hover:bg-rust-300 transition-colors duration-150" />
  );
}

export function Button(props: ButtonProps) {
  const { variant = "normal", size = "md", class: className, children } = props;
  const cls = `${base} ${sizes[size]} ${variants[variant]} ${className ?? ""}`;

  if ("href" in props && props.href !== undefined) {
    const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
    return (
      <a class={cls} {...rest}>
        {children}
        {variants.normal && <Background />}
      </a>
    );
  }

  const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
  return (
    <button type="button" class={cls} {...rest}>
      {children}
      <Background />
      {variants.normal && <Background />}
    </button>
  );
}
