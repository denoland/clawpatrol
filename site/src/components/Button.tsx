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
  "group inline-block font-mono font-semibold uppercase relative isolate z-10 " +
  "tracking-wider cursor-pointer transition-colors outline-1.5 outline-navy " +
  "-outline-offset-1.5 disabled:opacity-50 disabled:cursor-not-allowed";

const sizes: Record<Size, string> = {
  sm: "px-2 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-7 py-3.5 text-base",
};

const variants: Record<Variant, string> = {
  normal: " text-navy relative",
  outline: " text-text-muted " + "hover:bg-canvas-muted",
};

const backgroundOffsets: Record<Size, string> = {
  sm: "w-[calc(100%+3px)] h-[calc(100%+3px)] left-[1px] top-[1px]",
  md: "w-[calc(100%+3px)] h-[calc(100%+3px)] left-[2px] top-[2px]",
  lg: "w-[calc(100%+2px)] h-[calc(100%+3px)] left-[3px] top-[3px]",
};

function Background({ size = "md" }: { size?: Size }) {
  return (
    <div
      class={`${backgroundOffsets[size]} absolute bg-linear-to-r from-rust-300 to-rust-400 -z-10 group-hover:from-butter group-hover:to-rust-300 transition-colors duration-150`}
    />
  );
}

export function Button(props: ButtonProps) {
  const { variant = "normal", size = "md", class: className, children } = props;
  const cls = `${base} ${sizes[size]} ${variants[variant]} ${className ?? ""}`;
  const showBackground = variant === "normal";

  if ("href" in props && props.href !== undefined) {
    const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
    return (
      <a class={cls} {...rest}>
        {children}
        {showBackground && <Background size={size} />}
      </a>
    );
  }

  const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
  return (
    <button type="button" class={cls} {...rest}>
      {children}
      {showBackground && <Background size={size} />}
    </button>
  );
}
