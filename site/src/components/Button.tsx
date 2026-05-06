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
  "inline-block font-sans font-semibold uppercase " +
  "tracking-wider border cursor-pointer transition-colors " +
  "disabled:opacity-50 disabled:cursor-not-allowed";

const sizes: Record<Size, string> = {
  sm: "px-2 py-1 text-sm",
  md: "px-4 py-2 text-base",
  lg: "px-7 py-3.5 text-base",
};

const variants: Record<Variant, string> = {
  normal:
    "border-2 border-navy text-navy " +
    "hover:bg-rust-300 bg-rust hover:border-rust-300 shadow-[5px_5px_0_0_var(--color-rust),inset_3px_3px_0_0_var(--color-canvas)]",
  outline: "border-text-muted text-text-muted " + "hover:bg-canvas-muted",
};

export function Button(props: ButtonProps) {
  const { variant = "normal", size = "md", class: className, children } = props;
  const cls = `${base} ${sizes[size]} ${variants[variant]} ${className ?? ""}`;

  if ("href" in props && props.href !== undefined) {
    const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
    return (
      <a class={cls} {...rest}>
        {children}
      </a>
    );
  }

  const { variant: _v, size: _s, class: _c, children: _ch, ...rest } = props;
  return (
    <button type="button" class={cls} {...rest}>
      {children}
    </button>
  );
}
