import type { AnchorHTMLAttributes, ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "normal" | "outline";
type Size = "xs" | "sm" | "md" | "lg";

type CommonProps = {
  variant?: Variant;
  size?: Size;
  className?: string;
  children?: ReactNode;
};

type AnchorProps = CommonProps &
  Omit<AnchorHTMLAttributes<HTMLAnchorElement>, "size"> & { href: string };

type ButtonElProps = CommonProps &
  Omit<ButtonHTMLAttributes<HTMLButtonElement>, "size"> & { href?: undefined };

type ButtonProps = AnchorProps | ButtonElProps;

const base =
  "inline-block font-mono font-semibold uppercase tracking-wider cursor-pointer " +
  "transition-colors " +
  "disabled:cursor-not-allowed";

const sizes: Record<Size, string> = {
  xs: "px-2 py-0.5 text-xs",
  sm: "px-2 py-1 text-xs",
  md: "px-4 py-2 text-sm",
  lg: "px-7 py-3.5 text-base",
};

const variants: Record<Variant, string> = {
  normal:
    "border-1.5 border-navy bg-rust-400 text-navy hover:bg-rust-300 " +
    "disabled:bg-canvas-dark disabled:text-text-subtle " +
    "disabled:border-text-subtle disabled:outline-text-subtle " +
    "disabled:hover:bg-canvas-dark",
  outline:
    "border-1.5 border-navy text-current hover:bg-navy-200 " +
    "disabled:text-text-subtle " +
    "disabled:border-text-subtle disabled:outline-text-subtle " +
    "disabled:hover:bg-transparent",
};

export function Button(props: ButtonProps) {
  const { variant = "normal", size = "sm", className, children } = props;
  const cls = `${base} ${sizes[size]} ${variants[variant]} ${className ?? ""}`;

  if ("href" in props && props.href !== undefined) {
    const { variant: _v, size: _s, className: _c, children: _ch, ...rest } = props;
    return (
      <a className={cls} {...rest}>
        {children}
      </a>
    );
  }

  const { variant: _v, size: _s, className: _c, children: _ch, ...rest } = props;
  return (
    <button type="button" className={cls} {...rest}>
      {children}
    </button>
  );
}
