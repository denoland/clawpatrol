# Site (Landing Page)

## Code style

- **Prefer Tailwind classes over inline `style` attributes.** Use arbitrary values (`text-[#fca5a5]`, `left-[73%]`, `top-[calc(2*1.6em)]`) when no standard utility exists. Only use inline `style` for values that genuinely can't be expressed as Tailwind classes (e.g., complex multi-value `text-shadow`, `background-image` with gradients/`color-mix()`).
