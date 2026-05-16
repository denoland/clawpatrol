// Single source of truth for the hero H1 and the page <title>.
// HeroSection imports HERO_H1; vite.config.ts uses SITE_TITLE in a
// transformIndexHtml hook, and docs-render.ts uses SITE_TITLE for the
// prerender meta tags. Change here, both surfaces update.

export const HERO_H1 = "Security proxy for agents";
export const SITE_TITLE = `Claw Patrol - ${HERO_H1}`;
