// Nine isometric tiles: the central Claw Patrol tile, with four
// small "AI agent" tiles raised directly above its four quadrants,
// and four small "tooling" tiles lowered below them. Each small
// tile is exactly 1/4 the linear size of the big tile, sitting at
// one of CP's four quadrant slot positions — visually, as if you
// took the big tile, sliced it into four sub-rhombi tiling its top
// face, and lifted (or lowered) each one straight up by a different
// amount. Mirrors the FlowDiagram's top-to-bottom data path
// (agents → CP → tools).
//
// CP top face is a rhombus with W=130. The four sub-rhombus centers
// are at (0, -32.5), (65, 0), (-65, 0), (0, 32.5) — those are the
// cx values used for each small tile, regardless of cy.
//
// Tiles render painter-order (back-to-front by screen y) so any
// overlap z-stacks correctly. Static for now; animation is planned.

type Fill = {
  topFill: string;
  rightFill: string;
  leftFill: string;
  border: string;
};

const CANVAS_FILL: Fill = {
  topFill: "var(--color-canvas)",
  rightFill: "var(--color-canvas-300)",
  leftFill: "var(--color-canvas-200)",
  border: "var(--color-navy-200)",
};

const NAVY_FILL: Fill = {
  topFill: "var(--color-navy-100)",
  rightFill: "var(--color-navy-300)",
  leftFill: "var(--color-navy-200)",
  border: "var(--color-navy)",
};

const BIG_W = 130;
const BIG_D = 22;
// Small tiles are exactly 1/4 the linear size of the big tile, so
// four of them tile the big tile's top face when at z=0 height.
const SMALL_W = BIG_W / 2;
const SMALL_D = BIG_D / 2;

type Tile = {
  alt: string;
  iconSrc: string;
  cx: number;
  cy: number;
  W: number;
  D: number;
  // (x, y) on CP's top face where this tile's tether line lands.
  // Omit on CP itself; required on every small tile.
  anchor?: [number, number];
} & Fill;

// Slot anchor positions on CP's top face — the centers of its four
// sub-rhombi. Each small tile tethers down (or up) to one of these.
const NW: [number, number] = [0, -32.5];
const NE: [number, number] = [65, 0];
const SW: [number, number] = [-65, 0];
const SE: [number, number] = [0, 32.5];

// AI cluster on top: back row (further from CP) higher up in screen,
// front row (closer to CP) just above it. Each tile's cx and cy is
// nudged a few px off a perfect 2x2 grid so the cluster feels
// organic rather than gridded.
// Tooling cluster on the bottom mirrors this vertically.
const TILES: Tile[] = [
  // Top cluster — AI agents. Each tile sits over one of CP's four
  // sub-rhombus slots (NW=cx 0, NE=cx 65, SW=cx -65, SE=cx 0),
  // raised straight up by a staggered amount.
  {
    alt: "Claude",
    iconSrc: "/icons/anthropic.svg",
    cx: 0, // NW slot — raised highest
    cy: -290,
    W: SMALL_W,
    D: SMALL_D,
    anchor: NW,
    ...CANVAS_FILL,
  },
  {
    alt: "ChatGPT",
    iconSrc: "/icons/openai.svg",
    cx: 65, // NE slot
    cy: -170,
    W: SMALL_W,
    D: SMALL_D,
    anchor: NE,
    ...CANVAS_FILL,
  },
  {
    alt: "Gemini",
    iconSrc: "/icons/gemini.svg",
    cx: -65, // SW slot
    cy: -220,
    W: SMALL_W,
    D: SMALL_D,
    anchor: SW,
    ...CANVAS_FILL,
  },
  {
    alt: "OpenClaw",
    iconSrc: "/icons/openclaw.svg",
    cx: 0, // SE slot — raised least, sits just above CP
    cy: -95,
    W: SMALL_W,
    D: SMALL_D,
    anchor: SE,
    ...CANVAS_FILL,
  },
  // Middle — Claw Patrol (the big tile)
  {
    alt: "Claw Patrol",
    iconSrc: "/claw-patrol-icon.svg",
    cx: 0,
    cy: 0,
    W: BIG_W,
    D: BIG_D,
    ...NAVY_FILL,
  },
  // Bottom cluster — downstream tooling. Same four quadrant slots
  // as the top cluster, but lowered straight down by staggered
  // amounts (asymmetric clearance vs top because CP's depth D
  // extends downward from its top face).
  {
    alt: "Postgres",
    iconSrc: "/icons/postgres.svg",
    cx: 0, // SE slot — lowered least, sits just below CP
    cy: 110,
    W: SMALL_W,
    D: SMALL_D,
    anchor: SE,
    ...CANVAS_FILL,
  },
  {
    alt: "GitHub",
    iconSrc: "/icons/github.svg",
    cx: -65, // SW slot
    cy: 175,
    W: SMALL_W,
    D: SMALL_D,
    anchor: SW,
    ...CANVAS_FILL,
  },
  {
    alt: "Slack",
    iconSrc: "/icons/slack.svg",
    cx: 65, // NE slot
    cy: 215,
    W: SMALL_W,
    D: SMALL_D,
    anchor: NE,
    ...CANVAS_FILL,
  },
  {
    alt: "Notion",
    iconSrc: "/icons/notion.svg",
    cx: 0, // NW slot — lowered most
    cy: 290,
    W: SMALL_W,
    D: SMALL_D,
    anchor: NW,
    ...CANVAS_FILL,
  },
];

// Painter's algorithm — in iso view the camera is above-and-front,
// so raised tiles (small cy) are closer to the viewer than CP, and
// lowered tiles (large cy) are further away. Top-cluster tether
// lines paint AFTER CP so they're visible landing on CP's top face,
// terminating at the slot anchor. Bottom-cluster tether lines paint
// BEFORE CP so CP covers their on-face portion — visually each
// bottom line drops from CP's edge and goes down to its tile.
const SORTED = [...TILES].sort((a, b) => b.cy - a.cy);
const BOTTOM_CLUSTER = SORTED.filter((t) => t.cy > 0);
const CP_TILE = SORTED.find((t) => t.alt === "Claw Patrol")!;
const TOP_CLUSTER = SORTED.filter((t) => t.cy < 0);
const TOP_LINES = TILES.filter((t) => t.cy < 0 && t.anchor);
const BOTTOM_LINES = TILES.filter((t) => t.cy > 0 && t.anchor);

// For a small tile's tether, return the (x, y) point where the line
// should visibly end. Default = the tile's slot anchor on CP.
//
// Top cluster: if another top tile sits in the same cx column
// between this tile and CP, the line stops at that occluder's top
// vertex. The occluder paints on top of the line anyway (top tiles
// render last), so this just avoids the line reappearing on CP
// below the occluder and overlapping the occluder's own tether.
//
// Bottom cluster: never truncates — bottom-cluster lines render on
// top of bottom tiles, so the line crossing an in-column tile reads
// as the line lying on that tile's face, in front of it.
function tetherEnd(tile: Tile): [number, number] {
  if (tile.cy > 0) return tile.anchor!;
  const between = TOP_CLUSTER.filter((o) =>
    o !== tile && o.cx === tile.cx && o.cy > tile.cy
  );
  if (between.length === 0) return tile.anchor!;
  const nearest = between.reduce((min, o) => (o.cy < min.cy ? o : min));
  return [tile.cx, nearest.cy - nearest.W / 2];
}

// ViewBox extent — derived from every tile's bounding box so the
// SVG hugs the cluster without manual fiddling when positions move.
const xMin = Math.min(...TILES.map((t) => t.cx - t.W)) - 2;
const xMax = Math.max(...TILES.map((t) => t.cx + t.W)) + 2;
const yMin = Math.min(...TILES.map((t) => t.cy - t.W / 2)) - 2;
const yMax = Math.max(...TILES.map((t) => t.cy + t.W / 2 + t.D)) + 2;
const TOTAL_W = xMax - xMin;
const TOTAL_H = yMax - yMin;

export function IsometricStack({ class: cls = "" }: { class?: string }) {
  return (
    <svg
      role="img"
      aria-label="Cluster of isometric panels: four AI agents above Claw Patrol, four downstream tools below it"
      viewBox={`${xMin} ${yMin} ${TOTAL_W} ${TOTAL_H}`}
      class={`block ${cls}`}
    >
      {/* Bottom cluster — drawn first (furthest from camera). */}
      {BOTTOM_CLUSTER.map((t) => <Tile key={t.alt} tile={t} />)}

      {
        /* Bottom-cluster tether lines drawn BEFORE CP. Start slightly
          inside the tile's top face (cy - W/4) so the line reads as
          emerging from the face rather than from the back corner;
          the on-CP portion is hidden by CP, so the visible segment
          runs from the tile face up to CP's bottom-front edge. */
      }
      <g
        stroke="var(--color-navy-200)"
        stroke-width="1.5"
        stroke-dasharray="1 3"
        stroke-linecap="round"
        fill="none"
        aria-hidden="true"
      >
        {BOTTOM_LINES.map((t) => {
          const [endX, endY] = tetherEnd(t);
          return (
            <line
              key={`bot-tether-${t.alt}`}
              x1={t.cx}
              y1={t.cy - t.W / 4}
              x2={endX}
              y2={endY}
            />
          );
        })}
      </g>

      {/* CP — covers the on-face end of bottom-cluster tethers. */}
      <Tile tile={CP_TILE} />

      {
        /* Top-cluster tether lines drawn AFTER CP so they appear on
          CP's top face, terminating at the slot anchor. Start at
          the tile's center — the inside-tile portion gets hidden by
          the top tile (drawn next), so the line visually emerges
          from the tile's bottom-front edge. */
      }
      <g
        stroke="var(--color-navy-200)"
        stroke-width="1.5"
        stroke-dasharray="1 3"
        stroke-linecap="round"
        fill="none"
        aria-hidden="true"
      >
        {TOP_LINES.map((t) => {
          const [endX, endY] = tetherEnd(t);
          return (
            <line
              key={`top-tether-${t.alt}`}
              x1={t.cx}
              y1={t.cy}
              x2={endX}
              y2={endY}
            />
          );
        })}
      </g>

      {
        /* Top cluster — drawn last so raised tiles sit in front of
          CP and cover their own tether lines' inside-tile portion. */
      }
      {TOP_CLUSTER.map((t) => <Tile key={t.alt} tile={t} />)}
    </svg>
  );
}

function Tile({ tile }: { tile: Tile }) {
  const { cx, cy, W, D } = tile;

  // Top-face rhombus vertices in screen space.
  const yTop = cy - W / 2;
  const top = `${cx},${yTop}`;
  const right = `${cx + W},${yTop + W / 2}`;
  const bottom = `${cx},${yTop + W}`;
  const left = `${cx - W},${yTop + W / 2}`;

  // Bottom-edge counterparts (offset by depth D).
  const rightB = `${cx + W},${yTop + W / 2 + D}`;
  const bottomB = `${cx},${yTop + W + D}`;
  const leftB = `${cx - W},${yTop + W / 2 + D}`;

  // Logo lies flat on the top face, rotated 90° on the surface so
  // its bottom edge faces the lower-right corner of the rhombus.
  // Image X-axis → screen (1, -0.5); image Y-axis → screen (1, 0.5).
  // Translation puts the logo's center at (cx, cy).
  const iconSize = W * 0.66;
  const e = cx - iconSize;
  const f = cy;
  const iconTransform = `matrix(1 -0.5 1 0.5 ${e} ${f})`;

  return (
    <g>
      <polygon
        points={`${left} ${leftB} ${bottomB} ${bottom}`}
        fill={tile.leftFill}
        stroke={tile.border}
        stroke-width="1"
        stroke-linejoin="round"
      />
      <polygon
        points={`${right} ${rightB} ${bottomB} ${bottom}`}
        fill={tile.rightFill}
        stroke={tile.border}
        stroke-width="1"
        stroke-linejoin="round"
      />
      <polygon
        points={`${top} ${right} ${bottom} ${left}`}
        fill={tile.topFill}
        stroke={tile.border}
        stroke-width="1"
        stroke-linejoin="round"
      />
      <image
        href={tile.iconSrc}
        x={0}
        y={0}
        width={iconSize}
        height={iconSize}
        transform={iconTransform}
      />
    </g>
  );
}
