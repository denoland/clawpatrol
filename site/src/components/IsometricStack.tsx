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
// Four semi-transparent vertical wall panels enclose the clusters
// above and below CP: a V-shaped pair rising from CP's back edges
// (W-N and N-E) over the top cluster, and a mirrored pair dropping
// from CP's front edges (W-S and S-E) below it. Drawn at the back
// of the SVG so tiles and CP cover them where they overlap — the
// visible portions read as a faint 3D box framing the stack.

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
} & Fill;

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
    iconSrc: "/icons/claude.svg",
    cx: 0, // NW slot — raised highest
    cy: -290,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
  {
    alt: "ChatGPT",
    iconSrc: "/icons/openai.svg",
    cx: 65, // NE slot
    cy: -170,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
  {
    alt: "Gemini",
    iconSrc: "/icons/gemini.svg",
    cx: -65, // SW slot
    cy: -210,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
  {
    alt: "OpenClaw",
    iconSrc: "/icons/openclaw.svg",
    cx: 0, // SE slot — raised least, sits just above CP
    cy: -90,
    W: SMALL_W,
    D: SMALL_D,
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
    ...CANVAS_FILL,
  },
  {
    alt: "GitHub",
    iconSrc: "/icons/github.svg",
    cx: -65, // SW slot
    cy: 180,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
  {
    alt: "Slack",
    iconSrc: "/icons/slack.svg",
    cx: 65, // NE slot
    cy: 215,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
  {
    alt: "Notion",
    iconSrc: "/icons/notion.svg",
    cx: 0, // NW slot — lowered most
    cy: 290,
    W: SMALL_W,
    D: SMALL_D,
    ...CANVAS_FILL,
  },
];

// Painter's algorithm — in iso view the camera is above-and-front,
// so raised tiles (small cy) are closer to the viewer than CP, and
// lowered tiles (large cy) are further away. Paint back-to-front:
// bottom cluster, then CP, then top cluster.
const SORTED = [...TILES].sort((a, b) => b.cy - a.cy);
const BOTTOM_CLUSTER = SORTED.filter((t) => t.cy > 0);
const CP_TILE = SORTED.find((t) => t.alt === "Claw Patrol")!;
const TOP_CLUSTER = SORTED.filter((t) => t.cy < 0);

// ViewBox extent — derived from every tile's bounding box. The
// vertical bounds are padded by WALL_OVERHANG so the back/front
// wall apexes (which always land at yMin/yMax in screen space)
// extend a touch past the highest top tile and the lowest bottom
// tile, framing them.
const WALL_OVERHANG = 100;
const xMin = Math.min(...TILES.map((t) => t.cx - t.W)) - 2;
const xMax = Math.max(...TILES.map((t) => t.cx + t.W)) + 2;
const yMin = Math.min(...TILES.map((t) => t.cy - t.W / 2)) - WALL_OVERHANG;
const yMax =
  Math.max(...TILES.map((t) => t.cy + t.W / 2 + t.D)) + WALL_OVERHANG;
const TOTAL_W = xMax - xMin;
const TOTAL_H = yMax - yMin;

// Wall heights — the apex of each V (where the two walls meet at
// the N or S column) lands exactly at the viewBox edge.
const TOP_WALL_H = -yMin - BIG_W / 2;
const BOT_WALL_H = yMax - BIG_W / 2;

export function IsometricStack({ class: cls = "" }: { class?: string }) {
  return (
    <svg
      role="img"
      aria-label="Cluster of isometric panels: four AI agents above Claw Patrol, four downstream tools below it"
      viewBox={`${xMin} ${yMin} ${TOTAL_W} ${TOTAL_H}`}
      class={`block -my-24 ${cls}`}
    >
      {/* Two back walls — vertical 3D planes that contain CP's
          W-N and N-E top-face edges, extended both up (over the
          top cluster) and down (through CP into the bottom
          cluster). Each gradient peaks opaque near CP and fades
          toward both the top and bottom apex of the wall. Color
          per wall is for visual ID — unify later. */}
      <defs>
        {/* Back walls share a darker navy, front walls share a
            lighter step — two shades total, suggesting the back of
            the box recedes into shadow. Each gradient peaks at the
            CP midline (~y=0) and fades to nearly transparent at
            both apexes. */}
        <linearGradient
          id="wallBackLeft"
          x1="0"
          y1={yMin}
          x2="0"
          y2={yMax}
          gradientUnits="userSpaceOnUse"
        >
          <stop
            offset="0%"
            stop-color="var(--color-navy-100)"
            stop-opacity="0"
          />
          <stop
            offset="50%"
            stop-color="var(--color-navy-100)"
            stop-opacity="0.18"
          />
          <stop
            offset="100%"
            stop-color="var(--color-navy-100)"
            stop-opacity="0"
          />
        </linearGradient>
        <linearGradient
          id="wallBackRight"
          x1="0"
          y1={yMin}
          x2="0"
          y2={yMax}
          gradientUnits="userSpaceOnUse"
        >
          <stop
            offset="0%"
            stop-color="var(--color-navy-300)"
            stop-opacity="0"
          />
          <stop
            offset="50%"
            stop-color="var(--color-navy-300)"
            stop-opacity="0.18"
          />
          <stop
            offset="100%"
            stop-color="var(--color-navy-300)"
            stop-opacity="0"
          />
        </linearGradient>
        <linearGradient
          id="wallFrontLeft"
          x1="0"
          y1={yMin}
          x2="0"
          y2={yMax}
          gradientUnits="userSpaceOnUse"
        >
          <stop
            offset="0%"
            stop-color="var(--color-navy-50)"
            stop-opacity="0"
          />
          <stop
            offset="50%"
            stop-color="var(--color-navy-50)"
            stop-opacity="0.18"
          />
          <stop
            offset="100%"
            stop-color="var(--color-navy-50)"
            stop-opacity="0"
          />
        </linearGradient>
        <linearGradient
          id="wallFrontRight"
          x1="0"
          y1={yMin}
          x2="0"
          y2={yMax}
          gradientUnits="userSpaceOnUse"
        >
          <stop
            offset="0%"
            stop-color="var(--color-navy-200)"
            stop-opacity="0"
          />
          <stop
            offset="50%"
            stop-color="var(--color-navy-200)"
            stop-opacity="0.18"
          />
          <stop
            offset="100%"
            stop-color="var(--color-navy-200)"
            stop-opacity="0"
          />
        </linearGradient>
      </defs>
      {/* Back walls — two big parallelograms along CP's back-left
          (W-N) and back-right (N-E) edges, extending the full
          height of the viewBox (up to enclose the top cluster,
          down through CP into the bottom cluster). Drawn first,
          behind everything. */}
      <g aria-hidden="true">
        {/* Back-left wall (3D plane at x=-65), full vertical extent */}
        <polygon
          fill="url(#wallBackLeft)"
          points={`0,${
            -BIG_W / 2 - TOP_WALL_H
          } ${-BIG_W},${-TOP_WALL_H} ${-BIG_W},${BOT_WALL_H} 0,${
            -BIG_W / 2 + BOT_WALL_H
          }`}
        />
        {/* Back-right wall (3D plane at y=-65), full vertical extent */}
        <polygon
          fill="url(#wallBackRight)"
          points={`0,${
            -BIG_W / 2 - TOP_WALL_H
          } ${BIG_W},${-TOP_WALL_H} ${BIG_W},${BOT_WALL_H} 0,${
            -BIG_W / 2 + BOT_WALL_H
          }`}
        />
      </g>

      {/* Bottom cluster — drawn after back walls so the tiles
          appear in front of the walls. */}
      {BOTTOM_CLUSTER.map((t) => (
        <Tile key={t.alt} tile={t} />
      ))}

      <Tile tile={CP_TILE} />

      {/* Top cluster — drawn before front walls. */}
      {TOP_CLUSTER.map((t) => (
        <Tile key={t.alt} tile={t} />
      ))}

      {/* Front walls — two big parallelograms along CP's front-left
          (W-S) and front-right (S-E) edges, full vertical extent.
          Drawn last so they wash over every tile from in front. */}
      <g aria-hidden="true">
        {/* Front-left wall (3D plane at y=65), full vertical extent */}
        <polygon
          fill="url(#wallFrontLeft)"
          points={`${-BIG_W},${-TOP_WALL_H} 0,${BIG_W / 2 - TOP_WALL_H} 0,${
            BIG_W / 2 + BOT_WALL_H
          } ${-BIG_W},${BOT_WALL_H}`}
        />
        {/* Front-right wall (3D plane at x=65), full vertical extent */}
        <polygon
          fill="url(#wallFrontRight)"
          points={`${BIG_W},${-TOP_WALL_H} 0,${BIG_W / 2 - TOP_WALL_H} 0,${
            BIG_W / 2 + BOT_WALL_H
          } ${BIG_W},${BOT_WALL_H}`}
        />
      </g>
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
