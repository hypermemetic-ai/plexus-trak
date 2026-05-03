# TRAK-UI: Frontend Application

## Stack

- **Runtime**: Bun
- **Framework**: SolidJS (fine-grained reactivity, best for canvas + streaming)
- **Canvas**: raw Canvas 2D API + custom renderer (no heavy lib)
- **Styling**: vanilla CSS / CSS modules (no tailwind dep)

## Architecture: Framework-Agnostic Core

```
packages/
├── @trak/core/              # pure TS — zero framework deps
│   ├── client.ts            # wraps generated Plexus client
│   ├── store.ts             # reactive state (facet cache, navigation, auth)
│   ├── auth.ts              # JWT lifecycle (login, refresh, persist)
│   ├── tree.ts              # tree data structures + traversal
│   ├── graph.ts             # graph layout algorithms (force, dagre)
│   └── types.ts             # re-export generated types + app-level types
│
├── @trak/canvas/            # pure TS — canvas rendering primitives
│   ├── renderer.ts          # Canvas2D scene graph (nodes, edges, labels)
│   ├── layout/
│   │   ├── tree.ts          # indented outline layout
│   │   ├── force.ts         # force-directed graph layout
│   │   └── board.ts         # kanban column layout
│   ├── interaction.ts       # pan, zoom, click, drag, hover
│   └── theme.ts             # colors, fonts, spacing tokens
│
├── @trak/solid/             # SolidJS bindings (thin)
│   ├── providers.ts         # TrakProvider (context)
│   ├── hooks.ts             # useFacets, useTree, useGraph, useAuth
│   ├── components/
│   │   ├── Canvas.tsx       # <TrakCanvas> — mounts renderer
│   │   ├── Breadcrumbs.tsx
│   │   ├── SearchBar.tsx
│   │   ├── DetailPanel.tsx
│   │   ├── CreateDialog.tsx
│   │   └── ViewSwitcher.tsx
│   └── App.tsx              # shell
│
└── apps/
    └── trak-ui/             # the actual app (thin)
        ├── index.html
        ├── index.tsx         # mount SolidJS app
        ├── synapse.config.json
        └── package.json
```

The rule: **@trak/core and @trak/canvas have zero framework imports.**
They're pure TypeScript. You can plug them into React, Svelte, Vue,
or a terminal renderer. SolidJS is the first binding.

## Bootstrap

```bash
# 1. Create the project
mkdir trak-ui && cd trak-ui
bun init

# 2. Install deps
bun add solid-js
bun add -d vite vite-plugin-solid typescript

# 3. Generate client (trak must be running on 44107)
synapse-cc build typescript trak ws://localhost:44107 --output src/lib/trak

# 4. Configure codegen
cat > synapse.config.json << 'EOF'
{
  "schema": "1.0",
  "language": "typescript",
  "targets": {
    "client": {
      "generate": ["transport", "rpc", "plugins"],
      "transport": "browser",
      "outputDir": "src/lib/trak"
    }
  },
  "backends": {
    "trak": {
      "url": "ws://localhost:44107"
    }
  }
}
EOF
```

## Build pipeline

```json
// package.json
{
  "scripts": {
    "codegen": "synapse-cc build",
    "dev": "bun run codegen && vite",
    "build": "bun run codegen && vite build",
    "preview": "vite preview"
  }
}
```

`bun run dev` → regenerates client (cached, <100ms if schema unchanged) → starts vite.
Schema change on backend → next `bun run dev` regenerates types → TypeScript catches breakage.

## @trak/core — The Portable Brain

### client.ts
```typescript
import { PlexusRpcClient } from '../lib/trak/transport'
import { createFacetClient } from '../lib/trak/facet/client'
import { createIdentityClient } from '../lib/trak/identity/client'

export interface TrakConnection {
  facet: FacetClient
  identity: IdentityClient
  rpc: PlexusRpcClient
  disconnect(): void
}

export function connect(url: string, token?: string): TrakConnection {
  const rpc = new PlexusRpcClient({ backend: 'trak', url, token })
  return {
    facet: createFacetClient(rpc),
    identity: createIdentityClient(rpc),
    rpc,
    disconnect: () => rpc.close(),
  }
}
```

### store.ts
```typescript
// Framework-agnostic reactive store using the observer pattern.
// SolidJS, React, Svelte all wrap this with their own primitives.

export interface TrakStore {
  // Navigation
  currentId: string | null
  breadcrumbs: FacetMeta[]

  // Data cache (loaded on demand)
  children: Map<string, FacetSummary[]>
  details: Map<string, FacetDetail>
  edges: Map<string, EdgeDetail[]>

  // Auth
  token: string | null
  user: UserInfo | null

  // Actions
  navigate(id: string | null): Promise<void>
  refresh(): Promise<void>
  createFacet(opts: CreateOpts): Promise<string>
  updateStatus(id: string, status: string): Promise<void>
  link(from: string, to: string, kind: string): Promise<void>
  login(username: string, password: string): Promise<void>
  logout(): void
}

export function createStore(conn: TrakConnection): TrakStore { ... }
```

### tree.ts
```typescript
// Pure data structures for tree rendering.
// Input: flat list of FacetSummary with parent_id.
// Output: nested tree nodes with computed depth, expanded state.

export interface TreeNode {
  id: string
  title: string
  status: string
  depth: number
  childCount: number
  expanded: boolean
  children: TreeNode[]
  y: number          // computed vertical position for canvas
}

export function buildTree(facets: FacetSummary[], expandedSet: Set<string>): TreeNode[]
export function flattenTree(roots: TreeNode[]): TreeNode[]  // for canvas rendering
export function toggleExpand(tree: TreeNode[], id: string): TreeNode[]
```

### graph.ts
```typescript
// Pure layout algorithms. No DOM, no canvas — just coordinates.

export interface GraphNode {
  id: string
  x: number
  y: number
  title: string
  status: string
}

export interface GraphEdge {
  from: string
  to: string
  kind: string
}

export interface GraphLayout {
  nodes: GraphNode[]
  edges: GraphEdge[]
  width: number
  height: number
}

// Force-directed layout (iterative)
export function forceLayout(nodes: GraphNode[], edges: GraphEdge[], iterations?: number): GraphLayout

// Layered DAG layout (like dagre, for dependency graphs)
export function layeredLayout(nodes: GraphNode[], edges: GraphEdge[]): GraphLayout
```

## @trak/canvas — The Renderer

### renderer.ts
```typescript
// Scene graph over Canvas 2D. Handles:
// - Drawing nodes (rounded rects with title + status badge)
// - Drawing edges (bezier curves with arrowheads)
// - Drawing tree indentation lines
// - Text rendering with truncation
// - Hit testing (which node did the user click?)

export class TrakRenderer {
  constructor(canvas: HTMLCanvasElement, theme: Theme)

  // Render modes
  renderTree(nodes: FlatTreeNode[]): void
  renderGraph(layout: GraphLayout): void
  renderBoard(columns: BoardColumn[]): void

  // Interaction
  hitTest(x: number, y: number): string | null  // returns facet ID
  setViewport(x: number, y: number, scale: number): void

  // Lifecycle
  resize(width: number, height: number): void
  destroy(): void
}
```

### interaction.ts
```typescript
// Pan, zoom, drag handlers. Pure — emits events, doesn't touch DOM.

export interface CanvasInteraction {
  onPan(dx: number, dy: number): void
  onZoom(delta: number, cx: number, cy: number): void
  onClick(x: number, y: number): string | null  // hit test → facet ID
  onDragStart(id: string): void
  onDragMove(x: number, y: number): void
  onDragEnd(): { id: string, target: string } | null  // drop target
}
```

## @trak/solid — The Thin Binding

### Canvas.tsx
```tsx
import { onMount, onCleanup, createEffect } from 'solid-js'
import { TrakRenderer } from '@trak/canvas'
import { useTrak } from './providers'

export function TrakCanvas() {
  let canvas: HTMLCanvasElement

  const { store, view } = useTrak()

  onMount(() => {
    const renderer = new TrakRenderer(canvas, defaultTheme)
    const observer = new ResizeObserver(([e]) =>
      renderer.resize(e.contentRect.width, e.contentRect.height))
    observer.observe(canvas)

    // SolidJS fine-grained reactivity: only re-renders when
    // the specific data for the current view changes
    createEffect(() => {
      if (view() === 'outliner') {
        renderer.renderTree(store.flatTree())
      } else if (view() === 'graph') {
        renderer.renderGraph(store.graphLayout())
      } else if (view() === 'board') {
        renderer.renderBoard(store.boardColumns())
      }
    })

    canvas.addEventListener('click', (e) => {
      const id = renderer.hitTest(e.offsetX, e.offsetY)
      if (id) store.navigate(id)
    })

    onCleanup(() => { renderer.destroy(); observer.disconnect() })
  })

  return <canvas ref={canvas!} style="width:100%;height:100%" />
}
```

That's the entire framework binding for the main view — 30 lines.
The renderer, layout, and data are all pure TS underneath.

---

## Tickets

### TRAK-UI-1: @trak/core scaffold + codegen wiring
- Bun + Vite + SolidJS project setup
- synapse.config.json
- `bun run codegen` in build pipeline
- client.ts (connect, disconnect)
- store.ts (skeleton with navigate, auth)
- types.ts (re-exports)

### TRAK-UI-2: Auth flow
- Login/register forms (SolidJS)
- JWT lifecycle in auth.ts (pure TS)
- localStorage persistence
- Auto-refresh on expiry
- AuthGate component

### TRAK-UI-3: @trak/canvas renderer
- Canvas 2D scene graph
- Node rendering (rounded rect, title, status badge)
- Edge rendering (bezier, arrowhead)
- Hit testing
- Viewport (pan, zoom)
- Theme tokens

### TRAK-UI-4: Outliner view
- tree.ts (pure TS: buildTree, flattenTree, toggleExpand)
- Tree layout in canvas renderer
- Breadcrumb navigation
- Expand/collapse interaction
- Inline status editing

### TRAK-UI-5: Detail panel
- Facet content (markdown rendered)
- Links list (in/out by kind)
- Create/remove links
- Stub sections for comments, history, refs

### TRAK-UI-6: Board view
- board.ts layout (pure TS)
- Kanban columns from status values
- Drag-and-drop status change
- Scoped to current facet's children

### TRAK-UI-7: Graph view
- graph.ts layout algorithms (force + layered DAG)
- Graph rendering in canvas
- Edge kind filtering
- Click to navigate

### TRAK-UI-8: Search + create
- Search bar → facet.search
- Create dialog (title, body, parent, status)
- Markdown editor for body
