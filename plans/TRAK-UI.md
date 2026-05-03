# TRAK-UI: Frontend Application

## Bootstrap

### 1. Generate the TypeScript client

```bash
# From the trak-ui project root (after trak daemon is running on 44107):
synapse-cc build typescript trak ws://localhost:44107 --output src/lib/trak
```

This generates:
```
src/lib/trak/
├── index.ts              # barrel exports
├── types.ts              # PlexusStreamItem, PlexusError
├── rpc.ts                # RpcClient interface + extractData/collectOne helpers
├── transport.ts          # PlexusRpcClient (WebSocket JSON-RPC 2.0)
├── facet/
│   ├── client.ts         # typed FacetClient (create, get, list, tree, link, etc.)
│   └── types.ts          # Facet, FacetMeta, Edge, TrakEvent variants
├── identity/
│   ├── client.ts         # typed IdentityClient (register, login, refresh, me)
│   └── types.ts          # LoginSuccess, UserInfo, etc.
├── discuss/
│   ├── client.ts         # stub — methods return not_implemented
│   └── types.ts
├── audit/
├── access/
├── collab/
└── refs/
```

### 2. Create the project

```bash
# Scaffold with Vite + React/Vue/Svelte (or whatever framework)
npm create vite@latest trak-ui -- --template react-ts
cd trak-ui
npm install

# Generate client
synapse-cc build typescript trak ws://localhost:44107 --output src/lib/trak

# Add synapse config for repeatable builds
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
  },
  "watch": {
    "pollInterval": 1000,
    "hotReload": true
  }
}
EOF
```

### 3. Wire codegen into build

```json
// package.json
{
  "scripts": {
    "codegen": "synapse-cc build",
    "codegen:watch": "synapse-cc watch trak",
    "dev": "npm run codegen && vite",
    "build": "npm run codegen && tsc -b && vite build",
    "preview": "vite preview"
  }
}
```

Every `npm run dev` and `npm run build` regenerates the client first.
synapse-cc caches by schema hash — if the backend hasn't changed,
codegen returns in <100ms. If the backend schema changed (new methods,
new params), the client is regenerated automatically.

### 4. Use the generated client

```typescript
// src/lib/connection.ts
import { PlexusRpcClient } from './trak/transport'
import { createFacetClient } from './trak/facet/client'
import { createIdentityClient } from './trak/identity/client'

const rpc = new PlexusRpcClient({
  backend: 'trak',
  url: 'ws://localhost:44107',
})

export const facet = createFacetClient(rpc)
export const identity = createIdentityClient(rpc)
```

```typescript
// src/App.tsx — example usage
import { facet, identity } from './lib/connection'

// Login
const { accessToken } = await identity.login({
  username: 'ben',
  password: 'test123'
})
// Token is sent as cookie on the WebSocket connection

// Create a facet
const created = await facet.create({
  title: 'Ship trak-ui',
  status: 'open'
})

// List roots
for await (const item of facet.list({})) {
  console.log(item) // FacetSummary events
}

// Tree view
for await (const node of facet.tree({ id: rootId })) {
  console.log('  '.repeat(node.depth) + node.title)
}
```

---

## Application Architecture

### Views (all read from the same facet graph)

#### 1. Outliner (default view)
Expandable tree. Click to expand children. Breadcrumb navigation.
Each node shows: title, status badge, child count, link count.
Inline editing: click title to edit, dropdown for status.

#### 2. Board (kanban)
Columns = status values at current scope.
Cards = children of the focused facet.
Drag between columns = status change.
Click card = zoom into that facet (its children become new board).

#### 3. Graph (dependency view)
Force-directed or dagre layout.
Nodes = facets. Edges = typed links (color by kind).
Filter by link kind (depends_on only, blocks only, etc.).
Click node = detail panel.

#### 4. Detail panel (sidebar)
Shows: full facet content (body rendered as markdown),
links in/out, comments (from discuss), history (from audit),
external refs, fork info.

### Component tree

```
App
├── AuthGate              # login form / token management
├── Breadcrumbs           # current path in the tree
├── ViewSwitcher          # outliner / board / graph toggle
├── MainView
│   ├── OutlinerView      # recursive tree component
│   ├── BoardView         # kanban columns
│   └── GraphView         # d3/dagre dependency graph
├── DetailPanel           # sidebar for focused facet
│   ├── FacetContent      # title, body (markdown), status
│   ├── LinksList         # dependencies, blocks, relates-to
│   ├── CommentThread     # from discuss hub (stub shows empty)
│   ├── HistoryLog        # from audit hub (stub shows empty)
│   └── RefsList          # external references
├── SearchBar             # full-text search → facet.search
└── CreateDialog          # new facet form
```

### State management

```typescript
// Core state: just the current scope + cache
interface TrakState {
  // Navigation
  currentFacetId: string | null    // focused facet (null = root)
  breadcrumbs: FacetMeta[]         // ancestors of current

  // Data (loaded on demand)
  children: Map<string, FacetSummary[]>    // parent_id → children
  facetDetails: Map<string, FacetDetail>   // id → full detail
  edges: Map<string, EdgeDetail[]>         // id → links

  // UI
  view: 'outliner' | 'board' | 'graph'
  searchQuery: string
  searchResults: FacetMeta[]

  // Auth
  token: string | null
  user: UserInfo | null
}
```

No global store needed — just React context or Svelte stores.
Data loaded via the generated client, cached in Maps.

### Auth flow in the UI

```
1. App loads → check localStorage for saved JWT
2. If no JWT → show login form
3. Login form → identity.login(username, password) → save JWT
4. PlexusRpcClient sends JWT as cookie on WS upgrade
5. All subsequent calls are authenticated
6. On 401/token expired → identity.refresh(refreshToken) → update JWT
7. Logout → clear localStorage, disconnect WS
```

---

## Tickets

### TRAK-UI-1: Project scaffold + codegen wiring
- Vite + React (or Svelte) + TypeScript
- synapse.config.json
- `npm run codegen` in build pipeline
- Basic App shell with auth gate

### TRAK-UI-2: Auth flow
- Login/register forms
- JWT storage in localStorage
- Auto-refresh on expiry
- Connection management (reconnect on token change)

### TRAK-UI-3: Outliner view
- Recursive tree component
- Expand/collapse
- Breadcrumb navigation (click to zoom)
- Inline status editing
- Create child button

### TRAK-UI-4: Detail panel
- Full facet content (markdown rendering)
- Links list (in/out, grouped by kind)
- Create/remove links
- Stub sections for comments, history, refs

### TRAK-UI-5: Board view
- Kanban columns from status values
- Drag-and-drop status change
- Scoped to current facet's children

### TRAK-UI-6: Graph view
- d3-force or dagre layout
- Nodes = facets, edges = typed links
- Filter by edge kind
- Click to navigate

### TRAK-UI-7: Search
- Full-text search bar
- Results as facet cards
- Click to navigate

### TRAK-UI-8: Create/edit dialog
- Create new facet (title, body, status, parent, labels)
- Edit existing facet (inline or dialog)
- Markdown editor for body

---

## Dependencies (package.json)

```json
{
  "dependencies": {
    "react": "^18",
    "react-dom": "^18",
    "react-markdown": "^9",     // body rendering
    "@dnd-kit/core": "^6",      // drag-and-drop for kanban
    "d3-force": "^3",           // graph layout (or dagre)
    "zustand": "^4"             // lightweight state (optional)
  },
  "devDependencies": {
    "typescript": "^5",
    "vite": "^5",
    "@vitejs/plugin-react": "^4",
    "tailwindcss": "^3"         // styling
  }
}
```

## Key constraint

**The generated client IS the API contract.** If the backend changes
(new method, new field), `npm run codegen` regenerates the client,
TypeScript catches any breakage at compile time. No manual type
maintenance, no API docs to keep in sync.
