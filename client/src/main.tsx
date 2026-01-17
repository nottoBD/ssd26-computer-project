/**
 * FILE: main.tsx
 *
 * PURPOSE:
 *   Frontend entrypoint. Boots the React app, wires TanStack Router and React Query,
 *   and mounts into the DOM element with id="root"
 *
 * KEY INTEGRATIONS:
 *   - TanStack Router: client-side routing via generated routeTree
 *   - TanStack React Query: query caching, request deduplication, and async state
 *
 * SECURITY:
 *   - No secrets should be embedded here
 *   - This file configures infrastructure only (routing/cache), not auth logic itself
 */

import React from 'react'
import ReactDOM from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createRouter } from '@tanstack/react-router'
import { routeTree } from './routeTree.gen'
import { NotFound } from './routes/-not-found';
import './index.css'

// Global React Query client used across the app (caching, retries, invalidation, dedupe).
// Passed to Router context so route loaders/components can access it if needed.
const queryClient = new QueryClient()

// TanStack Router instance
// routeTree is generated from file-based routes (routeTree.gen)
// defaultNotFoundComponent is rendered for unknown routes
// preload "intent" prefetches route data when the user shows intent (e.g., hover/focus)
// context makes queryClient available inside routes (typed via Register below)
const router = createRouter({
  routeTree,
  // client-side 404
  defaultNotFoundComponent: NotFound,
  defaultPreload: 'intent',
  defaultPreloadStaleTime: 0,
  context: { queryClient },
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}

const rootElement = document.getElementById('root')!
if (!rootElement.innerHTML) {
  const root = ReactDOM.createRoot(rootElement)
  root.render(
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}
