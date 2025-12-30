# CloudShieldLab - Interactive Cloud Security Training Platform

## Overview

CloudShieldLab is a gamified cloud security training platform where users practice identifying and fixing cloud infrastructure vulnerabilities through realistic terminal-based simulations. The application provides 84 interactive labs across 7 categories covering Storage Security, Network Security, SOC Operations, SOC Engineer, Cloud Security Analyst, IAM Security (with Identity Graph visualization), and Cloud Security Engineer scenarios. Users learn through hands-on practice with simulated AWS CLI commands and receive real-time feedback mapped to security frameworks like MITRE ATT&CK and CIS Controls.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript, built with Vite
- **Routing**: Wouter for lightweight client-side routing
- **State Management**: TanStack React Query for server state and caching
- **Styling**: Tailwind CSS with a custom cybersecurity-themed dark design system (Matrix green/neon aesthetic)
- **UI Components**: shadcn/ui component library built on Radix UI primitives
- **Animations**: Framer Motion for page transitions and terminal animations
- **Fonts**: Inter (UI), Fira Code (terminal/code), Orbitron (display headings)

### Backend Architecture
- **Runtime**: Node.js with Express.js
- **Language**: TypeScript with ES modules
- **API Pattern**: RESTful endpoints with Zod schema validation
- **Session Management**: Express sessions with PostgreSQL session store (connect-pg-simple)
- **Authentication**: Replit Auth integration using OpenID Connect

### Data Storage
- **Database**: PostgreSQL via Drizzle ORM
- **Schema Location**: `shared/schema.ts` contains all table definitions
- **Core Tables**:
  - `users` and `sessions` - Replit Auth user management
  - `labs` - Training scenarios with difficulty levels and step-by-step instructions
  - `resources` - Simulated cloud resources (S3, EC2, IAM, security groups)
  - `userProgress` - Tracks completed labs and scores
  - `terminalLogs` - Command history for learning analytics
  - `badges` and `userBadges` - Achievement and leveling system

### Key Design Patterns
- **Shared Types**: Schema definitions in `shared/` folder used by both client and server
- **Route Definitions**: API routes defined in `shared/routes.ts` with Zod schemas for type-safe API contracts
- **Terminal Simulation**: Server-side command processor simulates AWS CLI responses without real cloud resources
- **Resource State Management**: Labs have mutable resource states that change from "vulnerable" to "fixed" as users complete remediation steps
- **Leveling System**: Dynamic user levels (Recruit to Elite Defender) based on completed lab count
- **Badge System**: 19 unlockable badges across Level, Category, and Achievement types

### Build System
- **Development**: Vite dev server with HMR, proxies API requests to Express
- **Production**: Vite builds static assets to `dist/public`, esbuild bundles server to `dist/index.cjs`
- **Path Aliases**: `@/` maps to client source, `@shared/` maps to shared code

## External Dependencies

### Authentication
- **Replit Auth**: OpenID Connect integration for user authentication
- Uses `openid-client` and `passport` for OAuth flow
- Session persistence via PostgreSQL

### Database
- **PostgreSQL**: Primary data store (requires `DATABASE_URL` environment variable)
- **Drizzle ORM**: Type-safe database queries and migrations
- **connect-pg-simple**: Session storage in PostgreSQL

### Frontend Libraries
- **Radix UI**: Accessible, unstyled component primitives
- **TanStack Query**: Data fetching, caching, and synchronization
- **Framer Motion**: Animation library
- **Lucide React**: Icon library

### Environment Variables Required
- `DATABASE_URL`: PostgreSQL connection string
- `SESSION_SECRET`: Secret for session encryption
- `ISSUER_URL`: Replit OIDC issuer (defaults to https://replit.com/oidc)
- `REPL_ID`: Automatically set by Replit environment
