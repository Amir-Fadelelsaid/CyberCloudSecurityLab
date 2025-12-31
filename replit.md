# CloudShieldLab - Interactive Cloud Security Training Platform

## Overview

CloudShieldLab is a gamified cloud security training platform where users practice identifying and fixing cloud infrastructure vulnerabilities through realistic terminal-based simulations. The application provides 97 interactive labs across 7 categories covering Storage Security (12 labs including 1 expert Challenge), Network Security (17 labs including 1 expert Challenge), SOC Operations (12 labs including 1 expert Challenge), SOC Engineer (13 labs including 1 expert Challenge), Cloud Security Analyst (14 labs including 2 expert Challenges), IAM Security (16 labs including 1 expert Challenge with Identity Graph visualization), and Cloud Security Engineer (13 labs including 1 expert Challenge) scenarios. Users learn through hands-on practice with simulated AWS CLI commands and receive real-time feedback mapped to security frameworks like MITRE ATT&CK and CIS Controls.

**Target Audience**: Aspiring SOC analysts, cloud security engineers, IAM/SecOps professionals.

## Application Features

### Navigation Pages
1. **Mission Control** (`/`) - Dashboard with overview of labs, progress stats, and quick access to training
2. **Active Labs** (`/labs`) - Browse and filter all 97 labs by category, difficulty, and completion status
3. **Leaderboard** (`/leaderboard`) - Live ranking of users by completed labs and scores
4. **Badges** (`/badges`) - 24 unlockable achievements across Level, Category, and Achievement types
5. **Certificates** (`/certificates`) - Downloadable certificates for completed categories
6. **My Progress** (`/progress`) - Personal analytics, level progression, and completion statistics
7. **Community** (`/community`) - Discussion forum to connect with fellow security learners

### Lab Experience
- **Mission Briefings**: Each lab starts with a realistic scenario and urgent briefing
- **Terminal Simulation**: Practice AWS CLI commands in a safe, simulated environment
- **Intel Boxes**: Beginner labs include contextual guidance explaining MITRE ATT&CK techniques
- **Step Completion Feedback**: All labs provide feedback explaining what was accomplished and why it matters
- **Progress Tracking**: Scores, completion status, and reset functionality
- **Lab-Specific Contextual Data**: Each visualization component (SOC Dashboard, Infrastructure Status, Identity Ecosystem) displays data tailored to the specific lab's objective

### Lab-Specific Visualization System
All visualization components dynamically display contextually relevant data based on the specific lab topic:
- **SOC Dashboard** (SOC Operations, SOC Engineer, Cloud Security Analyst labs): Shows lab-specific devices with relevant attack indicators (e.g., "Phishing Email Investigation" displays workstations with PHISHING-CLICK tags, mail servers with SUSPICIOUS-SENDER tags)
- **Infrastructure Status** (Storage Security, Network Security, Cloud Security Engineer labs): Displays contextual alert banners explaining the specific security issue (e.g., "ALERT: corp-payroll-data bucket detected on dark web forum listing")
- **Identity Ecosystem** (IAM Security labs): Shows severity-coded context alerts matching the lab objective (e.g., "CRITICAL: Admin user lacks multi-factor authentication")

### Gamification
- **Leveling System**: 6 levels from Recruit to Elite Defender based on completed labs
- **Badge System**: 24 badges for achievements, category mastery, and milestones (including the elite "Warlord" badge)
- **Leaderboard**: Compete with other users on lab completions and scores
- **Certificates**: Generate shareable certificates for category completion (with disclaimer noting these are completion certificates, not industry certifications)

### Community Features
- Discussion forum for asking questions and sharing knowledge
- Threaded replies with real-time updates (30-second polling)
- Profanity filter with 70+ blocked words/phrases and leet speak detection
- Code of conduct enforcement
- Users can delete their own posts
- Creator badge with shield emblem for platform developer posts

## Recent Changes (December 2024)

### Badge Equipping System
- Users can equip any earned badge to display prominently on their profile
- Equipped badges appear next to username on the leaderboard with yellow/gold styling
- Equipped badges appear next to username on community discussion posts and replies
- Users can equip/unequip badges from the Badges page with visual feedback (star icon for equipped badge)
- API endpoint validates that users can only equip badges they've actually earned

### Warlord Badge
- Added elite "Warlord" achievement badge requiring completion of all 97 labs AND 5 community discussion posts
- Encourages users to both master content and help others in the community

### Creator Badge
- Platform developer posts display a special "Creator" badge with shield emblem
- Badge appears on both posts and replies in the community section

### Certificate Updates
- Changed certificate signature from "Founder & Lead Instructor" to "Founder & Developer"
- Added disclaimer on Certificates page clarifying these are completion certificates, not industry certifications

### Community Discussion Feature
- Added dedicated Community page accessible from sidebar navigation
- Users can post questions, share insights, and reply to discussions
- Profanity filter with exact word matching to prevent false positives
- Code of conduct modal with enforcement before posting
- Real-time updates with automatic refresh
- Threaded replies with collapsible reply forms
- Post deletion for post owners

### Lab-Specific Contextual Visualization (December 2024)
- SOC Dashboard now generates device data specific to each lab's topic (not just category)
- 15+ lab-specific device configurations with realistic hostnames, IPs, and attack tags
- ResourceGraph displays contextual alert banners based on lab title
- IdentityGraph shows severity-coded (critical/high/medium) context alerts for IAM labs
- All three visualization components receive labTitle prop for dynamic data generation

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
  - `discussionPosts` - Community discussion posts with parent-child threading

### Key Design Patterns
- **Shared Types**: Schema definitions in `shared/` folder used by both client and server
- **Route Definitions**: API routes defined in `shared/routes.ts` with Zod schemas for type-safe API contracts
- **Terminal Simulation**: Server-side command processor simulates AWS CLI responses without real cloud resources
- **Resource State Management**: Labs have mutable resource states that change from "vulnerable" to "fixed" as users complete remediation steps
- **Leveling System**: Dynamic user levels (Recruit to Elite Defender) based on completed lab count
- **Badge System**: 24 unlockable badges across Level, Category, and Achievement types (including Warlord badge for community engagement)
- **Step Completion Feedback** (All Labs): 
  - Beginner labs feature Intel boxes (blue contextual guidance) that explain concepts and MITRE ATT&CK techniques before action
  - All labs (Beginner, Intermediate, Advanced, Challenge) include step completion feedback (trophy icon) that explains what was accomplished and why it matters for security
  - Learning objectives displayed in the Intel tab to set expectations for Beginner labs
  - Intermediate, Advanced, and Challenge labs have focused completion feedback on every step to reinforce learning

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

## File Structure

### Key Files
- `client/src/App.tsx` - Main routing and app structure
- `client/src/components/layout.tsx` - Sidebar navigation with 7 nav items
- `client/src/pages/` - All page components (dashboard, labs-list, lab-workspace, progress, badges, leaderboard, certificates, community)
- `server/routes.ts` - API endpoints
- `server/storage.ts` - Database operations interface
- `server/lab-definitions.ts` - All 97 lab definitions with steps and feedback
- `server/profanity-filter.ts` - Content moderation for community posts
- `shared/schema.ts` - Drizzle ORM schema definitions
