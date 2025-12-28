# CyberLab Design Guidelines

## Design Approach
**Reference-Based with Cybersecurity Aesthetic**
Drawing inspiration from: Linear (modern SaaS), GitHub Dark Mode (developer tools), Vercel (tech-forward simplicity), and gaming interfaces with neon/cyber elements.

Core principle: Matrix-meets-modern-SaaS - dark, techy, but clean and professional.

---

## Typography System

**Font Families:**
- Primary: Inter (UI elements, body text)
- Monospace: JetBrains Mono (terminals, code snippets, tech labels)

**Hierarchy:**
- Hero: 4xl-6xl, font-bold, tracking-tight
- Section Headers: 2xl-3xl, font-semibold
- Card Titles: lg-xl, font-medium
- Body: base, font-normal, leading-relaxed
- Terminal/Code: sm-base monospace, leading-relaxed
- Labels/Meta: xs-sm, uppercase tracking-wide

---

## Layout System

**Spacing Primitives:** Tailwind units of 2, 4, 6, 8, 12, 16, 24
- Component padding: p-6 to p-8
- Section spacing: py-16 to py-24
- Card gaps: gap-6
- Terminal padding: p-4

**Container Strategy:**
- Max-width: max-w-7xl for content
- Dashboard grids: 2-3 column layouts (grid-cols-1 md:grid-cols-2 lg:grid-cols-3)
- Sidebar + main content: Fixed sidebar (w-64) + flex-1 main area

---

## Component Library

**Navigation:**
- Top navbar: Transparent-to-solid on scroll, logo left, nav center, user avatar right
- Sidebar (dashboard): Fixed left, dark with subtle glow border, icon + label nav items

**Cards (Progress/Lab Modules):**
- Dark background with subtle border glow (neon accent)
- Header with icon + title + status badge
- Progress bars with gradient fills (primary to accent)
- Hover: Lift effect (subtle translate-y + shadow increase)

**Terminal Components:**
- Full-width or constrained container with dark background
- Monospace font with syntax highlighting colors
- Blinking cursor animation
- Command prompt prefix ($ or >)
- Line numbers optional for code blocks

**Buttons:**
- Primary: Solid with neon glow on hover
- Secondary: Outline with hover fill
- Destructive: Red accent glow
- Backdrop blur for buttons over images (backdrop-blur-sm bg-black/30)

**Step-by-Step Guidance:**
- Vertical stepper with connecting lines
- Current step highlighted with neon accent
- Completed steps with checkmark icons
- Each step expandable with content area

**Interactive Elements:**
- Code input areas with syntax highlighting
- Validation feedback (green/red accent glows)
- Tooltips on hover with dark bg + neon border
- Modal overlays for detailed lab instructions

---

## Animations

**Minimal, Purposeful Only:**
- Terminal cursor blink
- Card hover lift (transform translate-y-1)
- Progress bar fill animations on load
- Fade-in on scroll for section reveals (subtle)
- NO complex scroll-triggered animations

---

## Images

**Hero Section Image:**
YES - Large hero image depicting abstract cybersecurity visualization (network nodes, code matrix, digital locks) with dark overlay gradient
- Full-width, 60-80vh height
- Dark gradient overlay (top/bottom) for text legibility
- Positioned behind hero content

**Placement:**
- Dashboard: Small icon graphics for lab categories (not photos)
- Lab cards: Thumbnail icons representing lab type
- NO stock photos of people - use abstract tech visualizations only

---

## Page Sections

**Landing Page:**
1. Hero: Full-width image bg + centered headline + CTA buttons (blurred backdrop)
2. Features: 3-column grid with icon cards
3. Lab Preview: Showcase terminal simulation with sample code
4. Learning Path: Visual roadmap/stepper showing progression
5. Stats: 4-column metrics with neon counters
6. CTA Footer: Dark section with signup form

**Dashboard:**
- Sidebar navigation (fixed)
- Main area: Welcome header + active labs grid (2-3 cols) + recent progress timeline
- Terminal overlay: Expandable terminal window for active simulations

**Lab Detail:**
- Breadcrumb navigation
- Split view: Instructions (left) + Terminal/sandbox (right)
- Progress stepper (top or left sidebar)
- Submit/validate buttons (bottom)

---

## Visual Treatment Notes

- Borders: Subtle neon glow on focus/hover states
- Backgrounds: Layered dark tones (not pure black) - use grays 900-950
- Accents: Cyan/blue primary, pink/purple secondary (neon palette)
- Shadows: Colored glows instead of traditional shadows
- Icons: Heroicons for UI, custom tech icons for labs (placeholder comments)