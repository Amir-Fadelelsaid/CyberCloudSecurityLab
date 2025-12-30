# CloudShieldLab Design Guidelines

## Design Approach
**Reference-Based with Cybersecurity Aesthetic**
Drawing inspiration from: Linear (modern SaaS), GitHub Dark Mode (developer tools), Vercel (tech-forward simplicity), and gaming interfaces with neon/cyber elements.

Core principle: Matrix-meets-modern-SaaS - dark, techy, but clean and professional.

---

## Typography System

**Font Families:**
- Primary: Inter (UI elements, body text)
- Monospace: JetBrains Mono (terminals, code snippets, tech labels)
- Display: Orbitron (mission briefings, lab titles)

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

**Intel Boxes (Beginner Labs Only):**
- Cyan/blue background (bg-cyan-950/30) with cyan border (border-cyan-500/20)
- Blue shield icon with "INTEL:" label in cyan-400 text
- MITRE ATT&CK technique references highlighted with cyan-600/30 badge background
- Appears inline within step when step is NOT completed
- Provides contextual guidance explaining "what" and "why" before taking action
- Example: "INTEL: Start with HIGH severity alerts - they have the shortest SLA. MITRE ATT&CK T1078: Monitor for unusual account activity."

**Completion Feedback (All Labs):**
- Gold/primary background (bg-primary/10) with primary border (border-primary/30)
- Trophy icon (Trophy icon from lucide-react) in primary color
- "COMPLETED!" label in primary color, bold text
- 1-2 sentence feedback explaining what was accomplished
- Appears inline within step when step IS completed
- Animated entrance with spring transition (stiffness: 300, damping: 25)
- Example: "You identified the vulnerability. Understanding exposure scope helps prioritize remediation and determine if data was accessed."

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
- Intel/Completion Feedback entrance: Fade and scale (0.95 to 1.0)
- Trophy feedback spring animation for emphasis
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

**Lab Workspace:**
- Left panel: Mission Briefing tab (scenario context) + Steps tab (objectives with Intel and Feedback)
- Right panel: Terminal interface and resource visualization
- Progress summary: Bar showing completed steps out of total
- Tab switching: Intel/Brief shows mission context; Steps shows interactive objectives

**Lab Detail:**
- Breadcrumb navigation
- Split view: Instructions (left) + Terminal/sandbox (right)
- Progress stepper (top or left sidebar)
- Submit/validate buttons (bottom)

---

## Lab Workspace UI Specifics

**Mission Briefing/Intel Tab:**
- Mission Briefing section with scenario description
- Your Goal section (lab description in primary accent box)
- What You'll Learn section (for Beginner labs, showing learning objectives)
- Difficulty and estimated time badges

**Steps Tab:**
- Progress summary box showing X/Y steps completed
- Interactive step cards (clickable to expand)
- For each step:
  - Step number circle (highlighted when completed with checkmark)
  - Step title and description
  - Command hint box (bg-black/40 with primary text)
  - Intel box (ONLY for Beginner labs, only when NOT completed) - cyan styling
  - Completion feedback (trophy icon, only when step IS completed) - primary styling
- Step cards have hover states showing border/background elevation

**Color Scheme for Step Components:**
- Intel boxes: Cyan accent (cyan-950/30 bg, cyan-500/20 border, cyan-400 text)
- Completion feedback: Primary accent (primary/10 bg, primary/30 border, primary text)
- Step cards (active): primary/10 bg, primary/40 border
- Step cards (inactive): black/20 bg, white/10 border

---

## Visual Treatment Notes

- Borders: Subtle neon glow on focus/hover states
- Backgrounds: Layered dark tones (not pure black) - use grays 900-950
- Accents: Cyan/blue primary, pink/purple secondary (neon palette)
- Shadows: Colored glows instead of traditional shadows
- Icons: Heroicons for UI, custom tech icons for labs (placeholder comments)
- Feedback elements: Trophy icon for completion, Shield icon for MITRE ATT&CK references, BookOpen for Intel/Mission Briefing
- Text hierarchy: Primary/default for main content, secondary for supporting info, tertiary for least important

---

## Lab Completion Flow

1. User selects a lab and enters workspace
2. Left panel shows Mission Briefing tab initially
3. User clicks "Steps" tab to see objectives
4. Each step shows:
   - **Beginner Labs**: Intel box (before action) → User completes step → Completion feedback (after action)
   - **Intermediate/Advanced/Challenge Labs**: Step instructions → User completes step → Completion feedback (after action)
5. Trophy feedback animates in with spring effect when step is marked complete
6. Progress bar updates showing X/Y steps complete

---

## Accessibility Notes

- All interactive elements have data-testid attributes for testing
- Icon labels include aria-labels where needed
- Color alone doesn't convey information (use text labels with icons)
- Sufficient contrast ratios maintained between text and backgrounds
- Keyboard navigation supported for all controls
