# CloudShieldLab - Interactive Cloud Security Training Platform

Built to demonstrate real-world cloud security, SOC analysis, and incident response skills in a production-like environment.

### Who CloudShieldLab Is Designed For

- Aspiring SOC Analysts
- Cloud Security Engineers
- IAM / SecOps professionals
- Security teams onboarding junior analysts

[![Public Repository](https://img.shields.io/badge/Repository-Public-blue)](https://github.com/Amir-Fadelelsaid/CyberSecurityLab)
[![TypeScript](https://img.shields.io/badge/TypeScript-97.7%25-blue)](https://www.typescriptlang.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](https://cloudshieldlab.com/)

## [Try CloudShieldLab Live](https://cloudshieldlab.com/) 

A cutting-edge interactive cloud security training platform where users practice identifying and fixing cloud infrastructure vulnerabilities through realistic terminal-based simulations.

---

## Why I Built This

As a SOC Analyst and Cybersecurity professional, I noticed a critical gap in cloud security training: most platforms teach theory without hands-on practice. Junior analysts struggle to translate compliance frameworks like NIST and CIS Controls into actionable remediation steps.

**The Problem:** Cloud misconfigurations cause 80% of data breaches, yet there's no safe environment for security teams to practice identifying and fixing them before they encounter real incidents.

**My Solution:** CloudShieldLab provides an interactive, gamified training ground where security professionals can:
- Practice real-world vulnerability remediation in a safe sandbox
- Learn the "why" behind each fix through MITRE ATT&CK and CIS Control mappings
- Build muscle memory for incident response before facing production emergencies
- Experience enterprise SOC operations through realistic SIEM simulation
- Get real-time feedback on every step explaining what they accomplished and why it matters

**Skills This Proves:**
- Full-stack application development (React, TypeScript, Express, PostgreSQL)
- Cloud security architecture and AWS security best practices
- Security framework implementation (MITRE ATT&CK, CIS Controls, AWS Well-Architected)
- SOC operations, SIEM/SOAR concepts, and incident response
- Terminal-based security tooling and command-line proficiency
- Gamification design for security awareness training

---

## Features

### 97 Interactive Labs Across 7 Categories

| Category | Beginner | Intermediate | Advanced | Challenge | **Total** |
|----------|----------|--------------|----------|-----------|-----------|
| **Storage Security** | 3 labs | 4 labs | 3 labs | 2 labs | **12** |
| **Network Security** | 3 labs | 6 labs | 6 labs | 2 labs | **17** |
| **SOC Operations** | 3 labs | 4 labs | 3 labs | 2 labs | **12** |
| **SOC Engineer** | 4 labs | 4 labs | 4 labs | 1 lab | **13** |
| **Cloud Security Analyst** | 4 labs | 4 labs | 4 labs | 2 labs | **14** |
| **IAM Security** | 5 labs | 5 labs | 5 labs | 1 lab | **16** |
| **Cloud Security Engineer** | 4 labs | 4 labs | 4 labs | 1 lab | **13** |

### Comprehensive Step-by-Step Feedback System

Every lab provides real-time feedback at each step:

**🔵 Intel Boxes (Beginner Labs Only)**
- Blue contextual guidance boxes appear before each step
- Explain MITRE ATT&CK techniques and security concepts
- Help beginners understand "what" and "why" before taking action
- Learning objectives displayed to set expectations
- Example: "CIS AWS 1.4: Ensure access keys are rotated every 90 days or less. Old keys increase risk if compromised."

**🏆 Completion Feedback (All Labs - 1,907+ Feedback Messages)**
- Trophy icon appears after each step is completed
- 1-2 sentence explanations of what was accomplished
- Links actions to broader security concepts and best practices
- Demonstrates why each step matters
- Available on all Beginner, Intermediate, Advanced, and Challenge labs
- Examples:
  - "You identified the exposed access key. Speed is critical - bots continuously scan GitHub for AWS keys and can exploit them within minutes of exposure."
  - "Key rotated! You've invalidated the compromised credential. Regular rotation limits the window of exposure - even if keys leak, they won't work for long."
  - "You detected root account usage. Root activity is extremely rare - any use outside emergencies indicates a serious compromise or insider threat."

### Enterprise SOC Simulation Platform

Full-featured Security Operations Center dashboard with 6 operational tabs:

| Tab | Features |
|-----|----------|
| **ALERTS** | Real-time SIEM alerts with severity levels, enrichment data, and investigation panels |
| **LOGS** | Multi-source log analysis (Windows Events, Linux Syslog, Cloud Telemetry, Network Flows) |
| **DETECTIONS** | Custom detection rules with MITRE ATT&CK mapping and threshold logic |
| **CASES** | Case management workflow (open, investigating, pending, closed) with alert linking |
| **NETWORK** | Network traffic analysis with direction indicators and GeoIP enrichment |
| **ENDPOINTS** | Endpoint telemetry with process trees, command lines, and file hashes |

**Enrichment Layer:**
- GeoIP data (country, city, ISP)
- User context (department, role, risk score)
- Asset criticality ratings
- IP reputation scoring

### Certificate System

Earn certificates upon completing all labs in a category:

| Certificate | Labs Required |
|-------------|---------------|
| Storage Security | 12 labs |
| Network Security | 17 labs |
| SOC Operations | 12 labs |
| SOC Engineer | 13 labs |
| Cloud Security Analyst | 14 labs |
| IAM Security | 16 labs |
| Cloud Security Engineer | 13 labs |

### Dynamic Leveling System

| Level | Title | Labs Required | Badge Unlocked |
|-------|-------|---------------|----------------|
| 0 | Recruit | 0-6 labs | - |
| 1 | Operator | 7+ labs | Operator Badge |
| 2 | Analyst | 16+ labs | Analyst Badge |
| 3 | Engineer | 31+ labs | Engineer Badge |
| 4 | Architect | 51+ labs | Architect Badge |
| 5 | Elite Defender | All 97 labs | Elite Defender Badge |

### 23 Unlockable Badges

- **6 Level Badges**: Operator, Analyst, Engineer, Architect, Elite Defender, Challenge Master
- **7 Category Mastery Badges**: Storage Guardian, Network Sentinel, SOC Commander, SIEM Master, Cloud Protector, IAM Enforcer, Security Architect
- **10 Achievement Badges**: First Blood, Speed Runner, Deep Diver, Expert Hunter, Lone Wolf, Threat Responder, Incident Commander, APT Hunter, Perfect Week, Completionist

### Difficulty-Based Learning Path

| Level | Time | Steps | Focus | Feedback |
|-------|------|-------|-------|----------|
| **Beginner** | 5-10 min | 3 steps | Quick fixes, single resource | Intel boxes + completion feedback |
| **Intermediate** | 15-25 min | 6-7 steps | Multi-phase remediation with verification | Completion feedback on each step |
| **Advanced** | 30-55 min | 10-12 steps | Complex investigations, multiple resources, forensics | Completion feedback explaining concepts |
| **Challenge** | 20-120 min | 1 step | Expert-level APT scenarios, no guidance, multi-domain attacks | Completion feedback on finish |

### Smart Learning System
- **Step-by-Step Guidance**: Detailed instructions for each lab with numbered steps
- **Hideable Guide Panel**: Toggle the steps panel to practice independently
- **Progressive Difficulty**: Labs organized by difficulty level (Beginner, Intermediate, Advanced, Challenge)
- **Challenge Mode**: Practice labs with no guidance - apply your skills independently
- **Real-time Feedback**: Immediate validation of your security fixes with trophy icon feedback
- **Progress Tracking**: Monitor your learning journey across different security domains
- **Mission Completion Artifacts**: 4-tab modal with Incident Summary, Security Framework mappings, Technical Details, and Recommendations

### Categories
- **Storage Security** - S3 bucket policies, encryption, versioning, cross-account access
- **Network Security** - Security groups, VPC peering, WAF, Transit Gateway, NACLs
- **SOC Operations** - CloudTrail analysis, GuardDuty alerts, credential compromise, persistence detection
- **SOC Engineer** - SIEM configuration, threat intel, SOAR automation, detection engineering, purple team
- **Cloud Security Analyst** - Asset inventory, compliance assessment, container security, multi-cloud posture
- **IAM Security** - Least privilege, MFA enforcement, access key rotation, cross-account trust, privilege escalation
- **Cloud Security Engineer** - Security Hub, KMS rotation, VPC flow logs, GuardDuty, multi-account architecture, IaC security

### Realistic Simulation
- Terminal-based interface mimicking real AWS CLI
- Mock cloud resources that respond to your commands
- Authentic security vulnerability scenarios
- Practical remediation workflows
- Enterprise SOC dashboard with SIEM-style alerts

---

## Security Framework Depth

Each lab is mapped to industry-standard security frameworks, turning exercises into **interview ammunition**:

### Lab 1: Public S3 Bucket Exposure (Beginner)
| Framework | Reference | Description |
|-----------|-----------|-------------|
| **MITRE ATT&CK** | T1530 - Data from Cloud Storage | Adversaries access misconfigured cloud storage |
| **CIS Controls** | Control 3.3 - Configure Data Access Control Lists | Restrict access based on need-to-know |
| **AWS Well-Architected** | SEC 7 - Data Classification | Identify and classify organizational data |

**Detection Logic:** Monitor `s3:GetBucketAcl` and `s3:PutBucketPolicy` API calls in CloudTrail for unauthorized public access grants.

### Lab 2: Insecure Security Group (Intermediate)
| Framework | Reference | Description |
|-----------|-----------|-------------|
| **MITRE ATT&CK** | T1190 - Exploit Public-Facing Application | Attackers exploit exposed services |
| **CIS Controls** | Control 12.1 - Ensure Network Infrastructure is Up-to-Date | Maintain secure network configurations |
| **AWS Well-Architected** | SEC 5 - Network Protection | Implement multiple layers of defense |

**Detection Logic:** Alert on Security Group changes via `ec2:AuthorizeSecurityGroupIngress` when source is `0.0.0.0/0` on sensitive ports (22, 3389, 3306).

### Lab 3: CloudTrail Log Analysis (Advanced)
| Framework | Reference | Description |
|-----------|-----------|-------------|
| **MITRE ATT&CK** | T1078 - Valid Accounts | Adversaries use compromised credentials |
| **CIS Controls** | Control 8.5 - Collect Detailed Audit Logs | Enable logging for threat detection |
| **AWS Well-Architected** | SEC 4 - Detective Controls | Implement mechanisms to detect threats |

**Detection Logic:** Correlate `sts:AssumeRole` with unusual source IPs, failed `iam:CreateAccessKey` attempts, and `ConsoleLogin` from new geolocations.

---

## Tech Stack

**Frontend**
- React 18+ with TypeScript
- Tailwind CSS for styling
- Framer Motion for smooth animations
- TanStack React Query for data fetching
- Wouter for lightweight routing

**Backend**
- Express.js server
- PostgreSQL database (Neon)
- Drizzle ORM for type-safe queries
- Zod for schema validation
- Passport.js for authentication

**Authentication**
- Replit Auth integration for seamless login
- Session-based authentication
- Secure token management

## Getting Started

### Prerequisites
- Node.js 18+
- npm or yarn
- Replit account (optional, for cloud development)

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/Amir-Fadelelsaid/CyberSecurityLab.git
cd CyberSecurityLab
```

2. **Install dependencies**
```bash
npm install
```

3. **Set up environment variables**
```bash
# Create a .env file with necessary secrets
# (Database URL, OAuth credentials, etc.)
```

4. **Start the development server**
```bash
npm run dev
```

The app will be available at `http://localhost:5000`

## Usage

### For Learners
1. Visit the landing page and click **"START TRAINING"**
2. Browse available training labs
3. Select a lab by difficulty level (Beginner, Intermediate, Advanced, Challenge)
4. Follow the step-by-step guide in the left panel (or hide it for challenge mode)
5. Complete each step - Intel boxes (Beginner only) provide context, trophy feedback explains what you accomplished
6. Use the terminal to execute commands and fix vulnerabilities
7. Track your progress in the Mission Control dashboard
8. Earn badges and certificates as you complete labs

### Example Commands
```bash
# Scan for vulnerabilities
scan

# List S3 buckets
aws s3 ls

# Fix a vulnerable bucket
aws s3 fix corp-payroll-data

# Verify security improvements
scan
```

## Project Structure

```
CloudShieldLab/
├── client/                 # React frontend
│   ├── src/
│   │   ├── pages/         # Page components (landing, labs, workspace, badges, certificates)
│   │   ├── components/    # Reusable UI components (SOC dashboard, terminal, certificate)
│   │   ├── hooks/         # Custom React hooks
│   │   ├── lib/           # Utilities and helpers
│   │   └── index.css      # Global styles with neon theme
│   └── vite.config.ts     # Vite configuration
├── server/                # Express backend
│   ├── routes.ts          # API endpoints
│   ├── storage.ts         # Data persistence layer
│   ├── lab-definitions.ts # 97 lab definitions with 1,907+ completion feedback messages
│   ├── badge-definitions.ts # 23 badge definitions
│   └── index.ts           # Server entry point
├── shared/                # Shared types and schemas
│   └── schema.ts          # Drizzle schema & Zod validators
├── design_guidelines.md   # UI/UX design specifications
└── package.json          # Project dependencies
```

## Visual Design

CloudShieldLab features a **Matrix-meets-modern-SaaS** dark interface with:

| Element | Color | Usage |
|---------|-------|-------|
| **Primary** | Teal Green `hsl(160, 60%, 45%)` | Buttons, highlights, progress bars |
| **Accent** | Purple/Violet `hsl(250, 50%, 55%)` | Secondary actions, gradients |
| **Background** | Dark Gray `hsl(220, 20%, 8%)` | Main background, cards |
| **Success** | Green | Fixed resources, completed steps |
| **Danger** | Red | Vulnerable resources, alerts |

**Design Elements:**
- Terminal-style monospace fonts (JetBrains Mono)
- Neon glow effects on interactive elements
- Gradient borders and shadow animations
- Card hover lift effects with colored shadows
- Progress bars with gradient fills
- Cyberpunk-inspired UI with professional polish
- Intel boxes with cyan/blue styling for Beginner labs
- Trophy feedback with animated transitions on completion

## Learning Path

```
Beginner Labs (5-10 min, 3 steps, Intel + Feedback)
    ↓
    └─ Storage: Public S3 Bucket, Unencrypted Bucket, Logging Disabled
    └─ Network: SSH Exposed, RDP Open, Database Port Exposed
    └─ SOC: CloudTrail Disabled, GuardDuty Crypto Mining, Suspicious SSM Session

Intermediate Labs (15-25 min, 6-7 steps, Completion Feedback)
    ↓
    └─ Storage: Overly Permissive Policies, Versioning Compliance, Cross-Account Access
    └─ Network: VPC Flow Logs, NACL Misconfig, Unrestricted Egress, EIP Audit
    └─ SOC: IAM Policy Changes, KMS Key Deletion, Root Activity, EventBridge Persistence

Advanced Labs (30-55 min, 10-12 steps, Completion Feedback)
    ↓
    └─ Storage: Data Breach Investigation, Supply Chain Attack, Multi-Bucket Hardening
    └─ Network: WAF Deployment, VPC Peering Audit, Transit Gateway Route Leak
    └─ SOC: Credential Compromise, Cross-Account Role Attack, DataSync Exfiltration

Challenge Labs (20-45 min, no guidance, Completion Feedback)
    ↓
    └─ Storage: Storage Security Challenge - Multiple buckets, find and fix all issues
    └─ Network: Network Security Challenge - Lock down exposed infrastructure
    └─ SOC: SOC Operations Challenge - Investigate alerts and respond independently
```

## Security Considerations

- **Authentication**: Uses Replit OAuth for secure login
- **Data Validation**: All inputs validated with Zod schemas
- **Database Security**: PostgreSQL with parameterized queries
- **Session Management**: Secure session storage with connect-pg-simple
- **HTTPS Ready**: Configured for secure deployments

## API Endpoints

### Public
- `GET /` - Landing page
- `GET /labs` - List all labs
- `GET /labs/:id` - Get lab details

### Authenticated
- `GET /api/auth/user` - Current user info
- `POST /api/progress` - Submit lab completion
- `PATCH /api/labs/:id/reset` - Reset lab environment
- `GET /api/progress` - User progress history
- `GET /api/user/level` - Get user level info
- `GET /api/badges` - List all badges
- `GET /api/user/badges` - Get user's earned badges
- `GET /api/certificates` - Get user's certificates

## Development

### Run Tests
```bash
npm test
```

### Build for Production
```bash
npm run build
```

### Deploy to Replit
The project is configured to run on Replit with the `Start application` workflow:
```bash
npm run dev
```

## Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap

- [x] 97 labs across 7 categories (Storage, Network, SOC Operations, SOC Engineer, Cloud Security Analyst, IAM Security, Cloud Security Engineer)
- [x] Advanced labs with 10-12 steps and multiple resources
- [x] 11 Challenge labs including 8 expert APT-level scenarios (45-120 min)
- [x] Mission completion artifacts with 4-tab modal
- [x] Security framework mappings (MITRE ATT&CK, CIS Controls, AWS Well-Architected)
- [x] Hiring Manager / Recruiter demonstration page
- [x] Dynamic leveling system (Recruit to Elite Defender, plus Challenge Master)
- [x] 24 unlockable badges (Level, Category, Achievement)
- [x] Hideable guide panel for self-challenge mode
- [x] Live leaderboard with real-time WebSocket updates
- [x] Enterprise SOC simulation dashboard (SIEM, logs, detections, cases)
- [x] Certificate system with category completion tracking
- [x] Multi-source log analysis (Windows, Linux, Cloud, Network)
- [x] Enrichment layer (GeoIP, user context, asset criticality)
- [x] Detection rules with MITRE ATT&CK mapping
- [x] Case management workflow
- [x] Intel boxes for Beginner labs with step-level guidance
- [x] Completion feedback on all 97 labs (1,907+ feedback messages)
- [ ] Video tutorials and walkthroughs
- [ ] Community-contributed labs
- [ ] Mobile app support

## License

This project is open source and available under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: Report bugs via [GitHub Issues](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/discussions)
- **Live Version**: Visit [cloudshieldlab.com](https://cloudshieldlab.com/)

## Author

**Amir Fadelelsaid** - SOC Analyst & Cybersecurity Professional

Built with expertise in SIEM operations, cloud security, and incident response. This project demonstrates my commitment to making cloud security training accessible and practical.

---

<div align="center">

**Master Cloud Security Defense**

[Try Live Demo](https://cloudshieldlab.com/) | [View on GitHub](https://github.com/Amir-Fadelelsaid/CyberSecurityLab) | [Report Issue](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/issues)

</div>
