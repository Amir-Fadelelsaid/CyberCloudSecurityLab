# 🔐 CyberLab - Interactive Cloud Security Training Platform

[![Public Repository](https://img.shields.io/badge/Repository-Public-blue)](https://github.com/Amir-Fadelelsaid/CyberSecurityLab)
[![TypeScript](https://img.shields.io/badge/TypeScript-97.7%25-blue)](https://www.typescriptlang.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)](https://cloudshieldlabbyamirfadel.com/)

## 🎮 [▶ Try CyberLab Live](https://cloudshieldlabbyamirfadel.com/) 

A cutting-edge interactive cloud security training platform where users practice identifying and fixing cloud infrastructure vulnerabilities through realistic terminal-based simulations.

## 🎯 Features

### Interactive Labs
- **Beginner Level**: Public S3 Bucket Exposure - Learn to identify and remediate exposed cloud storage
- **Intermediate Level**: Insecure Security Group - Master network security configurations
- **Advanced Level**: Coming soon...

### Smart Learning System
- **Step-by-Step Guidance**: Detailed instructions for each lab with numbered steps
- **Progressive Difficulty**: Labs organized by difficulty level (Beginner, Intermediate, Advanced)
- **Real-time Feedback**: Immediate validation of your security fixes
- **Progress Tracking**: Monitor your learning journey across different security domains

### Categories
- 🛡️ **Storage Security** - S3 bucket policies and access controls
- 🌐 **Network Security** - Security group rules and SSH access restrictions
- 🔑 **IAM Security** - Identity and access management (coming soon)

### Realistic Simulation
- Terminal-based interface mimicking real AWS CLI
- Mock cloud resources that respond to your commands
- Authentic security vulnerability scenarios
- Practical remediation workflows

## 🚀 Tech Stack

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

## 📦 Getting Started

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

## 🎓 Usage

### For Learners
1. Visit the landing page and click **"INITIATE_TRAINING"**
2. Browse available training labs
3. Select a lab by difficulty level (Beginner, Intermediate, Advanced)
4. Follow the step-by-step guide in the left panel
5. Use the terminal to execute commands and fix vulnerabilities
6. Track your progress in the Mission Control dashboard

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

## 📁 Project Structure

```
CyberSecurityLab/
├── client/                 # React frontend
│   ├── src/
│   │   ├── pages/         # Page components (landing, labs, workspace)
│   │   ├── components/    # Reusable UI components
│   │   ├── hooks/         # Custom React hooks
│   │   ├── lib/           # Utilities and helpers
│   │   └── index.css      # Global styles with neon theme
│   └── vite.config.ts     # Vite configuration
├── server/                # Express backend
│   ├── routes.ts          # API endpoints
│   ├── storage.ts         # Data persistence layer
│   ├── index.ts           # Server entry point
│   └── replit_integrations/  # Replit-specific integrations
├── shared/                # Shared types and schemas
│   └── schema.ts          # Drizzle schema & Zod validators
├── script/                # Database scripts
├── design_guidelines.md   # UI/UX design specifications
└── package.json          # Project dependencies
```

## 🎨 Visual Design

CyberLab features a **cyber-themed dark interface** with:
- 🟢 Neon green primary accent (#00FF80)
- 🟣 Neon purple secondary accent (#A000FF)
- 🔵 Vibrant cyan accents (#00DCFF)
- Smooth animations and hover effects
- Glowing elements and pulsing shadows
- Scanline effects and cyberpunk aesthetic

## 🔄 Learning Path

```
Beginner Labs
    ↓
    └─ Storage Security (S3 Bucket Exposure)
    └─ Basic Terminal Commands
    └─ Cloud Resource Identification

Intermediate Labs
    ↓
    └─ Network Security (Security Group Rules)
    └─ Access Control Configuration
    └─ Multi-step Remediation

Advanced Labs (Coming Soon)
    ↓
    └─ IAM Policy Configuration
    └─ Cross-service Security
    └─ Real-world Attack Scenarios
```

## 🔐 Security Considerations

- **Authentication**: Uses Replit OAuth for secure login
- **Data Validation**: All inputs validated with Zod schemas
- **Database Security**: PostgreSQL with parameterized queries
- **Session Management**: Secure session storage with connect-pg-simple
- **HTTPS Ready**: Configured for secure deployments

## 📊 API Endpoints

### Public
- `GET /` - Landing page
- `GET /labs` - List all labs
- `GET /labs/:id` - Get lab details

### Authenticated
- `GET /api/auth/user` - Current user info
- `POST /api/progress` - Submit lab completion
- `PATCH /api/labs/:id/reset` - Reset lab environment
- `GET /api/progress` - User progress history

## 🛠️ Development

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

## 🤝 Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📋 Roadmap

- [ ] Advanced cloud security labs (IAM, encryption, compliance)
- [ ] Certification system with progress badges
- [ ] Leaderboards and team challenges
- [ ] Video tutorials and walkthroughs
- [ ] Community-contributed labs
- [ ] Mobile app support
- [ ] Multi-language support

## 📝 License

This project is open source and available under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- **Issues**: Report bugs via [GitHub Issues](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/issues)
- **Discussions**: Join our [GitHub Discussions](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/discussions)
- **Live Version**: Visit the [CyberLab website](https://cyberlab.replit.dev)

## 👨‍💻 Author

**Amir Fadelelsaid** - Created with ❤️ for cloud security enthusiasts

---

<div align="center">

**Master Cloud Security Defense** 🔐

[Visit CyberLab](https://cyberlab.replit.dev) · [View on GitHub](https://github.com/Amir-Fadelelsaid/CyberSecurityLab) · [Report Issue](https://github.com/Amir-Fadelelsaid/CyberSecurityLab/issues)

</div>
