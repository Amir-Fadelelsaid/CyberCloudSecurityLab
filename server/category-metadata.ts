export interface CategoryMetadata {
  name: string;
  displayName: string;
  skills: string[];
  experience: string;
  description: string;
  color: string;
}

export const CATEGORY_METADATA: Record<string, CategoryMetadata> = {
  "Storage Security": {
    name: "Storage Security",
    displayName: "Storage Security Specialist",
    skills: [
      "S3 Bucket Policy Configuration",
      "Access Control Lists (ACLs)",
      "Encryption at Rest & Transit",
      "Data Loss Prevention",
      "Audit Logging Configuration"
    ],
    experience: "Expertise in securing cloud storage services, implementing proper access controls, and preventing data exposure through misconfigured buckets.",
    description: "Master the art of securing cloud storage resources and preventing data breaches.",
    color: "#f97316"
  },
  "Network Security": {
    name: "Network Security",
    displayName: "Network Security Engineer",
    skills: [
      "Security Group Configuration",
      "Network ACL Management",
      "VPC Architecture",
      "Firewall Rules & Policies",
      "Traffic Flow Analysis"
    ],
    experience: "Proficiency in designing and implementing secure network architectures, configuring firewalls, and analyzing network traffic for threats.",
    description: "Protect cloud network infrastructure from unauthorized access and attacks.",
    color: "#8b5cf6"
  },
  "SOC Operations": {
    name: "SOC Operations",
    displayName: "SOC Operations Analyst",
    skills: [
      "SIEM Alert Triage",
      "Incident Response Procedures",
      "Log Analysis & Correlation",
      "Threat Detection",
      "Security Event Investigation"
    ],
    experience: "Hands-on experience in Security Operations Center workflows, alert management, and coordinated incident response.",
    description: "Lead security operations and respond to threats in real-time.",
    color: "#06b6d4"
  },
  "SOC Engineer": {
    name: "SOC Engineer",
    displayName: "SOC Engineer",
    skills: [
      "SIEM Platform Administration",
      "SOAR Workflow Development",
      "Detection Rule Engineering",
      "Automation & Orchestration",
      "Security Tool Integration"
    ],
    experience: "Technical expertise in building and maintaining SOC infrastructure, developing detection rules, and automating security workflows.",
    description: "Build and maintain the technical infrastructure that powers security operations.",
    color: "#3b82f6"
  },
  "Cloud Security Analyst": {
    name: "Cloud Security Analyst",
    displayName: "Cloud Security Analyst",
    skills: [
      "Cloud Configuration Assessment",
      "Compliance Monitoring",
      "Risk Assessment",
      "Security Posture Management",
      "Vulnerability Analysis"
    ],
    experience: "Skilled in analyzing cloud security configurations, identifying compliance gaps, and assessing organizational security posture.",
    description: "Analyze and improve cloud security configurations across the organization.",
    color: "#10b981"
  },
  "IAM Security": {
    name: "IAM Security",
    displayName: "IAM Security Specialist",
    skills: [
      "Identity & Access Management",
      "Role-Based Access Control",
      "Least Privilege Implementation",
      "Policy Analysis & Optimization",
      "Credential Management"
    ],
    experience: "Expert in designing and implementing identity management solutions, enforcing least privilege, and managing access policies.",
    description: "Master identity and access management to protect cloud resources.",
    color: "#ec4899"
  },
  "Cloud Security Engineer": {
    name: "Cloud Security Engineer",
    displayName: "Cloud Security Engineer",
    skills: [
      "Infrastructure as Code Security",
      "DevSecOps Practices",
      "Security Architecture Design",
      "Compliance Automation",
      "Cloud-Native Security Tools"
    ],
    experience: "Comprehensive expertise in designing secure cloud architectures, implementing DevSecOps practices, and automating security controls.",
    description: "Design and implement secure cloud infrastructure from the ground up.",
    color: "#f59e0b"
  }
};

export function getCategoryMetadata(category: string): CategoryMetadata | undefined {
  return CATEGORY_METADATA[category];
}

export function getAllCategories(): string[] {
  return Object.keys(CATEGORY_METADATA);
}
