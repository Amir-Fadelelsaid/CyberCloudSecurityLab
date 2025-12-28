// Lab Definitions for CyberLab - 33 Labs (11 per category)
// Difficulty Levels:
// - Beginner: 3-4 steps, single resource, quick fix
// - Intermediate: 5-7 steps, multiple phases, verification required
// - Advanced: 8-12 steps, multi-stage attack chains, forensics, multiple resources
// - Challenge: 1 step (objective only), no guidance - users practice independently

export interface LabDefinition {
  title: string;
  description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced" | "Challenge";
  category: "Storage Security" | "Network Security" | "SOC Operations";
  estimatedTime: string;
  initialState: Record<string, unknown>;
  steps: Array<{
    number: number;
    title: string;
    description: string;
    hint: string;
  }>;
  resources: Array<{
    type: string;
    name: string;
    config: Record<string, unknown>;
    isVulnerable: boolean;
    status: string;
  }>;
  fixCommands: string[];
}

// ============= STORAGE SECURITY LABS (10) =============
export const storageSecurityLabs: LabDefinition[] = [
  // BEGINNER LABS (3-4 steps, quick fixes)
  {
    title: "Public S3 Bucket Exposure",
    description: "A sensitive corporate S3 bucket has been accidentally left open to the public. Identify and secure it quickly.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["corp-payroll-data"] },
    steps: [
      { number: 1, title: "Scan for Vulnerabilities", description: "Run a security scan to identify exposed resources.", hint: "Type 'scan' to see vulnerable resources." },
      { number: 2, title: "List S3 Buckets", description: "Review your S3 buckets and their security status.", hint: "Type 'aws s3 ls' to list buckets." },
      { number: 3, title: "Fix the Vulnerable Bucket", description: "Apply a secure bucket policy to block public access.", hint: "Type 'aws s3 fix corp-payroll-data' to secure it." }
    ],
    resources: [
      { type: "s3", name: "corp-payroll-data", config: { access: "public-read" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 fix corp-payroll-data"]
  },
  {
    title: "Unencrypted S3 Bucket",
    description: "Customer data is stored without encryption. Enable server-side encryption to protect data at rest.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["customer-data-raw"] },
    steps: [
      { number: 1, title: "Scan Infrastructure", description: "Identify unencrypted storage.", hint: "Type 'scan' to find vulnerabilities." },
      { number: 2, title: "Check Encryption Status", description: "View bucket encryption details.", hint: "Type 'aws s3 ls-encryption' to check." },
      { number: 3, title: "Enable Encryption", description: "Apply AES-256 encryption.", hint: "Type 'aws s3 enable-encryption customer-data-raw'." }
    ],
    resources: [
      { type: "s3", name: "customer-data-raw", config: { encryption: "none" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-encryption customer-data-raw"]
  },
  {
    title: "S3 Bucket Logging Disabled",
    description: "Access logging is disabled, making it impossible to audit data access. Enable logging.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["financial-reports"] },
    steps: [
      { number: 1, title: "Identify Issue", description: "Scan for buckets missing audit logs.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Logging", description: "Review logging configuration.", hint: "Type 'aws s3 ls-logging' to check." },
      { number: 3, title: "Enable Logging", description: "Turn on access logging.", hint: "Type 'aws s3 enable-logging financial-reports'." }
    ],
    resources: [
      { type: "s3", name: "financial-reports", config: { logging: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-logging financial-reports"]
  },

  // INTERMEDIATE LABS (5-7 steps, multiple phases)
  {
    title: "S3 Versioning and Backup Compliance",
    description: "A backup bucket lacks versioning and lifecycle policies, risking permanent data loss. Configure proper backup protections.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["disaster-recovery-backup", "backup-logs"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Scan infrastructure for backup vulnerabilities.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Versioning Status", description: "Check which buckets have versioning enabled.", hint: "Type 'aws s3 ls-versioning' to review." },
      { number: 3, title: "Understand the Risk", description: "Without versioning, deleted files cannot be recovered. This violates backup compliance requirements.", hint: "Consider what happens if someone accidentally deletes critical backups." },
      { number: 4, title: "Enable Versioning", description: "Turn on versioning for the backup bucket.", hint: "Type 'aws s3 enable-versioning disaster-recovery-backup'." },
      { number: 5, title: "Verify Configuration", description: "Confirm versioning is now active.", hint: "Type 'aws s3 ls-versioning' to verify." },
      { number: 6, title: "Document Compliance", description: "Run a final scan to confirm compliance status.", hint: "Type 'scan' to generate compliance report." }
    ],
    resources: [
      { type: "s3", name: "disaster-recovery-backup", config: { versioning: false }, isVulnerable: true, status: "active" },
      { type: "s3", name: "backup-logs", config: { versioning: true }, isVulnerable: false, status: "active" }
    ],
    fixCommands: ["aws s3 enable-versioning disaster-recovery-backup"]
  },
  {
    title: "Overly Permissive Bucket Policy",
    description: "A data lake bucket grants wildcard permissions to all principals. Investigate the policy and implement least privilege access.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["shared-data-lake"] },
    steps: [
      { number: 1, title: "Identify Policy Risk", description: "Scan for overly permissive bucket policies.", hint: "Type 'scan' to find misconfigurations." },
      { number: 2, title: "Review Current Policy", description: "Examine the bucket's IAM policy document.", hint: "Type 'aws s3 get-policy shared-data-lake' to view." },
      { number: 3, title: "Analyze Permissions", description: "The policy grants 's3:*' to principal '*'. This allows anyone to read, write, and delete data.", hint: "Wildcard policies violate CIS Benchmark 2.1.5." },
      { number: 4, title: "Apply Least Privilege", description: "Restrict the policy to specific actions and principals.", hint: "Type 'aws s3 restrict-policy shared-data-lake'." },
      { number: 5, title: "Verify New Policy", description: "Check that the policy is now restrictive.", hint: "Type 'aws s3 get-policy shared-data-lake' to confirm." },
      { number: 6, title: "Final Verification", description: "Run security scan to confirm remediation.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "shared-data-lake", config: { policy: "s3:*", principal: "*" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 restrict-policy shared-data-lake"]
  },
  {
    title: "Cross-Account Bucket Access Investigation",
    description: "Security detected a bucket with access from unknown AWS accounts. Investigate and remove unauthorized access.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["partner-data-exchange"] },
    steps: [
      { number: 1, title: "Detect Anomaly", description: "Scan for buckets with external access.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "List External Access", description: "Check which accounts have access to the bucket.", hint: "Type 'aws s3 check-access partner-data-exchange'." },
      { number: 3, title: "Identify Unauthorized Accounts", description: "Account 999888777666 is not in our approved partners list. This could be a compromise.", hint: "Cross-reference with your organization's approved account list." },
      { number: 4, title: "Review Bucket Policy", description: "Examine how the external access was granted.", hint: "Type 'aws s3 get-policy partner-data-exchange'." },
      { number: 5, title: "Revoke Unauthorized Access", description: "Remove access for unknown accounts.", hint: "Type 'aws s3 revoke-external partner-data-exchange'." },
      { number: 6, title: "Verify Remediation", description: "Confirm only authorized accounts remain.", hint: "Type 'aws s3 check-access partner-data-exchange' to verify." }
    ],
    resources: [
      { type: "s3", name: "partner-data-exchange", config: { crossAccount: ["123456789012", "999888777666"] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 revoke-external partner-data-exchange"]
  },
  {
    title: "S3 Object Lock for Compliance",
    description: "Regulatory requirements mandate WORM protection for audit logs. Configure Object Lock to prevent deletion or modification.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["compliance-audit-logs"] },
    steps: [
      { number: 1, title: "Identify Compliance Gap", description: "Scan for buckets missing WORM protection.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Object Lock Status", description: "Review current Object Lock configuration.", hint: "Type 'aws s3 check-object-lock compliance-audit-logs'." },
      { number: 3, title: "Understand Requirements", description: "SOX and HIPAA require immutable audit logs. Without Object Lock, logs can be tampered with.", hint: "MITRE ATT&CK T1565: Data Manipulation." },
      { number: 4, title: "Enable Object Lock", description: "Configure WORM protection in compliance mode.", hint: "Type 'aws s3 enable-object-lock compliance-audit-logs'." },
      { number: 5, title: "Verify Protection", description: "Confirm Object Lock is active.", hint: "Type 'aws s3 check-object-lock compliance-audit-logs'." },
      { number: 6, title: "Generate Compliance Report", description: "Document the remediation for auditors.", hint: "Type 'scan' to generate report." }
    ],
    resources: [
      { type: "s3", name: "compliance-audit-logs", config: { objectLock: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-object-lock compliance-audit-logs"]
  },

  // ADVANCED LABS (8-12 steps, complex scenarios)
  {
    title: "Multi-Bucket Security Hardening",
    description: "A security audit revealed multiple buckets with various vulnerabilities: missing encryption, disabled Block Public Access, and improper replication. Perform a comprehensive hardening exercise.",
    difficulty: "Advanced",
    category: "Storage Security",
    estimatedTime: "30-45 minutes",
    initialState: { buckets: ["prod-application-data", "eu-customer-data", "temp-file-sharing"] },
    steps: [
      { number: 1, title: "Initial Assessment", description: "Perform a comprehensive security scan of all S3 resources.", hint: "Type 'scan' to identify all vulnerabilities." },
      { number: 2, title: "Inventory Buckets", description: "List all buckets and understand their purpose.", hint: "Type 'aws s3 ls' to see all buckets." },
      { number: 3, title: "Check Block Public Access", description: "Verify Block Public Access settings on production bucket.", hint: "Type 'aws s3 check-block-public prod-application-data'." },
      { number: 4, title: "Enable Block Public Access", description: "Turn on all four Block Public Access settings.", hint: "Type 'aws s3 block-public-access prod-application-data'." },
      { number: 5, title: "Review Replication Config", description: "Check data replication compliance for EU data.", hint: "Type 'aws s3 check-replication eu-customer-data'." },
      { number: 6, title: "Fix Replication Region", description: "Data must stay in EU regions for GDPR. Update replication.", hint: "Type 'aws s3 fix-replication eu-customer-data'." },
      { number: 7, title: "Audit Pre-signed URLs", description: "Check pre-signed URL expiration policy.", hint: "Type 'aws s3 check-presigned temp-file-sharing'." },
      { number: 8, title: "Fix Pre-signed Policy", description: "Reduce URL expiration to limit exposure window.", hint: "Type 'aws s3 fix-presigned temp-file-sharing'." },
      { number: 9, title: "Comprehensive Verification", description: "Run final security scan to confirm all issues resolved.", hint: "Type 'scan' to verify complete remediation." },
      { number: 10, title: "Document Findings", description: "All three vulnerabilities have been addressed: Block Public Access enabled, GDPR-compliant replication configured, and pre-signed URL policy hardened.", hint: "Mission complete when all resources show SECURE status." }
    ],
    resources: [
      { type: "s3", name: "prod-application-data", config: { blockPublicAccess: false }, isVulnerable: true, status: "active" },
      { type: "s3", name: "eu-customer-data", config: { replication: "us-east-1", required: "eu-west-1" }, isVulnerable: true, status: "active" },
      { type: "s3", name: "temp-file-sharing", config: { presignedExpiry: "7d" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 block-public-access prod-application-data", "aws s3 fix-replication eu-customer-data", "aws s3 fix-presigned temp-file-sharing"]
  },
  {
    title: "Data Breach Investigation - S3 Exposure",
    description: "Security operations detected potential data exfiltration from an S3 bucket. Investigate the exposure, identify compromised data, and implement controls to prevent future breaches.",
    difficulty: "Advanced",
    category: "Storage Security",
    estimatedTime: "35-50 minutes",
    initialState: { buckets: ["customer-pii-data", "access-logs-bucket"] },
    steps: [
      { number: 1, title: "Initial Triage", description: "Security alerted on suspicious S3 access patterns. Begin investigation.", hint: "Type 'scan' to assess current security posture." },
      { number: 2, title: "Review Bucket List", description: "Identify buckets containing sensitive data.", hint: "Type 'aws s3 ls' to list all buckets." },
      { number: 3, title: "Check Bucket Policy", description: "Examine the policy on the PII bucket.", hint: "Type 'aws s3 get-policy customer-pii-data'." },
      { number: 4, title: "Analyze Access Patterns", description: "The bucket was accessed from external IPs. The overly permissive policy allowed anonymous reads.", hint: "This is MITRE ATT&CK T1530: Data from Cloud Storage Object." },
      { number: 5, title: "Check Encryption Status", description: "Verify if exposed data was encrypted.", hint: "Type 'aws s3 ls-encryption'." },
      { number: 6, title: "Secure the Bucket Policy", description: "Immediately restrict the bucket policy.", hint: "Type 'aws s3 restrict-policy customer-pii-data'." },
      { number: 7, title: "Enable Encryption", description: "Encrypt the bucket to protect remaining data.", hint: "Type 'aws s3 enable-encryption customer-pii-data'." },
      { number: 8, title: "Enable Access Logging", description: "Turn on logging for future forensics.", hint: "Type 'aws s3 enable-logging customer-pii-data'." },
      { number: 9, title: "Block Public Access", description: "Prevent any future public exposure.", hint: "Type 'aws s3 block-public-access customer-pii-data'." },
      { number: 10, title: "Final Verification", description: "Confirm all security controls are in place.", hint: "Type 'scan' to verify remediation." },
      { number: 11, title: "Incident Documentation", description: "Document the breach timeline: initial exposure, data accessed, remediation steps taken, and controls implemented.", hint: "All controls implemented. Incident contained." }
    ],
    resources: [
      { type: "s3", name: "customer-pii-data", config: { policy: "s3:GetObject", principal: "*" }, isVulnerable: true, status: "active" },
      { type: "s3_encryption", name: "customer-pii-data-encryption", config: { encryption: "none" }, isVulnerable: true, status: "active" },
      { type: "s3_logging", name: "customer-pii-data-logging", config: { logging: false }, isVulnerable: true, status: "active" },
      { type: "s3_block_public", name: "customer-pii-data-public", config: { blockPublicAccess: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 restrict-policy customer-pii-data", "aws s3 enable-encryption customer-pii-data", "aws s3 enable-logging customer-pii-data", "aws s3 block-public-access customer-pii-data"]
  },
  {
    title: "Supply Chain Attack - Compromised Bucket",
    description: "Threat intelligence indicates a supply chain attack targeting your deployment bucket. Attackers may have injected malicious code. Investigate, contain, and remediate.",
    difficulty: "Advanced",
    category: "Storage Security",
    estimatedTime: "40-55 minutes",
    initialState: { buckets: ["deployment-artifacts", "build-cache"] },
    steps: [
      { number: 1, title: "Threat Intelligence Alert", description: "TI team reports a supply chain attack. Malicious actors are compromising CI/CD artifacts.", hint: "Type 'scan' to identify vulnerable resources." },
      { number: 2, title: "List Deployment Buckets", description: "Identify all buckets in the deployment pipeline.", hint: "Type 'aws s3 ls' to review buckets." },
      { number: 3, title: "Check Cross-Account Access", description: "Verify who has access to deployment artifacts.", hint: "Type 'aws s3 check-access deployment-artifacts'." },
      { number: 4, title: "Identify Unauthorized Access", description: "External account 999888777666 has write access - this is the attack vector.", hint: "MITRE ATT&CK T1195.002: Supply Chain Compromise." },
      { number: 5, title: "Review Bucket Policy", description: "Examine how the malicious access was granted.", hint: "Type 'aws s3 get-policy deployment-artifacts'." },
      { number: 6, title: "Revoke Malicious Access", description: "Immediately remove the unauthorized account.", hint: "Type 'aws s3 revoke-external deployment-artifacts'." },
      { number: 7, title: "Check Object Integrity", description: "Verify if Object Lock could prevent tampering.", hint: "Type 'aws s3 check-object-lock deployment-artifacts'." },
      { number: 8, title: "Enable Object Lock", description: "Prevent future artifact modification.", hint: "Type 'aws s3 enable-object-lock deployment-artifacts'." },
      { number: 9, title: "Enable Versioning", description: "Allow rollback to known-good artifacts.", hint: "Type 'aws s3 enable-versioning deployment-artifacts'." },
      { number: 10, title: "Verify All Controls", description: "Confirm all security measures are in place.", hint: "Type 'scan' to verify." },
      { number: 11, title: "Post-Incident Actions", description: "All artifacts should be rescanned, deployment keys rotated, and build pipeline audited.", hint: "Supply chain secured. Recommend full artifact rescan." }
    ],
    resources: [
      { type: "s3", name: "deployment-artifacts", config: { crossAccount: ["123456789012", "999888777666"] }, isVulnerable: true, status: "active" },
      { type: "s3_object_lock", name: "deployment-artifacts-lock", config: { objectLock: false }, isVulnerable: true, status: "active" },
      { type: "s3_versioning", name: "deployment-artifacts-versioning", config: { versioning: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 revoke-external deployment-artifacts", "aws s3 enable-object-lock deployment-artifacts", "aws s3 enable-versioning deployment-artifacts"]
  }
];

// ============= NETWORK SECURITY LABS (10) =============
export const networkSecurityLabs: LabDefinition[] = [
  // BEGINNER LABS
  {
    title: "Insecure Security Group - SSH Exposed",
    description: "An EC2 instance allows SSH from the entire internet. Quickly restrict access.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["db-prod-01"] },
    steps: [
      { number: 1, title: "Scan for Issues", description: "Identify exposed network ports.", hint: "Type 'scan' to find vulnerabilities." },
      { number: 2, title: "Review Security Group", description: "Check the security group rules.", hint: "Type 'aws ec2 describe-sg db-prod-01'." },
      { number: 3, title: "Restrict SSH Access", description: "Limit SSH to internal networks only.", hint: "Type 'aws ec2 restrict-ssh db-prod-01'." }
    ],
    resources: [
      { type: "security_group", name: "sg-db-prod-01", config: { ingress: [{ port: 22, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-ssh db-prod-01"]
  },
  {
    title: "Open RDP Port to Internet",
    description: "A Windows server has RDP exposed to the world - a common ransomware vector. Close it.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["win-admin-01"] },
    steps: [
      { number: 1, title: "Identify Risk", description: "Scan for exposed RDP ports.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "List Security Groups", description: "Review current configurations.", hint: "Type 'aws ec2 ls-sg'." },
      { number: 3, title: "Restrict RDP", description: "Allow RDP only from VPN.", hint: "Type 'aws ec2 restrict-rdp win-admin-01'." }
    ],
    resources: [
      { type: "security_group", name: "sg-win-admin", config: { ingress: [{ port: 3389, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-rdp win-admin-01"]
  },
  {
    title: "Database Port Exposed",
    description: "MySQL port 3306 is accessible from the internet. Restrict to app servers.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["mysql-prod-01"] },
    steps: [
      { number: 1, title: "Find Exposed Ports", description: "Scan for database exposure.", hint: "Type 'scan' to identify." },
      { number: 2, title: "Check Database SG", description: "Review MySQL security group.", hint: "Type 'aws ec2 describe-sg mysql-prod-01'." },
      { number: 3, title: "Restrict Access", description: "Allow only app server security group.", hint: "Type 'aws ec2 restrict-db mysql-prod-01'." }
    ],
    resources: [
      { type: "security_group", name: "sg-mysql-prod", config: { ingress: [{ port: 3306, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-db mysql-prod-01"]
  },

  // INTERMEDIATE LABS
  {
    title: "Network ACL Misconfiguration",
    description: "A Network ACL allows all inbound traffic, bypassing security group protections. Investigate and fix.",
    difficulty: "Intermediate",
    category: "Network Security",
    estimatedTime: "15-25 minutes",
    initialState: { nacls: ["acl-public-subnet"] },
    steps: [
      { number: 1, title: "Identify NACL Issue", description: "Scan for overly permissive network ACLs.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Understand NACLs", description: "NACLs are stateless and process rules in order. They provide subnet-level security.", hint: "NACLs work with security groups for defense-in-depth." },
      { number: 3, title: "Review NACL Rules", description: "Check current NACL configuration.", hint: "Type 'aws ec2 describe-nacl acl-public-subnet'." },
      { number: 4, title: "Analyze the Risk", description: "The NACL allows all traffic (0.0.0.0/0), making security groups the only protection layer.", hint: "Defense-in-depth requires multiple security layers." },
      { number: 5, title: "Apply Restrictive Rules", description: "Configure deny-by-default with specific allows.", hint: "Type 'aws ec2 fix-nacl acl-public-subnet'." },
      { number: 6, title: "Verify Configuration", description: "Confirm NACL is now properly configured.", hint: "Type 'aws ec2 describe-nacl acl-public-subnet' to verify." }
    ],
    resources: [
      { type: "nacl", name: "acl-public-subnet", config: { inbound: "allow-all" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 fix-nacl acl-public-subnet"]
  },
  {
    title: "VPC Flow Logs Disabled",
    description: "VPC Flow Logs are not enabled, preventing network traffic analysis. Configure logging for security visibility.",
    difficulty: "Intermediate",
    category: "Network Security",
    estimatedTime: "15-25 minutes",
    initialState: { vpcs: ["vpc-production"] },
    steps: [
      { number: 1, title: "Detect Missing Logs", description: "Scan for VPCs without flow logs.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand Flow Logs", description: "VPC Flow Logs capture network traffic metadata for security analysis and troubleshooting.", hint: "Essential for detecting lateral movement and data exfiltration." },
      { number: 3, title: "Check VPC Config", description: "Review current VPC flow log settings.", hint: "Type 'aws ec2 describe-vpc vpc-production'." },
      { number: 4, title: "Enable Flow Logs", description: "Turn on VPC Flow Logs with CloudWatch destination.", hint: "Type 'aws ec2 enable-flow-logs vpc-production'." },
      { number: 5, title: "Verify Logging", description: "Confirm flow logs are now active.", hint: "Type 'aws ec2 describe-vpc vpc-production' to verify." },
      { number: 6, title: "Document Configuration", description: "Flow logs configured. Traffic metadata now available for security analysis.", hint: "Type 'scan' to confirm." }
    ],
    resources: [
      { type: "vpc", name: "vpc-production", config: { flowLogs: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 enable-flow-logs vpc-production"]
  },
  {
    title: "Unrestricted Egress Rules",
    description: "Security groups allow all outbound traffic, enabling data exfiltration. Implement egress filtering.",
    difficulty: "Intermediate",
    category: "Network Security",
    estimatedTime: "15-25 minutes",
    initialState: { instances: ["app-server-01"] },
    steps: [
      { number: 1, title: "Identify Egress Risk", description: "Scan for unrestricted outbound rules.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Understand Egress Security", description: "Unrestricted egress allows compromised instances to exfiltrate data or communicate with C2 servers.", hint: "MITRE ATT&CK T1041: Exfiltration Over C2 Channel." },
      { number: 3, title: "Check Egress Rules", description: "Review current outbound security group rules.", hint: "Type 'aws ec2 describe-egress app-server-01'." },
      { number: 4, title: "Analyze Traffic Needs", description: "Application servers typically only need HTTPS to specific endpoints.", hint: "Principle of least privilege applies to network rules too." },
      { number: 5, title: "Restrict Egress", description: "Allow only necessary outbound traffic.", hint: "Type 'aws ec2 restrict-egress app-server-01'." },
      { number: 6, title: "Verify Egress Rules", description: "Confirm egress is now restricted.", hint: "Type 'aws ec2 describe-egress app-server-01' to verify." }
    ],
    resources: [
      { type: "security_group", name: "sg-app-server", config: { egress: "0.0.0.0/0:all" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-egress app-server-01"]
  },
  {
    title: "Unused Elastic IP Audit",
    description: "Security audit identified unassociated Elastic IPs. Clean up unused resources and document findings.",
    difficulty: "Intermediate",
    category: "Network Security",
    estimatedTime: "15-20 minutes",
    initialState: { eips: ["eip-unattached"] },
    steps: [
      { number: 1, title: "Find Unused EIPs", description: "Scan for unattached Elastic IPs.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand the Risk", description: "Unused EIPs waste money and can cause confusion during incident response.", hint: "AWS charges for unattached EIPs." },
      { number: 3, title: "List All EIPs", description: "Review all allocated Elastic IPs.", hint: "Type 'aws ec2 describe-eips'." },
      { number: 4, title: "Verify Not In Use", description: "Confirm the EIP is truly unused before releasing.", hint: "Check with application teams before removing." },
      { number: 5, title: "Release Unused EIP", description: "Release the unattached Elastic IP.", hint: "Type 'aws ec2 release-eip eip-unattached'." },
      { number: 6, title: "Document Cleanup", description: "Record the cleanup for audit purposes.", hint: "Type 'scan' to confirm." }
    ],
    resources: [
      { type: "eip", name: "eip-unattached", config: { associated: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 release-eip eip-unattached"]
  },

  // ADVANCED LABS
  {
    title: "Web Application Firewall Deployment",
    description: "An internet-facing ALB lacks WAF protection. Deploy AWS WAF with appropriate rule sets and verify protection against common attacks.",
    difficulty: "Advanced",
    category: "Network Security",
    estimatedTime: "30-45 minutes",
    initialState: { loadBalancers: ["alb-web-frontend"], waf: ["waf-managed-rules"] },
    steps: [
      { number: 1, title: "Initial Assessment", description: "Scan for unprotected internet-facing resources.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand WAF Protection", description: "AWS WAF protects against SQL injection, XSS, and other OWASP Top 10 attacks.", hint: "WAF is essential for any internet-facing application." },
      { number: 3, title: "Check Current WAF Status", description: "Verify WAF association with the ALB.", hint: "Type 'aws waf check-association alb-web-frontend'." },
      { number: 4, title: "Review Attack Surface", description: "The ALB handles all user traffic. Without WAF, it's vulnerable to web attacks.", hint: "MITRE ATT&CK T1190: Exploit Public-Facing Application." },
      { number: 5, title: "Plan Rule Sets", description: "Determine which managed rules to enable: CommonRuleSet, SQLiRuleSet, KnownBadInputsRuleSet.", hint: "Start with AWS managed rules, then customize." },
      { number: 6, title: "Associate WAF", description: "Attach AWS WAF with managed rule groups to the ALB.", hint: "Type 'aws waf associate alb-web-frontend'." },
      { number: 7, title: "Verify WAF Protection", description: "Confirm WAF is now protecting the ALB.", hint: "Type 'aws waf check-association alb-web-frontend' to verify." },
      { number: 8, title: "Review Active Rules", description: "The following rule groups are now active: AWSManagedRulesCommonRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesKnownBadInputsRuleSet.", hint: "These rules block common attack patterns." },
      { number: 9, title: "Final Verification", description: "Run security scan to confirm protection.", hint: "Type 'scan' to verify." },
      { number: 10, title: "Document Deployment", description: "WAF deployed successfully. Monitor CloudWatch for blocked requests and tune rules as needed.", hint: "Recommend enabling WAF logging for threat analysis." }
    ],
    resources: [
      { type: "alb", name: "alb-web-frontend", config: { waf: false, internetFacing: true }, isVulnerable: true, status: "active" },
      { type: "waf_rules", name: "waf-managed-rules", config: { ruleSets: ["CommonRuleSet", "SQLiRuleSet", "KnownBadInputsRuleSet"] }, isVulnerable: false, status: "available" }
    ],
    fixCommands: ["aws waf associate alb-web-frontend"]
  },
  {
    title: "VPC Peering Security Audit",
    description: "A VPC peering connection allows routing to all subnets. Investigate the blast radius and implement network segmentation.",
    difficulty: "Advanced",
    category: "Network Security",
    estimatedTime: "35-50 minutes",
    initialState: { peering: ["pcx-partner-connection"], vpcs: ["vpc-production", "vpc-partner"] },
    steps: [
      { number: 1, title: "Identify Peering Risk", description: "Scan for overly permissive VPC peering.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Understand VPC Peering", description: "VPC peering connects two VPCs privately. Routes determine what traffic is allowed.", hint: "Overly broad routes expose sensitive subnets." },
      { number: 3, title: "Review Peering Configuration", description: "Check current peering routes and configuration.", hint: "Type 'aws ec2 describe-peering pcx-partner-connection'." },
      { number: 4, title: "Analyze Blast Radius", description: "Route 0.0.0.0/0 means ALL subnets are accessible: databases, internal services, everything.", hint: "Partner should only access specific application subnets." },
      { number: 5, title: "Plan Segmentation", description: "Identify which subnets the partner actually needs access to.", hint: "Principle of least privilege for network access." },
      { number: 6, title: "Restrict Peering Routes", description: "Limit routes to specific application subnets only.", hint: "Type 'aws ec2 restrict-peering pcx-partner-connection'." },
      { number: 7, title: "Verify Route Changes", description: "Confirm routes are now restricted.", hint: "Type 'aws ec2 describe-peering pcx-partner-connection' to verify." },
      { number: 8, title: "Update Security Groups", description: "Ensure security groups also restrict traffic from peered VPC.", hint: "Defense-in-depth: routes + security groups." },
      { number: 9, title: "Final Verification", description: "Run comprehensive security scan.", hint: "Type 'scan' to verify all changes." },
      { number: 10, title: "Document Changes", description: "Peering now restricted to application subnets only. Partner VPC cannot access database or internal subnets.", hint: "Network segmentation complete." }
    ],
    resources: [
      { type: "vpc_peering", name: "pcx-partner-connection", config: { routes: "0.0.0.0/0" }, isVulnerable: true, status: "active" },
      { type: "vpc", name: "vpc-production", config: { subnets: ["app-subnet", "db-subnet", "internal-subnet"] }, isVulnerable: false, status: "info" },
      { type: "vpc", name: "vpc-partner", config: { allowedSubnets: ["app-subnet"] }, isVulnerable: false, status: "info" }
    ],
    fixCommands: ["aws ec2 restrict-peering pcx-partner-connection"]
  },
  {
    title: "Transit Gateway Route Leak Investigation",
    description: "A Transit Gateway is propagating routes to all attached VPCs, creating unintended connectivity between isolated environments. Investigate and fix the route leak.",
    difficulty: "Advanced",
    category: "Network Security",
    estimatedTime: "40-55 minutes",
    initialState: { tgw: ["tgw-central-hub"], vpcs: ["vpc-prod", "vpc-dev", "vpc-security"] },
    steps: [
      { number: 1, title: "Detect Route Leak", description: "Scan for Transit Gateway misconfigurations.", hint: "Type 'scan' to identify problems." },
      { number: 2, title: "Understand Transit Gateways", description: "Transit Gateways connect multiple VPCs. Route propagation controls which VPCs can communicate.", hint: "Automatic propagation can create unintended connectivity." },
      { number: 3, title: "Review TGW Configuration", description: "Check Transit Gateway route tables and associations.", hint: "Type 'aws ec2 describe-tgw tgw-central-hub'." },
      { number: 4, title: "Identify the Problem", description: "Route propagation is set to 'all-vpcs'. Dev can reach Prod, Security can reach Dev, etc.", hint: "This violates environment isolation requirements." },
      { number: 5, title: "Map Current Connectivity", description: "Document unintended connectivity paths: Dev->Prod, Prod->Security, etc.", hint: "This could allow lateral movement in a breach." },
      { number: 6, title: "Plan Isolation Strategy", description: "Prod should only connect to Security. Dev should be completely isolated.", hint: "Create separate route tables per environment." },
      { number: 7, title: "Fix Route Propagation", description: "Disable automatic route propagation and configure static routes.", hint: "Type 'aws ec2 fix-tgw-routes tgw-central-hub'." },
      { number: 8, title: "Verify VPC Isolation", description: "Confirm VPCs are now properly isolated.", hint: "Type 'aws ec2 describe-tgw tgw-central-hub' to verify." },
      { number: 9, title: "Test Connectivity", description: "Verify Prod can reach Security, but Dev cannot reach Prod.", hint: "Environment isolation restored." },
      { number: 10, title: "Final Verification", description: "Run comprehensive security scan.", hint: "Type 'scan' to confirm all issues resolved." },
      { number: 11, title: "Document Network Architecture", description: "Transit Gateway now properly segments environments. Recommend quarterly route table audits.", hint: "Network segmentation complete." }
    ],
    resources: [
      { type: "transit_gateway", name: "tgw-central-hub", config: { propagation: "all-vpcs" }, isVulnerable: true, status: "active" },
      { type: "vpc", name: "vpc-prod", config: { environment: "production", shouldConnect: ["vpc-security"] }, isVulnerable: false, status: "info" },
      { type: "vpc", name: "vpc-dev", config: { environment: "development", shouldConnect: [] }, isVulnerable: false, status: "info" },
      { type: "vpc", name: "vpc-security", config: { environment: "security", shouldConnect: ["vpc-prod"] }, isVulnerable: false, status: "info" }
    ],
    fixCommands: ["aws ec2 fix-tgw-routes tgw-central-hub"]
  }
];

// ============= SOC OPERATIONS LABS (10) =============
export const socOperationsLabs: LabDefinition[] = [
  // BEGINNER LABS
  {
    title: "CloudTrail Logging Disabled",
    description: "CloudTrail logging was disabled, creating a visibility gap. Re-enable it quickly.",
    difficulty: "Beginner",
    category: "SOC Operations",
    estimatedTime: "5-10 minutes",
    initialState: { trails: ["main-trail"] },
    steps: [
      { number: 1, title: "Detect Issue", description: "Scan for CloudTrail problems.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Trail Status", description: "Review CloudTrail configuration.", hint: "Type 'aws cloudtrail status main-trail'." },
      { number: 3, title: "Enable Logging", description: "Turn CloudTrail logging back on.", hint: "Type 'aws cloudtrail enable main-trail'." }
    ],
    resources: [
      { type: "cloudtrail", name: "main-trail", config: { logging: false }, isVulnerable: true, status: "disabled" }
    ],
    fixCommands: ["aws cloudtrail enable main-trail"]
  },
  {
    title: "GuardDuty Crypto Mining Alert",
    description: "GuardDuty detected an EC2 instance communicating with crypto mining pools. Isolate it.",
    difficulty: "Beginner",
    category: "SOC Operations",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["web-server-03"] },
    steps: [
      { number: 1, title: "Review Alert", description: "Check GuardDuty findings.", hint: "Type 'aws guardduty get-findings'." },
      { number: 2, title: "Identify Instance", description: "Determine which instance is compromised.", hint: "Type 'scan' to see affected resources." },
      { number: 3, title: "Isolate Instance", description: "Quarantine the compromised instance.", hint: "Type 'aws ec2 isolate web-server-03'." }
    ],
    resources: [
      { type: "ec2", name: "web-server-03", config: { mining: true, pool: "pool.minexmr.com" }, isVulnerable: true, status: "compromised" }
    ],
    fixCommands: ["aws ec2 isolate web-server-03"]
  },
  {
    title: "Suspicious SSM Session",
    description: "An SSM session was initiated from an unusual location. Terminate it immediately.",
    difficulty: "Beginner",
    category: "SOC Operations",
    estimatedTime: "5-10 minutes",
    initialState: { sessions: ["ssm-session-xyz"] },
    steps: [
      { number: 1, title: "Detect Session", description: "Scan for unusual SSM activity.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Sessions", description: "List all active SSM sessions.", hint: "Type 'aws ssm list-sessions'." },
      { number: 3, title: "Terminate Session", description: "End the suspicious session.", hint: "Type 'aws ssm terminate ssm-session-xyz'." }
    ],
    resources: [
      { type: "ssm_session", name: "ssm-session-xyz", config: { sourceIP: "185.220.101.42", user: "unknown" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ssm terminate ssm-session-xyz"]
  },

  // INTERMEDIATE LABS
  {
    title: "Unauthorized IAM Policy Change",
    description: "An IAM policy was modified to grant administrative access. Investigate the change and revert it.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    estimatedTime: "15-25 minutes",
    initialState: { policies: ["developer-policy"] },
    steps: [
      { number: 1, title: "Detect Policy Change", description: "Scan for unauthorized modifications.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand the Risk", description: "Privilege escalation via policy modification is a common attack technique.", hint: "MITRE ATT&CK T1098: Account Manipulation." },
      { number: 3, title: "Review Policy History", description: "Check policy version history to see what changed.", hint: "Type 'aws iam get-policy-versions developer-policy'." },
      { number: 4, title: "Analyze the Change", description: "Policy was escalated from ReadOnlyAccess to AdministratorAccess. This is a critical privilege escalation.", hint: "Someone either made an error or this is malicious." },
      { number: 5, title: "Revert Policy", description: "Restore the previous policy version.", hint: "Type 'aws iam revert-policy developer-policy'." },
      { number: 6, title: "Verify Reversion", description: "Confirm policy is back to original permissions.", hint: "Type 'aws iam get-policy-versions developer-policy' to verify." }
    ],
    resources: [
      { type: "iam_policy", name: "developer-policy", config: { modified: true, grants: "AdministratorAccess" }, isVulnerable: true, status: "modified" }
    ],
    fixCommands: ["aws iam revert-policy developer-policy"]
  },
  {
    title: "KMS Key Scheduled for Deletion",
    description: "A critical KMS key is scheduled for deletion. Cancel the deletion before encrypted data becomes unrecoverable.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    estimatedTime: "15-25 minutes",
    initialState: { keys: ["kms-prod-encryption"] },
    steps: [
      { number: 1, title: "Detect Pending Deletion", description: "Scan for keys scheduled for deletion.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand the Impact", description: "Once a KMS key is deleted, all data encrypted with it becomes permanently unrecoverable.", hint: "This could be a destructive attack or accidental misconfiguration." },
      { number: 3, title: "Check Key Status", description: "Review KMS key configuration and deletion date.", hint: "Type 'aws kms describe-key kms-prod-encryption'." },
      { number: 4, title: "Identify Affected Resources", description: "This key encrypts production database snapshots, S3 objects, and EBS volumes.", hint: "Losing this key would be catastrophic." },
      { number: 5, title: "Cancel Deletion", description: "Stop the key deletion immediately.", hint: "Type 'aws kms cancel-deletion kms-prod-encryption'." },
      { number: 6, title: "Verify Key Status", description: "Confirm key is no longer pending deletion.", hint: "Type 'aws kms describe-key kms-prod-encryption' to verify." }
    ],
    resources: [
      { type: "kms_key", name: "kms-prod-encryption", config: { pendingDeletion: true, deletionDate: "2025-02-01" }, isVulnerable: true, status: "pending-deletion" }
    ],
    fixCommands: ["aws kms cancel-deletion kms-prod-encryption"]
  },
  {
    title: "Root Account Activity Investigation",
    description: "The AWS root account was used for administrative actions. Investigate and secure the account.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    estimatedTime: "15-25 minutes",
    initialState: { accounts: ["root"] },
    steps: [
      { number: 1, title: "Detect Root Usage", description: "Scan for root account activity.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand the Risk", description: "Root account usage should be extremely rare. Any activity is suspicious.", hint: "Best practice: Lock root account with MFA and no access keys." },
      { number: 3, title: "Review Root Activity", description: "Check what actions root performed.", hint: "Type 'aws cloudtrail lookup-root'." },
      { number: 4, title: "Analyze Actions", description: "Root created a new user 'backdoor-admin' with AdministratorAccess. This is likely malicious.", hint: "MITRE ATT&CK T1136: Create Account." },
      { number: 5, title: "Secure Root Account", description: "Enable MFA and remove any access keys.", hint: "Type 'aws iam secure-root'." },
      { number: 6, title: "Verify Security", description: "Confirm root is now secured.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "iam_root", name: "root-account", config: { mfa: false, accessKeys: true }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws iam secure-root"]
  },
  {
    title: "EventBridge Persistence Mechanism",
    description: "An attacker created an EventBridge rule to maintain persistence. Identify and remove the malicious rule.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    estimatedTime: "20-30 minutes",
    initialState: { rules: ["malicious-persistence-rule"] },
    steps: [
      { number: 1, title: "Detect Malicious Rule", description: "Scan for suspicious EventBridge rules.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand Persistence", description: "Attackers use EventBridge to trigger on security events and restore access if removed.", hint: "MITRE ATT&CK T1546: Event Triggered Execution." },
      { number: 3, title: "Analyze Rule", description: "Review the rule configuration and target.", hint: "Type 'aws events describe-rule malicious-persistence-rule'." },
      { number: 4, title: "Identify the Threat", description: "Rule triggers on 'iam:*' events and invokes 'malicious-lambda'. This restores attacker access when IAM changes occur.", hint: "Sophisticated persistence mechanism." },
      { number: 5, title: "Delete Rule", description: "Remove the malicious persistence mechanism.", hint: "Type 'aws events delete-rule malicious-persistence-rule'." },
      { number: 6, title: "Verify Deletion", description: "Confirm rule is removed.", hint: "Type 'scan' to verify." },
      { number: 7, title: "Follow-up Actions", description: "Also investigate and remove the malicious Lambda function referenced by this rule.", hint: "Check for other persistence mechanisms." }
    ],
    resources: [
      { type: "eventbridge_rule", name: "malicious-persistence-rule", config: { pattern: "iam:*", target: "malicious-lambda" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws events delete-rule malicious-persistence-rule"]
  },

  // ADVANCED LABS
  {
    title: "Credential Compromise - Full Investigation",
    description: "GuardDuty flagged suspicious API activity from an IAM user. Conduct a full investigation: analyze CloudTrail logs, identify the attack timeline, revoke credentials, and document the incident.",
    difficulty: "Advanced",
    category: "SOC Operations",
    estimatedTime: "35-50 minutes",
    initialState: { logs: ["cloudtrail-events"], compromisedUser: "dev-jenkins-sa" },
    steps: [
      { number: 1, title: "Initial Alert Triage", description: "GuardDuty detected UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration. Begin investigation.", hint: "Type 'scan' to assess current state." },
      { number: 2, title: "Understand the Threat", description: "Credential compromise allows attackers to impersonate legitimate users. This is MITRE ATT&CK T1078: Valid Accounts.", hint: "Priority: Stop the bleeding, then investigate." },
      { number: 3, title: "Query CloudTrail Logs", description: "Examine recent API calls to understand the scope.", hint: "Type 'aws cloudtrail lookup-events'." },
      { number: 4, title: "Analyze Attack Timeline", description: "08:23:15 CreateAccessKey, 08:24:02 AssumeRole to AdminRole, 08:25:30 ListBuckets, 08:26:45 GetObject on PII data.", hint: "Attacker escalated privileges and accessed sensitive data." },
      { number: 5, title: "Identify IOCs", description: "Source IP 185.220.101.42 is a known Tor exit node. This confirms malicious activity.", hint: "Document all Indicators of Compromise." },
      { number: 6, title: "Identify Compromised Credentials", description: "Determine which credentials were used.", hint: "Type 'aws iam list-compromised'." },
      { number: 7, title: "Revoke Compromised Credentials", description: "Immediately deactivate the compromised access keys.", hint: "Type 'aws iam revoke-keys dev-jenkins-sa'." },
      { number: 8, title: "Verify Revocation", description: "Confirm access keys are deactivated.", hint: "Type 'aws iam list-compromised' should show secured status." },
      { number: 9, title: "Assess Data Exposure", description: "Attacker accessed customer-pii-data bucket. Potential data breach notification required.", hint: "Document all accessed resources." },
      { number: 10, title: "Generate Incident Report", description: "Create formal incident documentation.", hint: "Type 'report incident' to generate report." },
      { number: 11, title: "Post-Incident Actions", description: "Rotate all affected secrets, enable MFA for service accounts, implement credential rotation policy.", hint: "Incident contained. Begin remediation phase." }
    ],
    resources: [
      { type: "cloudtrail", name: "suspicious-api-activity", config: { events: [
        { eventName: "CreateAccessKey", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:23:15Z" },
        { eventName: "AssumeRole", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", targetRole: "AdminRole", timestamp: "2025-01-15T08:24:02Z" },
        { eventName: "ListBuckets", userIdentity: "AdminRole", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:25:30Z" },
        { eventName: "GetObject", userIdentity: "AdminRole", sourceIP: "185.220.101.42", bucket: "customer-pii-data", timestamp: "2025-01-15T08:26:45Z" }
      ]}, isVulnerable: true, status: "active" },
      { type: "iam_user", name: "dev-jenkins-sa", config: { accessKeyAge: "180 days", permissions: ["s3:*", "iam:CreateAccessKey", "sts:AssumeRole"] }, isVulnerable: true, status: "compromised" }
    ],
    fixCommands: ["aws iam revoke-keys dev-jenkins-sa"]
  },
  {
    title: "Cross-Account Role Assumption Attack",
    description: "An attacker is using a compromised role to pivot to other AWS accounts. Trace the role assumption chain, identify all compromised accounts, and revoke trust relationships.",
    difficulty: "Advanced",
    category: "SOC Operations",
    estimatedTime: "40-55 minutes",
    initialState: { roles: ["cross-account-role"] },
    steps: [
      { number: 1, title: "Detect Cross-Account Activity", description: "Scan for suspicious cross-account role assumptions.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Understand the Attack", description: "Cross-account role assumption allows attackers to pivot between AWS accounts if trust policies are misconfigured.", hint: "MITRE ATT&CK T1550.001: Use Alternate Authentication Material." },
      { number: 3, title: "Trace Role Chain", description: "Follow the assume role events to map the attack path.", hint: "Type 'aws cloudtrail trace-roles'." },
      { number: 4, title: "Analyze Attack Path", description: "Developer -> cross-account-role (this account) -> external-admin (account 999888777666). Attacker pivoted to external account.", hint: "The external account may be attacker-controlled." },
      { number: 5, title: "Verify Trust Policy", description: "Check which accounts can assume this role.", hint: "External account 999888777666 should not be in the trust policy." },
      { number: 6, title: "Assess Blast Radius", description: "What permissions does cross-account-role have? What could the attacker do?", hint: "Document all potential actions the attacker could take." },
      { number: 7, title: "Revoke Trust Policy", description: "Remove external account from the trust relationship.", hint: "Type 'aws iam revoke-trust cross-account-role'." },
      { number: 8, title: "Verify Revocation", description: "Confirm external account can no longer assume the role.", hint: "Trust policy should only include authorized accounts." },
      { number: 9, title: "Check for Lateral Movement", description: "Did the attacker create any other persistence mechanisms while they had access?", hint: "Check for new roles, users, or access keys." },
      { number: 10, title: "Final Verification", description: "Run comprehensive security scan.", hint: "Type 'scan' to verify all issues resolved." },
      { number: 11, title: "Document Incident", description: "Attack path traced, trust revoked, lateral movement investigated. Recommend trust policy review for all cross-account roles.", hint: "Cross-account attack contained." }
    ],
    resources: [
      { type: "iam_role", name: "cross-account-role", config: { trustedAccounts: ["999888777666"] }, isVulnerable: true, status: "compromised" },
      { type: "cloudtrail_evidence", name: "cross-account-trail", config: { roleChain: ["developer", "cross-account-role", "external-admin"] }, isVulnerable: false, status: "evidence" }
    ],
    fixCommands: ["aws iam revoke-trust cross-account-role"]
  },
  {
    title: "Data Exfiltration via DataSync",
    description: "Security monitoring detected large data transfers to an external location. Investigate the DataSync configuration, stop the exfiltration, and assess data loss.",
    difficulty: "Advanced",
    category: "SOC Operations",
    estimatedTime: "40-55 minutes",
    initialState: { tasks: ["datasync-exfil-task"] },
    steps: [
      { number: 1, title: "Initial Detection", description: "Network monitoring flagged unusual data transfer volumes. Investigate.", hint: "Type 'scan' to identify suspicious activity." },
      { number: 2, title: "Understand DataSync", description: "AWS DataSync automates data transfers. Attackers can abuse it to exfiltrate large volumes of data.", hint: "MITRE ATT&CK T1537: Transfer Data to Cloud Account." },
      { number: 3, title: "Review DataSync Tasks", description: "Check DataSync task configuration.", hint: "Type 'aws datasync describe-task datasync-exfil-task'." },
      { number: 4, title: "Analyze Transfer Details", description: "Destination: external-bucket. Status: running. Data Transferred: 2.4 TB. This is active exfiltration.", hint: "Immediate action required to stop data loss." },
      { number: 5, title: "Assess Source Data", description: "What data is being transferred? Identify source location and data sensitivity.", hint: "Check the source location configuration." },
      { number: 6, title: "Stop Data Transfer", description: "Immediately terminate the DataSync task.", hint: "Type 'aws datasync stop-task datasync-exfil-task'." },
      { number: 7, title: "Verify Task Stopped", description: "Confirm the transfer has been halted.", hint: "Type 'aws datasync describe-task datasync-exfil-task' to verify stopped status." },
      { number: 8, title: "Investigate Origin", description: "How was this task created? Check CloudTrail for CreateTask events.", hint: "Identify who created the malicious task." },
      { number: 9, title: "Assess Data Loss", description: "2.4 TB of data was transferred. Identify exactly what was exfiltrated for breach notification.", hint: "May require legal and compliance notification." },
      { number: 10, title: "Block External Destination", description: "Add the external bucket to deny list in SCPs or bucket policies.", hint: "Prevent future transfers to this destination." },
      { number: 11, title: "Final Verification", description: "Run security scan to confirm remediation.", hint: "Type 'scan' to verify." },
      { number: 12, title: "Incident Report", description: "Exfiltration stopped after 2.4 TB transferred. External destination identified. Recommend DataSync permission review and enhanced monitoring.", hint: "Data breach investigation required." }
    ],
    resources: [
      { type: "datasync_task", name: "datasync-exfil-task", config: { destination: "external-bucket", status: "running", dataTransferred: "2.4 TB" }, isVulnerable: true, status: "running" },
      { type: "cloudtrail_evidence", name: "datasync-creation-trail", config: { creator: "compromised-user", createTime: "2025-01-15T02:15:00Z" }, isVulnerable: false, status: "evidence" }
    ],
    fixCommands: ["aws datasync stop-task datasync-exfil-task"]
  }
];

// ============= CHALLENGE LABS (No guidance - practice independently) =============
export const challengeLabs: LabDefinition[] = [
  // Storage Security Challenge
  {
    title: "Storage Security Challenge",
    description: "Multiple S3 buckets have various security issues. Identify all vulnerabilities and fix them without guidance. Test your storage security skills!",
    difficulty: "Challenge",
    category: "Storage Security",
    estimatedTime: "20-40 minutes",
    initialState: { buckets: ["challenge-bucket-1", "challenge-bucket-2", "challenge-bucket-3"] },
    steps: [
      { number: 1, title: "Complete the Objective", description: "Find and fix all storage security vulnerabilities. Use 'scan' to discover issues, then apply the appropriate fixes. No hints provided - you're on your own!", hint: "Use your knowledge from previous labs." }
    ],
    resources: [
      { type: "s3", name: "challenge-bucket-1", config: { access: "public-read", encryption: "none" }, isVulnerable: true, status: "active" },
      { type: "s3", name: "challenge-bucket-2", config: { logging: "disabled", versioning: "disabled" }, isVulnerable: true, status: "active" },
      { type: "s3", name: "challenge-bucket-3", config: { policy: "overly-permissive" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 fix challenge-bucket-1", "aws s3 enable-encryption challenge-bucket-1", "aws s3 enable-logging challenge-bucket-2", "aws s3 enable-versioning challenge-bucket-2", "aws s3 fix-policy challenge-bucket-3"]
  },
  // Network Security Challenge
  {
    title: "Network Security Challenge",
    description: "Your infrastructure has multiple network security misconfigurations. Find all exposed ports and insecure rules without any guidance. Prove your network security expertise!",
    difficulty: "Challenge",
    category: "Network Security",
    estimatedTime: "20-40 minutes",
    initialState: { instances: ["challenge-instance-1", "challenge-instance-2"] },
    steps: [
      { number: 1, title: "Complete the Objective", description: "Identify and remediate all network security issues. Scan the infrastructure, analyze security groups, and lock down all exposed services. No step-by-step guidance!", hint: "Apply what you've learned." }
    ],
    resources: [
      { type: "ec2", name: "challenge-instance-1", config: { securityGroup: "sg-challenge-1", exposedPorts: [22, 3389, 3306] }, isVulnerable: true, status: "running" },
      { type: "security_group", name: "sg-challenge-1", config: { inboundRules: [{ port: 22, source: "0.0.0.0/0" }, { port: 3389, source: "0.0.0.0/0" }, { port: 3306, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" },
      { type: "ec2", name: "challenge-instance-2", config: { securityGroup: "sg-challenge-2", exposedPorts: [80, 443, 8080] }, isVulnerable: true, status: "running" }
    ],
    fixCommands: ["aws ec2 restrict-ssh challenge-instance-1", "aws ec2 restrict-rdp challenge-instance-1", "aws ec2 restrict-db challenge-instance-1"]
  },
  // SOC Operations Challenge
  {
    title: "SOC Operations Challenge",
    description: "Your SOC dashboard shows multiple alerts. Investigate the incidents, identify the attack chain, and respond appropriately - all without any guidance. Show your incident response skills!",
    difficulty: "Challenge",
    category: "SOC Operations",
    estimatedTime: "25-45 minutes",
    initialState: { alerts: ["challenge-alert-1", "challenge-alert-2", "challenge-alert-3"] },
    steps: [
      { number: 1, title: "Complete the Objective", description: "Analyze all security alerts, investigate using CloudTrail and GuardDuty, identify compromised resources, and take appropriate remediation actions. No hints - this is your final test!", hint: "Think like a SOC analyst." }
    ],
    resources: [
      { type: "cloudtrail_log", name: "challenge-trail", config: { suspiciousEvents: ["UnauthorizedAPICall", "PolicyChanged", "RoleCreated"] }, isVulnerable: false, status: "evidence" },
      { type: "guardduty_alert", name: "challenge-alert", config: { alertType: "UnauthorizedAccess:IAMUser/MaliciousIPCaller", severity: "HIGH" }, isVulnerable: false, status: "active" },
      { type: "iam_user", name: "challenge-compromised-user", config: { hasExcessivePermissions: true, suspiciousActivity: true }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws iam disable-user challenge-compromised-user", "aws cloudtrail enable challenge-trail"]
  }
];

export const allLabs = [
  ...storageSecurityLabs,
  ...networkSecurityLabs,
  ...socOperationsLabs,
  ...challengeLabs
];
