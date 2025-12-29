// Lab Definitions for CloudShieldLab - 57 Labs (5 categories)
// Difficulty Levels:
// - Beginner: 3-4 steps, single resource, quick fix
// - Intermediate: 5-7 steps, multiple phases, verification required
// - Advanced: 8-12 steps, multi-stage attack chains, forensics, multiple resources
// - Challenge: 1 step (objective only), no guidance - users practice independently

export interface LabDefinition {
  title: string;
  description: string;
  briefing?: string;
  scenario?: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced" | "Challenge";
  category: "Storage Security" | "Network Security" | "SOC Operations" | "SOC Engineer" | "Cloud Security Analyst" | "IAM Security" | "Cloud Security Engineer";
  estimatedTime: string;
  initialState: Record<string, unknown>;
  steps: Array<{
    number: number;
    title: string;
    description: string;
    hint: string;
    intel?: string;
  }>;
  resources: Array<{
    type: string;
    name: string;
    config: Record<string, unknown>;
    isVulnerable: boolean;
    status: string;
  }>;
  fixCommands: string[];
  successMessage?: string;
}

// ============= STORAGE SECURITY LABS (11) =============
export const storageSecurityLabs: LabDefinition[] = [
  // BEGINNER LABS (3-4 steps, quick fixes)
  {
    title: "Public S3 Bucket Exposure",
    description: "A sensitive corporate S3 bucket has been accidentally left open to the public. Identify and secure it quickly.",
    briefing: "URGENT ALERT: Our threat intelligence feed detected the 'corp-payroll-data' bucket appearing on a dark web forum listing exposed AWS resources. A security researcher notified us before threat actors could exploit it. You have 10 minutes before this hits the news.",
    scenario: "It's 3:47 AM. Your phone buzzes with a PagerDuty alert. A Twitter bot that monitors exposed S3 buckets just flagged your company's payroll data. The CFO's salary, everyone's SSNs, bank account details - all potentially exposed. Your mission: contain this before market open.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["corp-payroll-data"] },
    steps: [
      { number: 1, title: "Threat Assessment", description: "Run an immediate security scan to assess the damage. How many resources are exposed?", hint: "Type 'scan' to see vulnerable resources.", intel: "The bucket was likely misconfigured during last week's migration. Always verify permissions after infrastructure changes." },
      { number: 2, title: "Confirm the Target", description: "List all S3 buckets and identify which one is leaking sensitive payroll data.", hint: "Type 'aws s3 ls' to list buckets.", intel: "Look for naming patterns. 'corp-payroll-data' suggests high-value PII content." },
      { number: 3, title: "Execute Remediation", description: "Apply an emergency bucket policy to block all public access immediately.", hint: "Type 'aws s3 fix corp-payroll-data' to secure it.", intel: "After fixing, you'll need to check CloudTrail logs to see if anyone accessed the data during the exposure window." }
    ],
    resources: [
      { type: "s3", name: "corp-payroll-data", config: { access: "public-read" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 fix corp-payroll-data"],
    successMessage: "Bucket secured! You contained a potential data breach. Next step: forensics to determine if any data was exfiltrated during the exposure window."
  },
  {
    title: "Unencrypted S3 Bucket",
    description: "Customer data is stored without encryption. Enable server-side encryption to protect data at rest.",
    briefing: "COMPLIANCE VIOLATION: The quarterly security audit flagged a critical finding - customer data in 'customer-data-raw' is stored in plaintext. This violates PCI-DSS and could result in $100K/day in fines. Remediate within 24 hours.",
    scenario: "The compliance team is breathing down your neck. An auditor discovered that credit card data flows through an unencrypted bucket before processing. If regulators find out, it's not just fines - your company could lose its ability to process payments entirely.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["customer-data-raw"] },
    steps: [
      { number: 1, title: "Audit the Environment", description: "Scan your infrastructure to find all unencrypted storage resources.", hint: "Type 'scan' to find vulnerabilities.", intel: "PCI-DSS Requirement 3.4: Render PAN unreadable anywhere it is stored using encryption." },
      { number: 2, title: "Verify Encryption Gap", description: "Confirm which buckets lack server-side encryption.", hint: "Type 'aws s3 ls-encryption' to check.", intel: "AWS offers SSE-S3 (AES-256), SSE-KMS, and SSE-C. For PCI compliance, SSE-KMS with CMK is recommended." },
      { number: 3, title: "Enable Encryption", description: "Apply AES-256 server-side encryption to protect data at rest.", hint: "Type 'aws s3 enable-encryption customer-data-raw'.", intel: "Enabling encryption on existing buckets only affects new objects. Run aws s3 cp to re-encrypt existing objects." }
    ],
    resources: [
      { type: "s3", name: "customer-data-raw", config: { encryption: "none" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-encryption customer-data-raw"],
    successMessage: "Encryption enabled! Document this remediation for the auditors and schedule a re-audit to close the finding."
  },
  {
    title: "S3 Bucket Logging Disabled",
    description: "Access logging is disabled, making it impossible to audit data access. Enable logging.",
    briefing: "BLIND SPOT DETECTED: The SOC team tried to investigate suspicious activity on 'financial-reports' bucket but discovered logging was never enabled. We're flying blind - any past intrusions would be undetectable.",
    scenario: "The CISO wants answers: 'Who accessed the Q3 financial reports before the earnings call?' You check the logs... there are none. Someone disabled logging on this critical bucket. Without audit trails, insider trading investigations hit a dead end.",
    difficulty: "Beginner",
    category: "Storage Security",
    estimatedTime: "5-10 minutes",
    initialState: { buckets: ["financial-reports"] },
    steps: [
      { number: 1, title: "Identify Blind Spots", description: "Scan for buckets that lack proper audit logging.", hint: "Type 'scan' to identify issues.", intel: "CIS AWS Benchmark 2.1.3: Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket." },
      { number: 2, title: "Confirm Logging Gap", description: "Check the current logging configuration on the financial reports bucket.", hint: "Type 'aws s3 ls-logging' to check.", intel: "S3 access logs include requester, bucket name, request time, action, response status, and error codes." },
      { number: 3, title: "Enable Audit Trail", description: "Turn on server access logging to capture all future activity.", hint: "Type 'aws s3 enable-logging financial-reports'.", intel: "Logs are delivered on a best-effort basis within a few hours. For real-time alerting, use CloudTrail with EventBridge." }
    ],
    resources: [
      { type: "s3", name: "financial-reports", config: { logging: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-logging financial-reports"],
    successMessage: "Logging enabled! Future access will be tracked. Consider enabling CloudTrail data events for real-time monitoring."
  },

  // INTERMEDIATE LABS (5-7 steps, multiple phases)
  {
    title: "S3 Versioning and Backup Compliance",
    description: "A backup bucket lacks versioning and lifecycle policies, risking permanent data loss. Configure proper backup protections.",
    briefing: "DISASTER RECOVERY RISK: Internal audit discovered our disaster recovery bucket has no versioning. If ransomware hits or an insider goes rogue, we have no way to recover deleted data. The board wants this fixed before the next audit.",
    scenario: "Last month, a disgruntled employee at a competitor deleted their backups before quitting. The company lost 3 years of customer data. Your CISO saw the headlines and immediately asked: 'Can this happen to us?' Your job: make sure it can't.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["disaster-recovery-backup", "backup-logs"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Scan infrastructure for backup vulnerabilities.", hint: "Type 'scan' to identify issues.", intel: "Ransomware operators specifically target backups first to maximize impact." },
      { number: 2, title: "Review Versioning Status", description: "Check which buckets have versioning enabled.", hint: "Type 'aws s3 ls-versioning' to review.", intel: "S3 versioning keeps multiple variants of an object. When enabled, you can recover any previous version." },
      { number: 3, title: "Understand the Risk", description: "Without versioning, deleted files cannot be recovered. This violates backup compliance requirements.", hint: "Consider what happens if someone accidentally deletes critical backups.", intel: "NIST CSF: PR.IP-4 requires backups to be conducted, maintained, and tested." },
      { number: 4, title: "Enable Versioning", description: "Turn on versioning for the backup bucket.", hint: "Type 'aws s3 enable-versioning disaster-recovery-backup'.", intel: "Pro tip: Combine versioning with MFA Delete for an additional layer of protection against accidental or malicious deletion." },
      { number: 5, title: "Verify Configuration", description: "Confirm versioning is now active.", hint: "Type 'aws s3 ls-versioning' to verify.", intel: "Once enabled, versioning cannot be fully disabled - only suspended. This is a feature, not a bug." },
      { number: 6, title: "Document Compliance", description: "Run a final scan to confirm compliance status.", hint: "Type 'scan' to generate compliance report.", intel: "Document this change for your audit trail. Compliance isn't just about fixing - it's about proving you fixed it." }
    ],
    resources: [
      { type: "s3", name: "disaster-recovery-backup", config: { versioning: false }, isVulnerable: true, status: "active" },
      { type: "s3", name: "backup-logs", config: { versioning: true }, isVulnerable: false, status: "active" }
    ],
    fixCommands: ["aws s3 enable-versioning disaster-recovery-backup"],
    successMessage: "Versioning enabled! Your backups are now protected against deletion. Consider adding lifecycle policies to manage storage costs."
  },
  {
    title: "Overly Permissive Bucket Policy",
    description: "A data lake bucket grants wildcard permissions to all principals. Investigate the policy and implement least privilege access.",
    briefing: "CRITICAL MISCONFIGURATION: A new data engineer accidentally applied a policy granting full access to everyone. The 'shared-data-lake' bucket contains 2TB of analytics data including user behavior patterns. Lock it down now.",
    scenario: "A junior engineer tried to share data with a contractor and 'just made it work' by using Principal: '*'. Now anyone on the internet can read, write, or delete your entire data lake. Time to fix this before someone notices the open door.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["shared-data-lake"] },
    steps: [
      { number: 1, title: "Identify Policy Risk", description: "Scan for overly permissive bucket policies.", hint: "Type 'scan' to find misconfigurations.", intel: "AWS Config rule 's3-bucket-public-read-prohibited' can automatically detect and alert on these issues." },
      { number: 2, title: "Review Current Policy", description: "Examine the bucket's IAM policy document.", hint: "Type 'aws s3 get-policy shared-data-lake' to view.", intel: "Look for Principal: '*' or Principal: {'AWS': '*'} - both mean 'everyone in the world'." },
      { number: 3, title: "Analyze Permissions", description: "The policy grants 's3:*' to principal '*'. This allows anyone to read, write, and delete data.", hint: "Wildcard policies violate CIS Benchmark 2.1.5.", intel: "This is a common finding in penetration tests. Attackers use tools like 'bucket_finder' to discover misconfigured buckets." },
      { number: 4, title: "Apply Least Privilege", description: "Restrict the policy to specific actions and principals.", hint: "Type 'aws s3 restrict-policy shared-data-lake'.", intel: "Best practice: Use specific IAM roles instead of wildcards. Grant only read access if write isn't needed." },
      { number: 5, title: "Verify New Policy", description: "Check that the policy is now restrictive.", hint: "Type 'aws s3 get-policy shared-data-lake' to confirm.", intel: "After fixing, test that legitimate users can still access what they need." },
      { number: 6, title: "Final Verification", description: "Run security scan to confirm remediation.", hint: "Type 'scan' to verify.", intel: "Consider implementing S3 Block Public Access at the account level to prevent future misconfigurations." }
    ],
    resources: [
      { type: "s3", name: "shared-data-lake", config: { policy: "s3:*", principal: "*" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 restrict-policy shared-data-lake"],
    successMessage: "Policy locked down! You've implemented least privilege access. Consider setting up AWS Config rules to catch this automatically next time."
  },
  {
    title: "Cross-Account Bucket Access Investigation",
    description: "Security detected a bucket with access from unknown AWS accounts. Investigate and remove unauthorized access.",
    briefing: "SUSPICIOUS ACTIVITY: CloudTrail detected API calls from AWS account 999888777666 accessing our 'partner-data-exchange' bucket. This account is NOT in our approved partner list. Investigate immediately - this could be data exfiltration.",
    scenario: "Your SIEM just fired an alert: 'Unusual cross-account S3 access detected.' Someone added an unknown AWS account to your bucket policy. Was it a mistake, or did an attacker modify the policy to exfiltrate data? Time to investigate.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["partner-data-exchange"] },
    steps: [
      { number: 1, title: "Detect Anomaly", description: "Scan for buckets with external access.", hint: "Type 'scan' to identify issues.", intel: "Cross-account access is a common lateral movement technique. Attackers grant their accounts access for persistent data theft." },
      { number: 2, title: "List External Access", description: "Check which accounts have access to the bucket.", hint: "Type 'aws s3 check-access partner-data-exchange'.", intel: "MITRE ATT&CK T1537: Transfer Data to Cloud Account - Adversaries may exfiltrate data by granting themselves access." },
      { number: 3, title: "Identify Unauthorized Accounts", description: "Account 999888777666 is not in our approved partners list. This could be a compromise.", hint: "Cross-reference with your organization's approved account list.", intel: "Pro tip: Maintain a documented list of approved external accounts. Audit this list quarterly." },
      { number: 4, title: "Review Bucket Policy", description: "Examine how the external access was granted.", hint: "Type 'aws s3 get-policy partner-data-exchange'.", intel: "Check CloudTrail for 'PutBucketPolicy' events to see WHO added this account and WHEN." },
      { number: 5, title: "Revoke Unauthorized Access", description: "Remove access for unknown accounts.", hint: "Type 'aws s3 revoke-external partner-data-exchange'.", intel: "After revoking, monitor for re-addition attempts. If it happens again, you have an active compromise." },
      { number: 6, title: "Verify Remediation", description: "Confirm only authorized accounts remain.", hint: "Type 'aws s3 check-access partner-data-exchange' to verify.", intel: "Document this incident. If data was accessed, you may need to notify affected parties under GDPR/CCPA." }
    ],
    resources: [
      { type: "s3", name: "partner-data-exchange", config: { crossAccount: ["123456789012", "999888777666"] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 revoke-external partner-data-exchange"],
    successMessage: "Unauthorized access revoked! Review CloudTrail to determine the scope of potential data access. Consider this a potential incident."
  },
  {
    title: "S3 Object Lock for Compliance",
    description: "Regulatory requirements mandate WORM protection for audit logs. Configure Object Lock to prevent deletion or modification.",
    briefing: "COMPLIANCE DEADLINE: The legal team just informed us that our SEC filing requires WORM-compliant storage for audit logs. We have 48 hours to implement Object Lock on 'compliance-audit-logs' or face regulatory action.",
    scenario: "After the Enron scandal, regulations require financial records to be immutable. Your company's audit logs can currently be deleted by anyone with S3 access. If a bad actor covers their tracks by deleting logs, you'll have no evidence for investigations.",
    difficulty: "Intermediate",
    category: "Storage Security",
    estimatedTime: "15-25 minutes",
    initialState: { buckets: ["compliance-audit-logs"] },
    steps: [
      { number: 1, title: "Identify Compliance Gap", description: "Scan for buckets missing WORM protection.", hint: "Type 'scan' to identify issues.", intel: "SEC Rule 17a-4 and FINRA Rule 4511 require broker-dealers to preserve records in non-rewriteable, non-erasable format." },
      { number: 2, title: "Check Object Lock Status", description: "Review current Object Lock configuration.", hint: "Type 'aws s3 check-object-lock compliance-audit-logs'.", intel: "Object Lock has two modes: Governance (admins can override) and Compliance (nobody can delete, not even root)." },
      { number: 3, title: "Understand Requirements", description: "SOX and HIPAA require immutable audit logs. Without Object Lock, logs can be tampered with.", hint: "MITRE ATT&CK T1565: Data Manipulation.", intel: "Attackers who compromise systems often delete logs first to cover their tracks. Immutable logs are your insurance policy." },
      { number: 4, title: "Enable Object Lock", description: "Configure WORM protection in compliance mode.", hint: "Type 'aws s3 enable-object-lock compliance-audit-logs'.", intel: "Warning: Compliance mode is PERMANENT. Objects cannot be deleted until retention expires. Choose retention period carefully." },
      { number: 5, title: "Verify Protection", description: "Confirm Object Lock is active.", hint: "Type 'aws s3 check-object-lock compliance-audit-logs'.", intel: "Test by attempting to delete a locked object - you should receive an 'Access Denied' error even with admin permissions." },
      { number: 6, title: "Generate Compliance Report", description: "Document the remediation for auditors.", hint: "Type 'scan' to generate report.", intel: "Keep screenshots and timestamps. Auditors love documentation that proves exactly when controls were implemented." }
    ],
    resources: [
      { type: "s3", name: "compliance-audit-logs", config: { objectLock: false }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws s3 enable-object-lock compliance-audit-logs"],
    successMessage: "WORM protection enabled! Your audit logs are now tamper-proof. You're compliant with SEC 17a-4 and SOX requirements."
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

// ============= NETWORK SECURITY LABS (11) =============
export const networkSecurityLabs: LabDefinition[] = [
  // BEGINNER LABS
  {
    title: "Insecure Security Group - SSH Exposed",
    description: "An EC2 instance allows SSH from the entire internet. Quickly restrict access.",
    briefing: "ACTIVE THREAT: Honeypot data shows attackers are actively scanning our IP ranges for open SSH ports. They've found 'db-prod-01' and brute force attempts have begun. You have minutes before they gain access.",
    scenario: "Shodan just indexed your database server with port 22 open to the world. Automated bots are already trying 1000+ username/password combinations per minute. One weak password is all it takes. Shut this door NOW.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["db-prod-01"] },
    steps: [
      { number: 1, title: "Scan for Issues", description: "Identify exposed network ports.", hint: "Type 'scan' to find vulnerabilities.", intel: "Exposed SSH is the #1 attack vector for cloud compromises. Most attacks are automated and happen within hours of exposure." },
      { number: 2, title: "Review Security Group", description: "Check the security group rules.", hint: "Type 'aws ec2 describe-sg db-prod-01'.", intel: "Look for 0.0.0.0/0 - this means 'everyone on the internet'. Never use this for management ports." },
      { number: 3, title: "Restrict SSH Access", description: "Limit SSH to internal networks only.", hint: "Type 'aws ec2 restrict-ssh db-prod-01'.", intel: "Best practice: Use Systems Manager Session Manager instead of SSH. It provides audit trails and doesn't require open ports." }
    ],
    resources: [
      { type: "security_group", name: "sg-db-prod-01", config: { ingress: [{ port: 22, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-ssh db-prod-01"],
    successMessage: "SSH locked down! Brute force attacks will now fail at the network layer. Consider implementing Session Manager for passwordless, audited access."
  },
  {
    title: "Open RDP Port to Internet",
    description: "A Windows server has RDP exposed to the world - a common ransomware vector. Close it.",
    briefing: "RANSOMWARE RISK: Threat intelligence reports a new RDP brute-force campaign by 'LockBit' targeting exposed Windows servers. Your admin server 'win-admin-01' has RDP wide open. Secure it before you become the next victim.",
    scenario: "The FBI just issued an advisory: ransomware gangs are specifically targeting RDP. Your Windows admin server is visible to 4 billion internet users right now. The only thing between you and a $500K ransom demand is a password.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["win-admin-01"] },
    steps: [
      { number: 1, title: "Identify Risk", description: "Scan for exposed RDP ports.", hint: "Type 'scan' to find issues.", intel: "RDP (port 3389) is the most commonly exploited port. Ransomware operators actively buy access to exposed RDP servers." },
      { number: 2, title: "List Security Groups", description: "Review current configurations.", hint: "Type 'aws ec2 ls-sg'.", intel: "BlueKeep (CVE-2019-0708) made RDP exploitation trivial. Even patched systems are vulnerable to credential attacks." },
      { number: 3, title: "Restrict RDP", description: "Allow RDP only from VPN.", hint: "Type 'aws ec2 restrict-rdp win-admin-01'.", intel: "After restricting, enable NLA (Network Level Authentication) for an additional security layer." }
    ],
    resources: [
      { type: "security_group", name: "sg-win-admin", config: { ingress: [{ port: 3389, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-rdp win-admin-01"],
    successMessage: "RDP secured! You've closed one of the most dangerous attack vectors. Consider using AWS Fleet Manager or Azure Bastion for secure remote access."
  },
  {
    title: "Database Port Exposed",
    description: "MySQL port 3306 is accessible from the internet. Restrict to app servers.",
    briefing: "DATA BREACH IMMINENT: Your MySQL database is reachable from any IP address on earth. Attackers can attempt to connect, brute force credentials, or exploit SQL injection directly. This is how major breaches start.",
    scenario: "A security researcher just responsibly disclosed that your MySQL port is open. You have 24 hours before they publish the finding. If attackers find it first, customer data could be exfiltrated in minutes.",
    difficulty: "Beginner",
    category: "Network Security",
    estimatedTime: "5-10 minutes",
    initialState: { instances: ["mysql-prod-01"] },
    steps: [
      { number: 1, title: "Find Exposed Ports", description: "Scan for database exposure.", hint: "Type 'scan' to identify.", intel: "Database ports should NEVER be internet-facing. Always place databases in private subnets." },
      { number: 2, title: "Check Database SG", description: "Review MySQL security group.", hint: "Type 'aws ec2 describe-sg mysql-prod-01'.", intel: "The 2017 MongoDB apocalypse happened because thousands of databases were internet-exposed with no authentication." },
      { number: 3, title: "Restrict Access", description: "Allow only app server security group.", hint: "Type 'aws ec2 restrict-db mysql-prod-01'.", intel: "Use security group references (sg-xxxxx) instead of IP ranges when possible. This ensures only authorized instances can connect." }
    ],
    resources: [
      { type: "security_group", name: "sg-mysql-prod", config: { ingress: [{ port: 3306, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["aws ec2 restrict-db mysql-prod-01"],
    successMessage: "Database secured! Only your application servers can now reach MySQL. Consider enabling IAM database authentication for passwordless, audited access."
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

// ============= SOC ENGINEER LABS (12) =============
export const socEngineerLabs: LabDefinition[] = [
  // BEGINNER LABS (4)
  {
    title: "SIEM Alert Configuration",
    description: "Configure basic SIEM alerting rules for critical security events like failed logins and privilege escalations.",
    difficulty: "Beginner",
    category: "SOC Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { siem: ["siem-primary"] },
    steps: [
      { number: 1, title: "Access SIEM Console", description: "Connect to the SIEM dashboard.", hint: "Type 'siem connect'." },
      { number: 2, title: "Review Alert Rules", description: "List current alerting rules.", hint: "Type 'siem list-rules'." },
      { number: 3, title: "Create Failed Login Alert", description: "Add alerting for 5+ failed logins.", hint: "Type 'siem create-rule failed-logins'." }
    ],
    resources: [
      { type: "siem", name: "siem-primary", config: { alertRules: 0 }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["siem create-rule failed-logins"]
  },
  {
    title: "Log Source Integration",
    description: "Integrate a new log source into the SIEM for centralized monitoring.",
    difficulty: "Beginner",
    category: "SOC Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { logSources: ["firewall-logs"] },
    steps: [
      { number: 1, title: "Check Log Sources", description: "List currently integrated log sources.", hint: "Type 'siem list-sources'." },
      { number: 2, title: "Identify Missing Source", description: "Firewall logs are not integrated.", hint: "Type 'scan' to verify." },
      { number: 3, title: "Add Log Source", description: "Integrate firewall logs into SIEM.", hint: "Type 'siem add-source firewall-logs'." }
    ],
    resources: [
      { type: "log_source", name: "firewall-logs", config: { integrated: false }, isVulnerable: true, status: "disconnected" }
    ],
    fixCommands: ["siem add-source firewall-logs"]
  },
  {
    title: "Dashboard Widget Setup",
    description: "Create a security dashboard widget to monitor critical metrics.",
    difficulty: "Beginner",
    category: "SOC Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { dashboards: ["soc-dashboard"] },
    steps: [
      { number: 1, title: "Access Dashboard", description: "Open the SOC monitoring dashboard.", hint: "Type 'dashboard open soc-dashboard'." },
      { number: 2, title: "Review Widgets", description: "Check existing dashboard widgets.", hint: "Type 'dashboard list-widgets'." },
      { number: 3, title: "Add Threat Widget", description: "Add a real-time threat indicator widget.", hint: "Type 'dashboard add-widget threat-indicator'." }
    ],
    resources: [
      { type: "dashboard", name: "soc-dashboard", config: { widgets: 2 }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["dashboard add-widget threat-indicator"]
  },
  {
    title: "Alert Severity Classification",
    description: "Configure proper severity levels for different types of security alerts.",
    difficulty: "Beginner",
    category: "SOC Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { alertConfig: ["severity-rules"] },
    steps: [
      { number: 1, title: "Review Severity Levels", description: "Check current alert severity configuration.", hint: "Type 'siem show-severity-config'." },
      { number: 2, title: "Identify Misconfiguration", description: "Critical alerts are set to low priority.", hint: "This causes alert fatigue and missed incidents." },
      { number: 3, title: "Fix Severity Mapping", description: "Correct the severity classification.", hint: "Type 'siem fix-severity critical-alerts'." }
    ],
    resources: [
      { type: "alert_config", name: "severity-rules", config: { criticalSeverity: "low" }, isVulnerable: true, status: "misconfigured" }
    ],
    fixCommands: ["siem fix-severity critical-alerts"]
  },

  // INTERMEDIATE LABS (4)
  {
    title: "Correlation Rule Development",
    description: "Build a multi-stage correlation rule to detect lateral movement patterns across the network.",
    difficulty: "Intermediate",
    category: "SOC Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { correlationEngine: ["correlation-engine-1"] },
    steps: [
      { number: 1, title: "Analyze Attack Pattern", description: "Review the lateral movement pattern we want to detect.", hint: "Type 'siem analyze-pattern lateral-movement'." },
      { number: 2, title: "Identify Required Events", description: "Determine which log events indicate lateral movement.", hint: "Authentication events followed by remote execution." },
      { number: 3, title: "Create Base Rule", description: "Start with authentication event detection.", hint: "Type 'siem create-correlation auth-chain'." },
      { number: 4, title: "Add Chained Events", description: "Link to subsequent remote execution events.", hint: "Type 'siem add-chain-event auth-chain remote-exec'." },
      { number: 5, title: "Set Time Window", description: "Configure the correlation time window.", hint: "Type 'siem set-window auth-chain 300s'." },
      { number: 6, title: "Test Rule", description: "Validate the correlation rule works.", hint: "Type 'siem test-rule auth-chain'." }
    ],
    resources: [
      { type: "correlation_engine", name: "correlation-engine-1", config: { rules: 3 }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["siem create-correlation auth-chain", "siem add-chain-event auth-chain remote-exec", "siem set-window auth-chain 300s"]
  },
  {
    title: "Threat Intel Feed Integration",
    description: "Integrate external threat intelligence feeds to enhance detection capabilities.",
    difficulty: "Intermediate",
    category: "SOC Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { threatFeeds: ["misp-feed"] },
    steps: [
      { number: 1, title: "Review Available Feeds", description: "Check which threat intel feeds are available.", hint: "Type 'threat-intel list-feeds'." },
      { number: 2, title: "Evaluate Feed Quality", description: "Assess the MISP feed for relevance.", hint: "Type 'threat-intel analyze misp-feed'." },
      { number: 3, title: "Configure Integration", description: "Set up the feed connection parameters.", hint: "Type 'threat-intel configure misp-feed'." },
      { number: 4, title: "Enable IOC Matching", description: "Turn on automatic IOC correlation.", hint: "Type 'threat-intel enable-matching misp-feed'." },
      { number: 5, title: "Verify Integration", description: "Confirm the feed is providing data.", hint: "Type 'threat-intel status misp-feed'." },
      { number: 6, title: "Create Alert Rules", description: "Set up alerts for threat intel matches.", hint: "Type 'threat-intel create-alerts misp-feed'." }
    ],
    resources: [
      { type: "threat_feed", name: "misp-feed", config: { status: "disconnected", iocCount: 50000 }, isVulnerable: true, status: "inactive" }
    ],
    fixCommands: ["threat-intel configure misp-feed", "threat-intel enable-matching misp-feed"]
  },
  {
    title: "Automated Playbook Creation",
    description: "Build a SOAR playbook to automate initial incident response for phishing attacks.",
    difficulty: "Intermediate",
    category: "SOC Engineer",
    estimatedTime: "20-30 minutes",
    initialState: { soar: ["soar-platform"] },
    steps: [
      { number: 1, title: "Access SOAR Platform", description: "Open the orchestration platform.", hint: "Type 'soar connect'." },
      { number: 2, title: "Review Phishing Workflow", description: "Understand the manual phishing response process.", hint: "Type 'soar show-workflow phishing-manual'." },
      { number: 3, title: "Create New Playbook", description: "Initialize an automated phishing playbook.", hint: "Type 'soar create-playbook phishing-auto'." },
      { number: 4, title: "Add Email Analysis Step", description: "Automate header and attachment analysis.", hint: "Type 'soar add-step phishing-auto email-analysis'." },
      { number: 5, title: "Add User Notification", description: "Auto-notify affected users.", hint: "Type 'soar add-step phishing-auto notify-user'." },
      { number: 6, title: "Add Quarantine Action", description: "Automate email quarantine.", hint: "Type 'soar add-step phishing-auto quarantine'." },
      { number: 7, title: "Activate Playbook", description: "Enable the automated playbook.", hint: "Type 'soar activate phishing-auto'." }
    ],
    resources: [
      { type: "soar", name: "soar-platform", config: { playbooks: 5, automationLevel: "low" }, isVulnerable: true, status: "active" }
    ],
    fixCommands: ["soar create-playbook phishing-auto", "soar activate phishing-auto"]
  },
  {
    title: "Log Retention Policy Configuration",
    description: "Configure proper log retention policies to meet compliance requirements while managing storage costs.",
    difficulty: "Intermediate",
    category: "SOC Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { logRetention: ["retention-policy"] },
    steps: [
      { number: 1, title: "Check Current Policy", description: "Review existing log retention settings.", hint: "Type 'logs show-retention'." },
      { number: 2, title: "Identify Compliance Gap", description: "PCI-DSS requires 1 year retention; current is 30 days.", hint: "This is a compliance violation." },
      { number: 3, title: "Review Storage Tiers", description: "Check available storage options.", hint: "Type 'logs show-storage-tiers'." },
      { number: 4, title: "Configure Hot Storage", description: "Set 90 days for fast access.", hint: "Type 'logs set-retention hot 90d'." },
      { number: 5, title: "Configure Cold Storage", description: "Set 1 year for compliance.", hint: "Type 'logs set-retention cold 365d'." },
      { number: 6, title: "Verify Compliance", description: "Confirm retention meets requirements.", hint: "Type 'logs verify-compliance'." }
    ],
    resources: [
      { type: "log_retention", name: "retention-policy", config: { currentRetention: "30d", required: "365d" }, isVulnerable: true, status: "non-compliant" }
    ],
    fixCommands: ["logs set-retention hot 90d", "logs set-retention cold 365d"]
  },

  // ADVANCED LABS (4)
  {
    title: "Detection Engineering Pipeline",
    description: "Build a complete detection-as-code pipeline with version control, testing, and automated deployment of detection rules.",
    difficulty: "Advanced",
    category: "SOC Engineer",
    estimatedTime: "35-50 minutes",
    initialState: { pipeline: ["detection-pipeline"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Evaluate the existing detection deployment process.", hint: "Type 'scan' to identify gaps." },
      { number: 2, title: "Initialize Repository", description: "Create a Git repository for detection rules.", hint: "Type 'git init detection-rules'." },
      { number: 3, title: "Create Rule Template", description: "Build a standardized detection rule format.", hint: "Type 'detection create-template sigma-format'." },
      { number: 4, title: "Implement Validation", description: "Add automated syntax and logic validation.", hint: "Type 'detection add-validation syntax-check'." },
      { number: 5, title: "Configure Testing", description: "Set up automated testing with sample data.", hint: "Type 'detection configure-tests sample-data'." },
      { number: 6, title: "Build CI/CD Pipeline", description: "Create automated deployment pipeline.", hint: "Type 'detection create-pipeline ci-cd'." },
      { number: 7, title: "Add Approval Workflow", description: "Require review before production deployment.", hint: "Type 'detection add-approval-gate production'." },
      { number: 8, title: "Deploy Sample Rule", description: "Test the pipeline with a sample detection.", hint: "Type 'detection deploy-rule sample-rule'." },
      { number: 9, title: "Verify Pipeline", description: "Confirm end-to-end functionality.", hint: "Type 'detection verify-pipeline'." },
      { number: 10, title: "Document Process", description: "Detection-as-code pipeline operational. Rules now versioned, tested, and auto-deployed.", hint: "Pipeline complete." }
    ],
    resources: [
      { type: "detection_pipeline", name: "detection-pipeline", config: { versionControl: false, testing: false, cicd: false }, isVulnerable: true, status: "manual" }
    ],
    fixCommands: ["detection create-pipeline ci-cd", "detection verify-pipeline"]
  },
  {
    title: "Purple Team Exercise Infrastructure",
    description: "Set up automated adversary simulation infrastructure for continuous security validation.",
    difficulty: "Advanced",
    category: "SOC Engineer",
    estimatedTime: "40-55 minutes",
    initialState: { purpleTeam: ["caldera-server"] },
    steps: [
      { number: 1, title: "Deploy Simulation Server", description: "Initialize the adversary simulation platform.", hint: "Type 'purple-team deploy caldera-server'." },
      { number: 2, title: "Configure Agent Deployment", description: "Set up agents on test endpoints.", hint: "Type 'purple-team deploy-agents test-endpoints'." },
      { number: 3, title: "Select Attack Chains", description: "Choose MITRE ATT&CK techniques to simulate.", hint: "Type 'purple-team select-techniques T1059,T1055,T1078'." },
      { number: 4, title: "Configure Reporting", description: "Set up detection gap reporting.", hint: "Type 'purple-team configure-reporting gaps'." },
      { number: 5, title: "Run Initial Simulation", description: "Execute the first adversary simulation.", hint: "Type 'purple-team execute simulation-1'." },
      { number: 6, title: "Collect Detection Results", description: "Gather results from SIEM and EDR.", hint: "Type 'purple-team collect-results simulation-1'." },
      { number: 7, title: "Analyze Coverage Gaps", description: "Identify techniques that weren't detected.", hint: "Type 'purple-team analyze-gaps simulation-1'." },
      { number: 8, title: "Create Remediation Plan", description: "Document needed detection improvements.", hint: "Type 'purple-team create-remediation simulation-1'." },
      { number: 9, title: "Implement New Detections", description: "Add rules for missed techniques.", hint: "Type 'purple-team implement-detections simulation-1'." },
      { number: 10, title: "Re-run Validation", description: "Verify new detections work.", hint: "Type 'purple-team execute simulation-2'." },
      { number: 11, title: "Generate Report", description: "Create final coverage report.", hint: "Type 'purple-team generate-report'." }
    ],
    resources: [
      { type: "adversary_sim", name: "caldera-server", config: { status: "not-deployed", techniques: [] }, isVulnerable: true, status: "inactive" }
    ],
    fixCommands: ["purple-team deploy caldera-server", "purple-team generate-report"]
  },
  {
    title: "Multi-Tenant SIEM Architecture",
    description: "Design and implement a multi-tenant SIEM architecture for managed security service provider operations.",
    difficulty: "Advanced",
    category: "SOC Engineer",
    estimatedTime: "45-60 minutes",
    initialState: { siemCluster: ["siem-cluster"] },
    steps: [
      { number: 1, title: "Assess Requirements", description: "Review multi-tenant isolation needs.", hint: "Type 'scan' to understand current architecture." },
      { number: 2, title: "Design Tenant Schema", description: "Create logical tenant separation model.", hint: "Type 'siem design-tenant-schema'." },
      { number: 3, title: "Implement Data Isolation", description: "Configure index-level tenant separation.", hint: "Type 'siem configure-isolation index-per-tenant'." },
      { number: 4, title: "Set Up RBAC", description: "Create role-based access per tenant.", hint: "Type 'siem configure-rbac tenant-roles'." },
      { number: 5, title: "Configure Dashboards", description: "Create tenant-specific dashboards.", hint: "Type 'siem create-tenant-dashboards'." },
      { number: 6, title: "Set Up Alerting", description: "Configure per-tenant alert routing.", hint: "Type 'siem configure-alert-routing per-tenant'." },
      { number: 7, title: "Implement Rate Limiting", description: "Prevent noisy neighbor issues.", hint: "Type 'siem configure-rate-limits'." },
      { number: 8, title: "Create Tenant A", description: "Onboard first tenant.", hint: "Type 'siem onboard-tenant tenant-a'." },
      { number: 9, title: "Validate Isolation", description: "Verify tenant data is isolated.", hint: "Type 'siem test-isolation tenant-a'." },
      { number: 10, title: "Document Architecture", description: "Multi-tenant SIEM operational. Full data isolation, RBAC, and tenant dashboards configured.", hint: "Architecture complete." }
    ],
    resources: [
      { type: "siem_cluster", name: "siem-cluster", config: { tenants: 0, isolation: false }, isVulnerable: true, status: "single-tenant" }
    ],
    fixCommands: ["siem configure-isolation index-per-tenant", "siem onboard-tenant tenant-a"]
  },
  {
    title: "Threat Hunting Automation Framework",
    description: "Build an automated threat hunting framework that runs scheduled hunts and generates findings reports.",
    difficulty: "Advanced",
    category: "SOC Engineer",
    estimatedTime: "40-55 minutes",
    initialState: { huntFramework: ["hunt-platform"] },
    steps: [
      { number: 1, title: "Initialize Framework", description: "Set up the threat hunting platform.", hint: "Type 'hunt-framework initialize'." },
      { number: 2, title: "Create Hunt Library", description: "Build a library of reusable hunt queries.", hint: "Type 'hunt-framework create-library'." },
      { number: 3, title: "Add Hypothesis Templates", description: "Create structured hunt hypotheses.", hint: "Type 'hunt-framework add-hypothesis-template'." },
      { number: 4, title: "Configure Data Sources", description: "Connect required data sources.", hint: "Type 'hunt-framework connect-sources logs,edr,netflow'." },
      { number: 5, title: "Build First Hunt", description: "Create a hunt for beaconing behavior.", hint: "Type 'hunt-framework create-hunt beaconing-detection'." },
      { number: 6, title: "Add Analytics", description: "Implement statistical analysis.", hint: "Type 'hunt-framework add-analytics beaconing-detection'." },
      { number: 7, title: "Schedule Automation", description: "Set up recurring hunt schedule.", hint: "Type 'hunt-framework schedule beaconing-detection daily'." },
      { number: 8, title: "Configure Findings", description: "Set up findings management.", hint: "Type 'hunt-framework configure-findings'." },
      { number: 9, title: "Run Test Hunt", description: "Execute the hunt manually.", hint: "Type 'hunt-framework execute beaconing-detection'." },
      { number: 10, title: "Review Results", description: "Analyze hunt findings.", hint: "Type 'hunt-framework show-findings beaconing-detection'." },
      { number: 11, title: "Generate Report", description: "Create formal hunt report.", hint: "Type 'hunt-framework generate-report'." }
    ],
    resources: [
      { type: "hunt_platform", name: "hunt-platform", config: { hunts: 0, automated: false }, isVulnerable: true, status: "not-configured" }
    ],
    fixCommands: ["hunt-framework initialize", "hunt-framework schedule beaconing-detection daily"]
  }
];

// ============= CLOUD SECURITY ANALYST LABS (12) =============
export const cloudSecurityAnalystLabs: LabDefinition[] = [
  // BEGINNER LABS (4)
  {
    title: "Cloud Asset Inventory",
    description: "Perform a cloud asset discovery to identify all resources in your AWS environment.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { assets: ["untracked-resources"] },
    steps: [
      { number: 1, title: "Run Discovery", description: "Initiate cloud asset discovery.", hint: "Type 'cloud-inventory discover'." },
      { number: 2, title: "Review Assets", description: "List discovered cloud resources.", hint: "Type 'cloud-inventory list-all'." },
      { number: 3, title: "Tag Untracked", description: "Apply proper tags to untracked resources.", hint: "Type 'cloud-inventory tag-untracked'." }
    ],
    resources: [
      { type: "inventory", name: "untracked-resources", config: { untaggedCount: 15 }, isVulnerable: true, status: "incomplete" }
    ],
    fixCommands: ["cloud-inventory tag-untracked"]
  },
  {
    title: "Security Baseline Assessment",
    description: "Run a CIS benchmark assessment against your cloud environment.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { assessments: ["cis-benchmark"] },
    steps: [
      { number: 1, title: "Start Assessment", description: "Run CIS benchmark scan.", hint: "Type 'cis-benchmark run aws-account'." },
      { number: 2, title: "Review Findings", description: "Check the benchmark results.", hint: "Type 'cis-benchmark show-findings'." },
      { number: 3, title: "Export Report", description: "Generate compliance report.", hint: "Type 'cis-benchmark export-report'." }
    ],
    resources: [
      { type: "assessment", name: "cis-benchmark", config: { status: "not-run" }, isVulnerable: true, status: "pending" }
    ],
    fixCommands: ["cis-benchmark run aws-account"]
  },
  {
    title: "IAM User Audit",
    description: "Audit IAM users for inactive accounts and excessive permissions.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { iamAudit: ["user-audit"] },
    steps: [
      { number: 1, title: "List Users", description: "Get all IAM users.", hint: "Type 'iam-audit list-users'." },
      { number: 2, title: "Find Inactive", description: "Identify users inactive 90+ days.", hint: "Type 'iam-audit find-inactive'." },
      { number: 3, title: "Disable Inactive", description: "Disable the inactive accounts.", hint: "Type 'iam-audit disable-inactive'." }
    ],
    resources: [
      { type: "iam_audit", name: "user-audit", config: { inactiveUsers: 5 }, isVulnerable: true, status: "needs-review" }
    ],
    fixCommands: ["iam-audit disable-inactive"]
  },
  {
    title: "Public Resource Detection",
    description: "Identify publicly accessible resources in your cloud environment.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { publicResources: ["public-scan"] },
    steps: [
      { number: 1, title: "Scan for Public", description: "Find publicly accessible resources.", hint: "Type 'cloud-scan public-resources'." },
      { number: 2, title: "Review Findings", description: "Check which resources are exposed.", hint: "Type 'cloud-scan show-public'." },
      { number: 3, title: "Remediate Critical", description: "Block public access on critical resources.", hint: "Type 'cloud-scan block-public critical'." }
    ],
    resources: [
      { type: "public_scan", name: "public-scan", config: { publicCount: 3 }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["cloud-scan block-public critical"]
  },

  // INTERMEDIATE LABS (4)
  {
    title: "Cross-Account Access Review",
    description: "Audit and secure cross-account IAM trust relationships to prevent unauthorized access.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { crossAccount: ["trust-policies"] },
    steps: [
      { number: 1, title: "List Trust Relationships", description: "Identify all cross-account trusts.", hint: "Type 'iam-audit list-trust-policies'." },
      { number: 2, title: "Analyze Risk", description: "Evaluate each trust for risk level.", hint: "Type 'iam-audit analyze-trusts'." },
      { number: 3, title: "Identify Overly Permissive", description: "Find trusts with wildcard principals.", hint: "Type 'iam-audit find-wildcard-trusts'." },
      { number: 4, title: "Review External Accounts", description: "Verify all external accounts are authorized.", hint: "Type 'iam-audit verify-external'." },
      { number: 5, title: "Remove Unauthorized", description: "Revoke unauthorized trust relationships.", hint: "Type 'iam-audit revoke-trust unauthorized-role'." },
      { number: 6, title: "Document Findings", description: "Generate trust relationship report.", hint: "Type 'iam-audit export-trust-report'." }
    ],
    resources: [
      { type: "trust_policy", name: "trust-policies", config: { externalTrusts: 5, unauthorized: 2 }, isVulnerable: true, status: "needs-review" }
    ],
    fixCommands: ["iam-audit revoke-trust unauthorized-role"]
  },
  {
    title: "Cloud Security Posture Assessment",
    description: "Perform a comprehensive security posture assessment across multiple cloud services.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "20-30 minutes",
    initialState: { cspm: ["posture-assessment"] },
    steps: [
      { number: 1, title: "Initialize CSPM", description: "Connect to cloud security posture management.", hint: "Type 'cspm connect'." },
      { number: 2, title: "Run Full Scan", description: "Perform comprehensive security scan.", hint: "Type 'cspm full-scan'." },
      { number: 3, title: "Review Critical Findings", description: "Focus on critical severity issues.", hint: "Type 'cspm show-critical'." },
      { number: 4, title: "Analyze Trends", description: "Check if issues are new or recurring.", hint: "Type 'cspm analyze-trends'." },
      { number: 5, title: "Create Remediation Plan", description: "Build prioritized fix plan.", hint: "Type 'cspm create-remediation-plan'." },
      { number: 6, title: "Apply Auto-Remediations", description: "Fix issues with safe auto-remediation.", hint: "Type 'cspm auto-remediate safe'." },
      { number: 7, title: "Verify Improvements", description: "Re-scan to confirm fixes.", hint: "Type 'cspm verify-remediation'." }
    ],
    resources: [
      { type: "cspm", name: "posture-assessment", config: { criticalFindings: 8, highFindings: 15 }, isVulnerable: true, status: "poor-posture" }
    ],
    fixCommands: ["cspm auto-remediate safe"]
  },
  {
    title: "Secrets Management Audit",
    description: "Audit cloud secrets management practices and identify exposed credentials.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { secretsAudit: ["secrets-scan"] },
    steps: [
      { number: 1, title: "Scan for Secrets", description: "Search for exposed credentials.", hint: "Type 'secrets-scan detect'." },
      { number: 2, title: "Review Findings", description: "Check detected secret exposures.", hint: "Type 'secrets-scan show-findings'." },
      { number: 3, title: "Assess Impact", description: "Determine which secrets are active.", hint: "Type 'secrets-scan check-active'." },
      { number: 4, title: "Rotate Exposed", description: "Rotate any active exposed credentials.", hint: "Type 'secrets-scan rotate-exposed'." },
      { number: 5, title: "Enable Secret Manager", description: "Move secrets to proper storage.", hint: "Type 'secrets-scan enable-secrets-manager'." },
      { number: 6, title: "Verify Remediation", description: "Confirm no more exposures.", hint: "Type 'secrets-scan verify'." }
    ],
    resources: [
      { type: "secrets_audit", name: "secrets-scan", config: { exposedSecrets: 4, activeExposures: 2 }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["secrets-scan rotate-exposed", "secrets-scan enable-secrets-manager"]
  },
  {
    title: "Network Flow Analysis",
    description: "Analyze VPC flow logs to identify suspicious network patterns and potential data exfiltration.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "20-30 minutes",
    initialState: { flowLogs: ["vpc-flows"] },
    steps: [
      { number: 1, title: "Access Flow Logs", description: "Query VPC flow log data.", hint: "Type 'flow-analysis connect vpc-flows'." },
      { number: 2, title: "Baseline Traffic", description: "Establish normal traffic patterns.", hint: "Type 'flow-analysis baseline'." },
      { number: 3, title: "Detect Anomalies", description: "Find traffic deviating from baseline.", hint: "Type 'flow-analysis detect-anomalies'." },
      { number: 4, title: "Investigate High Volume", description: "Check unusually high outbound traffic.", hint: "Type 'flow-analysis investigate high-outbound'." },
      { number: 5, title: "Check Destinations", description: "Verify traffic destinations are legitimate.", hint: "Type 'flow-analysis check-destinations'." },
      { number: 6, title: "Create Alert Rule", description: "Set up alerting for suspicious patterns.", hint: "Type 'flow-analysis create-alert exfil-pattern'." }
    ],
    resources: [
      { type: "flow_logs", name: "vpc-flows", config: { anomalies: 3, suspiciousFlows: 12 }, isVulnerable: true, status: "unanalyzed" }
    ],
    fixCommands: ["flow-analysis create-alert exfil-pattern"]
  },

  // ADVANCED LABS (4)
  {
    title: "Multi-Cloud Security Assessment",
    description: "Perform a unified security assessment across AWS, Azure, and GCP environments.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "40-55 minutes",
    initialState: { multiCloud: ["cloud-connectors"] },
    steps: [
      { number: 1, title: "Connect AWS", description: "Establish AWS security assessment connection.", hint: "Type 'multicloud connect aws'." },
      { number: 2, title: "Connect Azure", description: "Link Azure subscription for assessment.", hint: "Type 'multicloud connect azure'." },
      { number: 3, title: "Connect GCP", description: "Add GCP project for unified view.", hint: "Type 'multicloud connect gcp'." },
      { number: 4, title: "Normalize Findings", description: "Map findings to common framework.", hint: "Type 'multicloud normalize-findings'." },
      { number: 5, title: "Compare Postures", description: "Assess relative security of each cloud.", hint: "Type 'multicloud compare-postures'." },
      { number: 6, title: "Identify Gaps", description: "Find security gaps unique to each cloud.", hint: "Type 'multicloud identify-gaps'." },
      { number: 7, title: "Create Unified Policy", description: "Build cross-cloud security policy.", hint: "Type 'multicloud create-policy'." },
      { number: 8, title: "Apply Remediations", description: "Fix critical issues across all clouds.", hint: "Type 'multicloud remediate-critical'." },
      { number: 9, title: "Verify Compliance", description: "Check multi-cloud compliance status.", hint: "Type 'multicloud verify-compliance'." },
      { number: 10, title: "Generate Report", description: "Create unified security posture report.", hint: "Type 'multicloud generate-report'." }
    ],
    resources: [
      { type: "multicloud", name: "cloud-connectors", config: { clouds: 3, unifiedView: false }, isVulnerable: true, status: "disconnected" }
    ],
    fixCommands: ["multicloud remediate-critical", "multicloud generate-report"]
  },
  {
    title: "Container Security Assessment",
    description: "Assess container and Kubernetes security posture, including image vulnerabilities and runtime threats.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "35-50 minutes",
    initialState: { containerSec: ["eks-cluster"] },
    steps: [
      { number: 1, title: "Connect to Cluster", description: "Access the Kubernetes cluster.", hint: "Type 'container-sec connect eks-cluster'." },
      { number: 2, title: "Scan Images", description: "Vulnerability scan all container images.", hint: "Type 'container-sec scan-images'." },
      { number: 3, title: "Review Critical CVEs", description: "Focus on critical vulnerabilities.", hint: "Type 'container-sec show-critical-cves'." },
      { number: 4, title: "Assess Runtime", description: "Check runtime security configuration.", hint: "Type 'container-sec assess-runtime'." },
      { number: 5, title: "Review Pod Security", description: "Audit pod security policies.", hint: "Type 'container-sec audit-psp'." },
      { number: 6, title: "Check Network Policies", description: "Verify network segmentation.", hint: "Type 'container-sec check-network-policies'." },
      { number: 7, title: "Review RBAC", description: "Audit Kubernetes RBAC settings.", hint: "Type 'container-sec audit-rbac'." },
      { number: 8, title: "Identify Privileged", description: "Find privileged containers.", hint: "Type 'container-sec find-privileged'." },
      { number: 9, title: "Apply Hardening", description: "Implement security hardening.", hint: "Type 'container-sec apply-hardening'." },
      { number: 10, title: "Verify Security", description: "Confirm improvements applied.", hint: "Type 'container-sec verify-posture'." }
    ],
    resources: [
      { type: "container_cluster", name: "eks-cluster", config: { criticalCVEs: 12, privilegedPods: 5 }, isVulnerable: true, status: "insecure" }
    ],
    fixCommands: ["container-sec apply-hardening"]
  },
  {
    title: "Cloud Compliance Gap Analysis",
    description: "Perform comprehensive compliance gap analysis against SOC 2, PCI-DSS, and HIPAA requirements.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "45-60 minutes",
    initialState: { compliance: ["compliance-assessment"] },
    steps: [
      { number: 1, title: "Select Frameworks", description: "Choose compliance frameworks to assess.", hint: "Type 'compliance select-frameworks soc2,pci,hipaa'." },
      { number: 2, title: "Map Controls", description: "Map cloud resources to control requirements.", hint: "Type 'compliance map-controls'." },
      { number: 3, title: "Run Assessment", description: "Execute compliance assessment.", hint: "Type 'compliance run-assessment'." },
      { number: 4, title: "Review SOC 2 Gaps", description: "Check SOC 2 specific findings.", hint: "Type 'compliance show-gaps soc2'." },
      { number: 5, title: "Review PCI Gaps", description: "Check PCI-DSS specific findings.", hint: "Type 'compliance show-gaps pci'." },
      { number: 6, title: "Review HIPAA Gaps", description: "Check HIPAA specific findings.", hint: "Type 'compliance show-gaps hipaa'." },
      { number: 7, title: "Prioritize Remediation", description: "Rank gaps by risk and overlap.", hint: "Type 'compliance prioritize-gaps'." },
      { number: 8, title: "Generate Evidence", description: "Collect compliance evidence.", hint: "Type 'compliance collect-evidence'." },
      { number: 9, title: "Create Remediation Plan", description: "Build compliance roadmap.", hint: "Type 'compliance create-roadmap'." },
      { number: 10, title: "Apply Quick Wins", description: "Fix low-effort high-impact gaps.", hint: "Type 'compliance fix-quick-wins'." },
      { number: 11, title: "Generate Reports", description: "Create compliance reports.", hint: "Type 'compliance generate-reports'." }
    ],
    resources: [
      { type: "compliance", name: "compliance-assessment", config: { frameworks: 3, gaps: 45 }, isVulnerable: true, status: "non-compliant" }
    ],
    fixCommands: ["compliance fix-quick-wins", "compliance generate-reports"]
  },
  {
    title: "Cloud Attack Surface Management",
    description: "Map and reduce the external attack surface of your cloud infrastructure including shadow IT discovery.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "40-55 minutes",
    initialState: { attackSurface: ["external-assets"] },
    steps: [
      { number: 1, title: "Initialize Discovery", description: "Start external asset discovery.", hint: "Type 'attack-surface discover-external'." },
      { number: 2, title: "Enumerate Domains", description: "Find all related domains and subdomains.", hint: "Type 'attack-surface enum-domains'." },
      { number: 3, title: "Scan Open Ports", description: "Identify exposed services.", hint: "Type 'attack-surface scan-ports'." },
      { number: 4, title: "Detect Shadow IT", description: "Find unauthorized cloud resources.", hint: "Type 'attack-surface find-shadow-it'." },
      { number: 5, title: "Assess Vulnerabilities", description: "Scan exposed services for vulns.", hint: "Type 'attack-surface scan-vulns'." },
      { number: 6, title: "Check SSL/TLS", description: "Audit certificate configurations.", hint: "Type 'attack-surface check-certs'." },
      { number: 7, title: "Review Exposed APIs", description: "Find publicly accessible APIs.", hint: "Type 'attack-surface find-apis'." },
      { number: 8, title: "Reduce Surface", description: "Remove or secure unnecessary exposure.", hint: "Type 'attack-surface remediate'." },
      { number: 9, title: "Configure Monitoring", description: "Set up continuous attack surface monitoring.", hint: "Type 'attack-surface enable-monitoring'." },
      { number: 10, title: "Verify Reduction", description: "Confirm attack surface reduced.", hint: "Type 'attack-surface verify'." },
      { number: 11, title: "Generate Report", description: "Create attack surface report.", hint: "Type 'attack-surface generate-report'." }
    ],
    resources: [
      { type: "attack_surface", name: "external-assets", config: { exposedAssets: 25, shadowIT: 8 }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["attack-surface remediate", "attack-surface enable-monitoring"]
  }
];

// ============= IAM SECURITY LABS (12) =============
export const iamSecurityLabs: LabDefinition[] = [
  // BEGINNER LABS (4)
  {
    title: "Overly Permissive IAM User",
    description: "An IAM user has been granted AdministratorAccess. Implement least privilege by restricting permissions.",
    briefing: "PRIVILEGE ESCALATION RISK: Security audit flagged user 'dev-contractor' with full admin access. This violates least privilege and creates insider threat risk.",
    scenario: "A contractor who was only supposed to deploy Lambda functions somehow has admin access to everything. One malicious action could wipe out your entire AWS infrastructure.",
    difficulty: "Beginner",
    category: "IAM Security",
    estimatedTime: "5-10 minutes",
    initialState: { users: ["dev-contractor"] },
    steps: [
      { number: 1, title: "Scan for Issues", description: "Identify overly permissive IAM configurations.", hint: "Type 'scan' to find vulnerabilities.", intel: "CIS AWS 1.16: Ensure IAM policies are attached only to groups or roles." },
      { number: 2, title: "List IAM Users", description: "Review all IAM users and their permissions.", hint: "Type 'aws iam list-users' to see users.", intel: "Look for users with AdministratorAccess or PowerUserAccess policies." },
      { number: 3, title: "Review User Policies", description: "Check what policies are attached to the contractor.", hint: "Type 'aws iam get-user-policy dev-contractor'.", intel: "Contractors should have time-limited, scoped permissions." },
      { number: 4, title: "Apply Least Privilege", description: "Replace admin access with minimal required permissions.", hint: "Type 'aws iam restrict-user dev-contractor'.", intel: "Use IAM Access Analyzer to determine what permissions are actually needed." }
    ],
    resources: [
      { type: "iam_user", name: "dev-contractor", config: { policy: "AdministratorAccess" }, isVulnerable: true, status: "overprivileged" }
    ],
    fixCommands: ["aws iam restrict-user dev-contractor"]
  },
  {
    title: "Missing MFA on Root Account",
    description: "The AWS root account lacks multi-factor authentication, exposing the entire account to credential theft.",
    briefing: "CRITICAL: Root account has no MFA enabled. If credentials are compromised, attackers have unlimited access to all resources.",
    scenario: "Your root account password was found in a credential dump. Without MFA, you're one password away from total account takeover.",
    difficulty: "Beginner",
    category: "IAM Security",
    estimatedTime: "5-10 minutes",
    initialState: { accounts: ["root-account"] },
    steps: [
      { number: 1, title: "Assess MFA Status", description: "Check if MFA is enabled on the root account.", hint: "Type 'scan' to identify issues.", intel: "CIS AWS 1.5: Ensure MFA is enabled for the root account." },
      { number: 2, title: "Check Account Summary", description: "Review the account security configuration.", hint: "Type 'aws iam get-account-summary'.", intel: "Look for AccountMFAEnabled = 0 which indicates no MFA." },
      { number: 3, title: "Verify Root Login History", description: "Check if root has been used recently.", hint: "Type 'aws iam check-root-activity'.", intel: "Root should rarely be used after initial setup." },
      { number: 4, title: "Enable MFA", description: "Activate multi-factor authentication for root.", hint: "Type 'aws iam enable-root-mfa'.", intel: "Use a hardware MFA device for root, not a virtual one." }
    ],
    resources: [
      { type: "iam_account", name: "root-account", config: { mfa: false }, isVulnerable: true, status: "unprotected" }
    ],
    fixCommands: ["aws iam enable-root-mfa"]
  },
  {
    title: "Exposed IAM Access Keys",
    description: "Long-lived IAM access keys were found in a public repository. Rotate and secure them immediately.",
    briefing: "KEY EXPOSURE: GitHub secret scanning detected AWS access keys in a public repo. Keys must be rotated immediately.",
    scenario: "A developer accidentally committed AWS keys to GitHub. Bots scan for these constantly - you have minutes before they're exploited.",
    difficulty: "Beginner",
    category: "IAM Security",
    estimatedTime: "5-10 minutes",
    initialState: { keys: ["exposed-key-AKIA"] },
    steps: [
      { number: 1, title: "Identify Exposed Keys", description: "Find which access keys have been compromised.", hint: "Type 'scan' to identify issues.", intel: "AWS GuardDuty can detect when access keys are used from unusual locations." },
      { number: 2, title: "List Access Keys", description: "Check all active access keys.", hint: "Type 'aws iam list-access-keys'.", intel: "Keys older than 90 days should be rotated per CIS benchmarks." },
      { number: 3, title: "Check Key Usage", description: "See when the exposed key was last used.", hint: "Type 'aws iam get-key-last-used exposed-key-AKIA'.", intel: "If used from unknown IPs, assume compromise and investigate." },
      { number: 4, title: "Rotate Keys", description: "Deactivate the exposed key and create a new one.", hint: "Type 'aws iam rotate-access-key exposed-key-AKIA'.", intel: "Always deactivate before deleting to avoid breaking applications." }
    ],
    resources: [
      { type: "iam_key", name: "exposed-key-AKIA", config: { age: 180, exposed: true }, isVulnerable: true, status: "compromised" }
    ],
    fixCommands: ["aws iam rotate-access-key exposed-key-AKIA"]
  },
  {
    title: "Inactive IAM User Cleanup",
    description: "Multiple IAM users haven't logged in for over 90 days. Remove dormant accounts to reduce attack surface.",
    briefing: "HYGIENE ISSUE: 5 IAM users have been inactive for 90+ days. Dormant accounts are prime targets for account takeover.",
    scenario: "Former employees and forgotten service accounts litter your IAM. Each one is a potential backdoor waiting to be exploited.",
    difficulty: "Beginner",
    category: "IAM Security",
    estimatedTime: "5-10 minutes",
    initialState: { users: ["former-employee", "old-service-acct"] },
    steps: [
      { number: 1, title: "Find Inactive Users", description: "Scan for users who haven't logged in recently.", hint: "Type 'scan' to identify issues.", intel: "CIS AWS 1.12: Ensure credentials unused for 90 days or greater are disabled." },
      { number: 2, title: "Generate Credential Report", description: "Get a detailed report of all user activity.", hint: "Type 'aws iam generate-credential-report'.", intel: "The credential report shows password and access key last used dates." },
      { number: 3, title: "Review Inactive Accounts", description: "List users with no recent activity.", hint: "Type 'aws iam list-inactive-users'.", intel: "Match against HR termination records to identify former employees." },
      { number: 4, title: "Disable Inactive Users", description: "Remove or disable dormant accounts.", hint: "Type 'aws iam cleanup-inactive-users'.", intel: "Consider archiving users first in case access needs to be restored." }
    ],
    resources: [
      { type: "iam_user", name: "former-employee", config: { lastLogin: "180 days ago" }, isVulnerable: true, status: "inactive" },
      { type: "iam_user", name: "old-service-acct", config: { lastLogin: "120 days ago" }, isVulnerable: true, status: "inactive" }
    ],
    fixCommands: ["aws iam cleanup-inactive-users"]
  },

  // INTERMEDIATE LABS (4)
  {
    title: "Cross-Account Role Trust Policy",
    description: "An IAM role trusts an unknown external AWS account. Audit and restrict the trust relationship.",
    briefing: "TRUST BOUNDARY VIOLATION: Role 'external-data-access' trusts account 999888777666 which is not in our organization. Investigate immediately.",
    scenario: "A vendor was given cross-account access last year. They've since gone out of business, but their account still has access to your production data.",
    difficulty: "Intermediate",
    category: "IAM Security",
    estimatedTime: "15-25 minutes",
    initialState: { roles: ["external-data-access"] },
    steps: [
      { number: 1, title: "Identify Trust Issues", description: "Scan for roles with external trust relationships.", hint: "Type 'scan' to find vulnerabilities.", intel: "IAM Access Analyzer automatically detects external principals." },
      { number: 2, title: "List Roles", description: "Review all IAM roles in the account.", hint: "Type 'aws iam list-roles'.", intel: "Focus on roles with trust policies that allow sts:AssumeRole." },
      { number: 3, title: "Examine Trust Policy", description: "Check who can assume the suspicious role.", hint: "Type 'aws iam get-role-trust external-data-access'.", intel: "Look for Principal statements with external account IDs." },
      { number: 4, title: "Check Role Usage", description: "See if this role has been used recently.", hint: "Type 'aws iam get-role-last-used external-data-access'.", intel: "Correlate with CloudTrail for specific actions taken." },
      { number: 5, title: "Verify External Account", description: "Confirm if the trusted account is legitimate.", hint: "Type 'aws organizations describe-account 999888777666'.", intel: "Unknown accounts should be treated as hostile." },
      { number: 6, title: "Restrict Trust Policy", description: "Update the trust policy to remove unauthorized access.", hint: "Type 'aws iam fix-role-trust external-data-access'.", intel: "Use conditions like aws:PrincipalOrgID to limit trust to your org." }
    ],
    resources: [
      { type: "iam_role", name: "external-data-access", config: { trustedAccount: "999888777666" }, isVulnerable: true, status: "external-trust" }
    ],
    fixCommands: ["aws iam fix-role-trust external-data-access"]
  },
  {
    title: "IAM Policy Privilege Escalation Path",
    description: "An IAM policy allows iam:CreatePolicy and iam:AttachUserPolicy, enabling privilege escalation. Fix the permissions.",
    briefing: "PRIVILEGE ESCALATION: The 'developer' policy contains a path to admin. Users can create and attach their own policies.",
    scenario: "A clever developer discovered they can grant themselves any permission. Your 'least privilege' is an illusion.",
    difficulty: "Intermediate",
    category: "IAM Security",
    estimatedTime: "15-25 minutes",
    initialState: { policies: ["developer-policy"] },
    steps: [
      { number: 1, title: "Scan for Escalation Paths", description: "Identify policies that allow privilege escalation.", hint: "Type 'scan' to find vulnerabilities.", intel: "Tools like Pacu and Cloudsplaining can automate this detection." },
      { number: 2, title: "List Custom Policies", description: "Review all customer-managed IAM policies.", hint: "Type 'aws iam list-policies --scope Local'.", intel: "Custom policies are more likely to contain escalation paths." },
      { number: 3, title: "Analyze Policy Document", description: "Check the developer policy for dangerous permissions.", hint: "Type 'aws iam get-policy-document developer-policy'.", intel: "Look for iam:*, sts:*, or combinations that allow self-modification." },
      { number: 4, title: "Simulate Escalation", description: "Test if escalation is actually possible.", hint: "Type 'aws iam simulate-policy developer-policy iam:AttachUserPolicy'.", intel: "Use IAM Policy Simulator to validate your findings." },
      { number: 5, title: "Create Restricted Version", description: "Build a policy without escalation permissions.", hint: "Type 'aws iam create-safe-policy developer-policy'.", intel: "Add explicit deny for iam:Create*, iam:Attach*, iam:Put*." },
      { number: 6, title: "Apply Fixed Policy", description: "Replace the vulnerable policy with the secure version.", hint: "Type 'aws iam fix-policy developer-policy'.", intel: "Test thoroughly before applying - this could break developer workflows." }
    ],
    resources: [
      { type: "iam_policy", name: "developer-policy", config: { escalationPath: true }, isVulnerable: true, status: "dangerous" }
    ],
    fixCommands: ["aws iam fix-policy developer-policy"]
  },
  {
    title: "Service-Linked Role Audit",
    description: "Multiple AWS services have created roles with broad permissions. Audit and ensure they follow least privilege.",
    briefing: "SERVICE ROLES AUDIT: 8 service-linked roles exist with varying privilege levels. Some may be over-permissioned or unused.",
    scenario: "AWS services create roles automatically, but do they need all those permissions? Time to audit what's actually required.",
    difficulty: "Intermediate",
    category: "IAM Security",
    estimatedTime: "15-25 minutes",
    initialState: { roles: ["AWSServiceRoleForECS", "AWSServiceRoleForRDS"] },
    steps: [
      { number: 1, title: "List Service Roles", description: "Find all service-linked roles in the account.", hint: "Type 'scan' to identify roles.", intel: "Service-linked roles are managed by AWS but can still be audited." },
      { number: 2, title: "Identify Active Services", description: "Check which services are actually in use.", hint: "Type 'aws service list-active'.", intel: "Unused services shouldn't have roles." },
      { number: 3, title: "Review Role Permissions", description: "Check what each service role can do.", hint: "Type 'aws iam list-service-roles'.", intel: "Compare against AWS documentation for expected permissions." },
      { number: 4, title: "Check Usage Patterns", description: "See how each role has been used.", hint: "Type 'aws iam analyze-service-role-usage'.", intel: "CloudTrail shows all role assumption and API calls." },
      { number: 5, title: "Identify Unused Roles", description: "Find service roles that haven't been used.", hint: "Type 'aws iam find-unused-service-roles'.", intel: "If a service isn't used, its role can be deleted." },
      { number: 6, title: "Clean Up Unused Roles", description: "Remove roles for services no longer in use.", hint: "Type 'aws iam cleanup-service-roles'.", intel: "Some service roles cannot be deleted while resources exist." }
    ],
    resources: [
      { type: "iam_role", name: "AWSServiceRoleForECS", config: { lastUsed: "30 days ago" }, isVulnerable: false, status: "active" },
      { type: "iam_role", name: "AWSServiceRoleForRDS", config: { lastUsed: "never" }, isVulnerable: true, status: "unused" }
    ],
    fixCommands: ["aws iam cleanup-service-roles"]
  },
  {
    title: "Permission Boundary Implementation",
    description: "Developers can create IAM roles without restrictions. Implement permission boundaries to limit their scope.",
    briefing: "GUARDRAILS MISSING: Developers can create roles with any permissions. Implement permission boundaries to prevent privilege escalation.",
    scenario: "Your developers need to create roles for their applications, but without guardrails they could accidentally (or intentionally) create admin roles.",
    difficulty: "Intermediate",
    category: "IAM Security",
    estimatedTime: "15-25 minutes",
    initialState: { policies: ["developer-role-creation"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Check how developers currently create roles.", hint: "Type 'scan' to find vulnerabilities.", intel: "Permission boundaries limit what permissions a role can grant." },
      { number: 2, title: "Review Existing Roles", description: "See what roles developers have created.", hint: "Type 'aws iam list-developer-roles'.", intel: "Look for roles with excessive permissions." },
      { number: 3, title: "Design Boundary Policy", description: "Create a permission boundary that limits scope.", hint: "Type 'aws iam create-permission-boundary developer-boundary'.", intel: "Boundary should only allow permissions developers actually need." },
      { number: 4, title: "Test Boundary", description: "Verify the boundary works as expected.", hint: "Type 'aws iam test-boundary developer-boundary'.", intel: "Test both allowed and denied actions." },
      { number: 5, title: "Apply to Developer Policy", description: "Require boundary on all developer-created roles.", hint: "Type 'aws iam enforce-boundary developer-role-creation'.", intel: "Use iam:CreateRole condition to enforce boundaries." },
      { number: 6, title: "Verify Enforcement", description: "Confirm developers can only create bounded roles.", hint: "Type 'aws iam verify-boundary-enforcement'.", intel: "Try creating a role without boundary to confirm it fails." }
    ],
    resources: [
      { type: "iam_policy", name: "developer-role-creation", config: { hasBoundary: false }, isVulnerable: true, status: "unbounded" }
    ],
    fixCommands: ["aws iam enforce-boundary developer-role-creation"]
  },

  // ADVANCED LABS (4)
  {
    title: "IAM Credential Compromise Investigation",
    description: "CloudTrail detected suspicious API calls from an IAM user. Investigate the compromise and contain the threat.",
    briefing: "ACTIVE THREAT: GuardDuty detected anomalous API calls from user 'admin-jenkins'. Source IP is in Russia. Immediate response required.",
    scenario: "Your CI/CD system's credentials are being used from Moscow at 3 AM. The attacker is actively enumerating your infrastructure.",
    difficulty: "Advanced",
    category: "IAM Security",
    estimatedTime: "30-45 minutes",
    initialState: { users: ["admin-jenkins"], logs: ["cloudtrail-alerts"] },
    steps: [
      { number: 1, title: "Confirm the Alert", description: "Verify the GuardDuty finding is legitimate.", hint: "Type 'scan' to assess the situation.", intel: "Check if the IP geolocation matches expected CI/CD locations." },
      { number: 2, title: "Review CloudTrail Events", description: "Examine what actions the compromised credential performed.", hint: "Type 'aws cloudtrail lookup-events --username admin-jenkins'.", intel: "Look for reconnaissance commands like List*, Describe*, Get*." },
      { number: 3, title: "Identify Attack Timeline", description: "Determine when the compromise started.", hint: "Type 'aws cloudtrail analyze-timeline admin-jenkins'.", intel: "Find the first anomalous event to scope the incident." },
      { number: 4, title: "Check for Persistence", description: "Look for new users, roles, or access keys created.", hint: "Type 'aws iam find-persistence admin-jenkins'.", intel: "Attackers often create backdoor users or roles." },
      { number: 5, title: "Disable Compromised Credentials", description: "Immediately deactivate the compromised user.", hint: "Type 'aws iam disable-user admin-jenkins'.", intel: "Disable before delete to preserve forensic evidence." },
      { number: 6, title: "Rotate All Keys", description: "Generate new credentials for the service.", hint: "Type 'aws iam rotate-all-keys admin-jenkins'.", intel: "Assume all keys for this user are compromised." },
      { number: 7, title: "Remove Persistence", description: "Delete any backdoors the attacker created.", hint: "Type 'aws iam remove-persistence'.", intel: "Check for lambda functions, EC2 instances with roles, etc." },
      { number: 8, title: "Review Data Access", description: "Determine what data was accessed.", hint: "Type 'aws s3 analyze-access-logs admin-jenkins'.", intel: "S3 access logs show exactly what objects were downloaded." },
      { number: 9, title: "Implement Controls", description: "Add MFA and IP restrictions.", hint: "Type 'aws iam harden-service-account admin-jenkins'.", intel: "Service accounts should use IAM roles for EC2, not long-lived keys." },
      { number: 10, title: "Generate Incident Report", description: "Document the incident for compliance.", hint: "Type 'aws iam generate-incident-report admin-jenkins'.", intel: "Include timeline, impact assessment, and remediation steps." }
    ],
    resources: [
      { type: "iam_user", name: "admin-jenkins", config: { compromised: true, sourceIP: "Moscow, Russia" }, isVulnerable: true, status: "compromised" },
      { type: "cloudtrail", name: "cloudtrail-alerts", config: { anomalousEvents: 47 }, isVulnerable: false, status: "alerting" }
    ],
    fixCommands: ["aws iam disable-user admin-jenkins", "aws iam remove-persistence", "aws iam generate-incident-report admin-jenkins"]
  },
  {
    title: "Identity Federation Security Audit",
    description: "SAML federation is configured with a third-party IdP. Audit the trust relationship and session policies.",
    briefing: "FEDERATION REVIEW: Your Okta SAML integration hasn't been reviewed since setup. Session durations may be too long, and role mappings may be stale.",
    scenario: "SSO makes access easy - maybe too easy. Can a terminated employee still access AWS through cached SAML assertions?",
    difficulty: "Advanced",
    category: "IAM Security",
    estimatedTime: "30-45 minutes",
    initialState: { providers: ["okta-saml-provider"] },
    steps: [
      { number: 1, title: "List Identity Providers", description: "Review configured SAML and OIDC providers.", hint: "Type 'scan' to identify configuration.", intel: "Check for multiple IdPs that may have different security postures." },
      { number: 2, title: "Review SAML Metadata", description: "Examine the federation trust configuration.", hint: "Type 'aws iam get-saml-provider okta-saml-provider'.", intel: "Verify the metadata URL is current and certificates aren't expired." },
      { number: 3, title: "Check Role Mappings", description: "See which roles can be assumed via SAML.", hint: "Type 'aws iam list-saml-roles'.", intel: "Ensure role mappings align with current org structure." },
      { number: 4, title: "Audit Session Duration", description: "Check how long federated sessions last.", hint: "Type 'aws iam check-session-duration'.", intel: "Long sessions increase risk if IdP is compromised." },
      { number: 5, title: "Review Attribute Mapping", description: "Verify SAML attributes map correctly to IAM.", hint: "Type 'aws iam review-saml-attributes'.", intel: "Incorrect mappings could grant wrong permissions." },
      { number: 6, title: "Check for Stale Mappings", description: "Find role mappings for deleted IdP groups.", hint: "Type 'aws iam find-stale-mappings'.", intel: "Orphaned mappings are security debt." },
      { number: 7, title: "Test Session Revocation", description: "Verify sessions can be terminated from IdP.", hint: "Type 'aws iam test-session-revocation'.", intel: "SAML doesn't support real-time revocation - test your workarounds." },
      { number: 8, title: "Reduce Session Duration", description: "Shorten max session duration to reduce risk.", hint: "Type 'aws iam reduce-session-duration'.", intel: "Balance security with user experience." },
      { number: 9, title: "Implement Conditions", description: "Add IP and MFA conditions to federated roles.", hint: "Type 'aws iam add-federation-conditions'.", intel: "Condition keys like aws:SourceIp work with SAML." },
      { number: 10, title: "Generate Compliance Report", description: "Document federation security posture.", hint: "Type 'aws iam generate-federation-report'.", intel: "Include recommendations for IdP hardening." }
    ],
    resources: [
      { type: "iam_provider", name: "okta-saml-provider", config: { sessionDuration: 43200, mfaRequired: false }, isVulnerable: true, status: "needs-review" }
    ],
    fixCommands: ["aws iam reduce-session-duration", "aws iam add-federation-conditions"]
  },
  {
    title: "Resource-Based Policy Audit",
    description: "Multiple AWS resources have their own access policies that may bypass IAM. Conduct a comprehensive audit.",
    briefing: "POLICY SPRAWL: S3, KMS, SNS, SQS, and Lambda all have resource policies. Some may grant public access or cross-account permissions you don't know about.",
    scenario: "IAM policies aren't the only way to grant access. Resource policies are the shadow IAM - and they're often forgotten.",
    difficulty: "Advanced",
    category: "IAM Security",
    estimatedTime: "35-50 minutes",
    initialState: { resources: ["s3-policies", "kms-policies", "lambda-policies"] },
    steps: [
      { number: 1, title: "Initialize Audit", description: "Scan all resources for inline policies.", hint: "Type 'scan' to begin analysis.", intel: "IAM Access Analyzer can help identify external access." },
      { number: 2, title: "Audit S3 Bucket Policies", description: "Review all S3 bucket policies for external access.", hint: "Type 'aws s3 audit-bucket-policies'.", intel: "Look for Principal: * which allows public access." },
      { number: 3, title: "Audit KMS Key Policies", description: "Check who can use encryption keys.", hint: "Type 'aws kms audit-key-policies'.", intel: "KMS policies control encryption access - very sensitive." },
      { number: 4, title: "Audit Lambda Policies", description: "Review Lambda function resource policies.", hint: "Type 'aws lambda audit-function-policies'.", intel: "Lambda policies control who can invoke functions." },
      { number: 5, title: "Audit SNS/SQS Policies", description: "Check messaging service access.", hint: "Type 'aws sns-sqs audit-policies'.", intel: "Queue policies can allow cross-account message injection." },
      { number: 6, title: "Enable Access Analyzer", description: "Set up continuous policy analysis.", hint: "Type 'aws access-analyzer enable'.", intel: "Access Analyzer automatically finds external access grants." },
      { number: 7, title: "Review Analyzer Findings", description: "Check what external access exists.", hint: "Type 'aws access-analyzer list-findings'.", intel: "Findings show exactly which principals have access." },
      { number: 8, title: "Remediate Public Access", description: "Remove unintended public access.", hint: "Type 'aws access-analyzer remediate-public'.", intel: "Start with high-severity findings." },
      { number: 9, title: "Remediate Cross-Account", description: "Fix unauthorized cross-account access.", hint: "Type 'aws access-analyzer remediate-cross-account'.", intel: "Verify before removing - some may be intentional." },
      { number: 10, title: "Set Up Monitoring", description: "Alert on future policy changes.", hint: "Type 'aws access-analyzer enable-monitoring'.", intel: "Use EventBridge to trigger on policy modifications." },
      { number: 11, title: "Generate Audit Report", description: "Document all findings and remediations.", hint: "Type 'aws access-analyzer generate-report'.", intel: "Include baseline for future comparisons." }
    ],
    resources: [
      { type: "policy_audit", name: "s3-policies", config: { publicBuckets: 3 }, isVulnerable: true, status: "exposed" },
      { type: "policy_audit", name: "kms-policies", config: { externalAccess: 2 }, isVulnerable: true, status: "external-access" },
      { type: "policy_audit", name: "lambda-policies", config: { publicFunctions: 1 }, isVulnerable: true, status: "public" }
    ],
    fixCommands: ["aws access-analyzer remediate-public", "aws access-analyzer remediate-cross-account", "aws access-analyzer enable-monitoring"]
  },
  {
    title: "Zero Trust IAM Architecture",
    description: "Implement a zero trust model by enforcing strict identity verification, least privilege, and continuous authorization.",
    briefing: "SECURITY TRANSFORMATION: Leadership mandated zero trust. Every access request must be verified, every privilege minimized, every session monitored.",
    scenario: "The perimeter is dead. VPN doesn't mean trusted anymore. It's time to build an IAM architecture that assumes breach.",
    difficulty: "Advanced",
    category: "IAM Security",
    estimatedTime: "40-55 minutes",
    initialState: { architecture: ["current-iam-state"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Evaluate existing IAM architecture.", hint: "Type 'scan' to analyze infrastructure.", intel: "Document trust boundaries and access patterns." },
      { number: 2, title: "Enable MFA Everywhere", description: "Require MFA for all human users.", hint: "Type 'aws iam enforce-mfa-all-users'.", intel: "Zero trust starts with strong authentication." },
      { number: 3, title: "Implement Least Privilege", description: "Right-size all permissions based on usage.", hint: "Type 'aws iam implement-least-privilege'.", intel: "Use Access Analyzer's policy generation feature." },
      { number: 4, title: "Enable Session Policies", description: "Add time and scope limits to sessions.", hint: "Type 'aws iam configure-session-policies'.", intel: "Short sessions limit blast radius of compromise." },
      { number: 5, title: "Configure IP Restrictions", description: "Limit access to known networks.", hint: "Type 'aws iam configure-ip-restrictions'.", intel: "Use aws:SourceIp conditions in policies." },
      { number: 6, title: "Implement Service Control Policies", description: "Add organization-wide guardrails.", hint: "Type 'aws organizations configure-scps'.", intel: "SCPs are the ultimate preventive control." },
      { number: 7, title: "Enable Continuous Monitoring", description: "Set up real-time authorization logging.", hint: "Type 'aws cloudtrail enable-enhanced-logging'.", intel: "CloudTrail Insights can detect anomalies." },
      { number: 8, title: "Configure Anomaly Detection", description: "Alert on unusual access patterns.", hint: "Type 'aws guardduty configure-iam-findings'.", intel: "GuardDuty detects credential abuse automatically." },
      { number: 9, title: "Implement Just-in-Time Access", description: "Enable temporary privilege escalation.", hint: "Type 'aws iam configure-jit-access'.", intel: "Standing privileges are standing risk." },
      { number: 10, title: "Test Zero Trust Controls", description: "Verify all controls work together.", hint: "Type 'aws iam test-zero-trust'.", intel: "Try accessing resources from unexpected locations." },
      { number: 11, title: "Generate Compliance Report", description: "Document zero trust implementation.", hint: "Type 'aws iam generate-zero-trust-report'.", intel: "Map controls to zero trust maturity model." }
    ],
    resources: [
      { type: "iam_architecture", name: "current-iam-state", config: { zeroTrustScore: 35 }, isVulnerable: true, status: "traditional" }
    ],
    fixCommands: ["aws iam enforce-mfa-all-users", "aws iam implement-least-privilege", "aws organizations configure-scps", "aws iam generate-zero-trust-report"]
  }
];

// ============= CLOUD SECURITY ENGINEER LABS (12) =============
export const cloudSecurityEngineerLabs: LabDefinition[] = [
  // BEGINNER LABS (4)
  {
    title: "Security Group Rule Hardening",
    description: "Multiple EC2 instances have overly permissive security group rules. Implement restrictive ingress controls.",
    briefing: "EXPOSED SERVICES: Port scan detected 15 services exposed to the internet. Most should be internal only.",
    scenario: "Your production servers are advertising themselves to the entire internet. It's only a matter of time before an exploit is found.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { securityGroups: ["web-server-sg"] },
    steps: [
      { number: 1, title: "Scan for Exposure", description: "Identify overly permissive security groups.", hint: "Type 'scan' to find vulnerabilities.", intel: "CIS AWS 5.2: Ensure no security groups allow ingress from 0.0.0.0/0 to port 22." },
      { number: 2, title: "List Security Groups", description: "Review all security group configurations.", hint: "Type 'aws ec2 describe-security-groups'.", intel: "Focus on groups attached to production instances." },
      { number: 3, title: "Identify Risky Rules", description: "Find rules allowing 0.0.0.0/0 access.", hint: "Type 'aws ec2 list-open-rules'.", intel: "SSH (22), RDP (3389), and databases should never be public." },
      { number: 4, title: "Restrict Access", description: "Update rules to allow only necessary IPs.", hint: "Type 'aws ec2 harden-security-group web-server-sg'.", intel: "Use prefix lists for maintainable IP allowlists." }
    ],
    resources: [
      { type: "security_group", name: "web-server-sg", config: { openPorts: [22, 3306, 80, 443] }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["aws ec2 harden-security-group web-server-sg"]
  },
  {
    title: "CloudTrail Logging Configuration",
    description: "CloudTrail is not enabled in all regions, creating blind spots for security monitoring. Enable comprehensive logging.",
    briefing: "VISIBILITY GAP: CloudTrail only covers us-east-1. Attackers could operate in other regions undetected.",
    scenario: "An attacker just spun up crypto miners in eu-west-1. You didn't see it because CloudTrail wasn't watching.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { cloudtrail: ["partial-trail"] },
    steps: [
      { number: 1, title: "Assess Logging Coverage", description: "Check CloudTrail configuration.", hint: "Type 'scan' to identify gaps.", intel: "CIS AWS 3.1: Ensure CloudTrail is enabled in all regions." },
      { number: 2, title: "List Trails", description: "See which trails exist.", hint: "Type 'aws cloudtrail describe-trails'.", intel: "Look for IsMultiRegionTrail setting." },
      { number: 3, title: "Check Trail Status", description: "Verify trails are actively logging.", hint: "Type 'aws cloudtrail get-trail-status'.", intel: "A trail can exist but be disabled." },
      { number: 4, title: "Enable Multi-Region", description: "Configure trail to cover all regions.", hint: "Type 'aws cloudtrail enable-all-regions'.", intel: "One multi-region trail is more efficient than regional trails." }
    ],
    resources: [
      { type: "cloudtrail", name: "partial-trail", config: { multiRegion: false, regions: ["us-east-1"] }, isVulnerable: true, status: "partial" }
    ],
    fixCommands: ["aws cloudtrail enable-all-regions"]
  },
  {
    title: "S3 Block Public Access",
    description: "Account-level S3 Block Public Access is disabled, allowing buckets to be made public. Enable account-wide protection.",
    briefing: "ACCOUNT EXPOSURE: S3 Block Public Access is off at the account level. Any bucket can be made public accidentally.",
    scenario: "One misconfigured bucket policy away from a data breach. Time to enable the safety net.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { s3Account: ["public-access-settings"] },
    steps: [
      { number: 1, title: "Check Account Settings", description: "Review S3 account-level settings.", hint: "Type 'scan' to identify configuration.", intel: "Account-level settings override bucket-level settings." },
      { number: 2, title: "Review Current Config", description: "See current Block Public Access status.", hint: "Type 'aws s3 get-public-access-block'.", intel: "All four settings should be enabled." },
      { number: 3, title: "Identify Public Buckets", description: "Find any currently public buckets.", hint: "Type 'aws s3 list-public-buckets'.", intel: "Fix these before enabling block to avoid breaking apps." },
      { number: 4, title: "Enable Block Public Access", description: "Turn on account-level protection.", hint: "Type 'aws s3 enable-account-block-public-access'.", intel: "This is a one-time setting that protects all future buckets." }
    ],
    resources: [
      { type: "s3_account", name: "public-access-settings", config: { blockPublicAccess: false }, isVulnerable: true, status: "unprotected" }
    ],
    fixCommands: ["aws s3 enable-account-block-public-access"]
  },
  {
    title: "Default VPC Security Review",
    description: "The default VPC is in use with default security groups. Implement proper network segmentation.",
    briefing: "DEFAULT INFRASTRUCTURE: Production workloads are running in the default VPC. This violates security best practices.",
    scenario: "The default VPC was designed for convenience, not security. Time to implement proper network architecture.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { vpc: ["default-vpc"] },
    steps: [
      { number: 1, title: "Identify Default Resources", description: "Find resources using default VPC.", hint: "Type 'scan' to analyze.", intel: "CIS AWS 5.3: Ensure the default security group restricts all traffic." },
      { number: 2, title: "Check Default VPC", description: "Review default VPC configuration.", hint: "Type 'aws ec2 describe-default-vpc'.", intel: "Default VPCs have internet gateways and public subnets." },
      { number: 3, title: "Review Default Security Group", description: "Check the default SG rules.", hint: "Type 'aws ec2 describe-default-security-group'.", intel: "Default SGs allow all traffic between members." },
      { number: 4, title: "Restrict Default Security Group", description: "Remove all rules from default SG.", hint: "Type 'aws ec2 restrict-default-security-group'.", intel: "Never use the default SG - create purpose-specific groups." }
    ],
    resources: [
      { type: "vpc", name: "default-vpc", config: { isDefault: true, instanceCount: 5 }, isVulnerable: true, status: "default-in-use" }
    ],
    fixCommands: ["aws ec2 restrict-default-security-group"]
  },

  // INTERMEDIATE LABS (4)
  {
    title: "KMS Key Rotation Policy",
    description: "Customer-managed KMS keys have automatic rotation disabled. Implement key rotation policies.",
    briefing: "ENCRYPTION RISK: 8 KMS keys haven't been rotated in over a year. Compliance requires annual rotation.",
    scenario: "If a key is compromised, you want to limit the blast radius. Rotation ensures old data becomes unreadable to attackers with old keys.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { kmsKeys: ["prod-encryption-key", "backup-key"] },
    steps: [
      { number: 1, title: "Inventory KMS Keys", description: "List all customer-managed keys.", hint: "Type 'scan' to identify keys.", intel: "AWS-managed keys rotate automatically; customer keys don't by default." },
      { number: 2, title: "Check Rotation Status", description: "See which keys have rotation enabled.", hint: "Type 'aws kms list-keys-rotation-status'.", intel: "CIS AWS 3.8: Ensure rotation for customer-created CMKs is enabled." },
      { number: 3, title: "Review Key Usage", description: "Identify what each key encrypts.", hint: "Type 'aws kms describe-key-usage prod-encryption-key'.", intel: "Understanding usage helps prioritize rotation." },
      { number: 4, title: "Check Key Age", description: "Find keys that haven't rotated.", hint: "Type 'aws kms get-key-age prod-encryption-key'.", intel: "Keys older than 365 days should be rotated." },
      { number: 5, title: "Enable Automatic Rotation", description: "Turn on yearly rotation for all keys.", hint: "Type 'aws kms enable-key-rotation prod-encryption-key'.", intel: "Rotation creates new key material but keeps the same key ID." },
      { number: 6, title: "Verify Rotation", description: "Confirm rotation is enabled.", hint: "Type 'aws kms verify-rotation-all'.", intel: "Rotation happens on the anniversary of key creation." }
    ],
    resources: [
      { type: "kms_key", name: "prod-encryption-key", config: { rotationEnabled: false, ageMonths: 18 }, isVulnerable: true, status: "rotation-disabled" },
      { type: "kms_key", name: "backup-key", config: { rotationEnabled: false, ageMonths: 24 }, isVulnerable: true, status: "rotation-disabled" }
    ],
    fixCommands: ["aws kms enable-key-rotation prod-encryption-key", "aws kms enable-key-rotation backup-key"]
  },
  {
    title: "VPC Flow Logs Analysis",
    description: "VPC Flow Logs are disabled, preventing network traffic analysis. Enable and configure flow logging.",
    briefing: "NETWORK BLINDNESS: No VPC Flow Logs means no visibility into network connections. You can't detect lateral movement.",
    scenario: "An attacker is inside your VPC. Without flow logs, you can't see what they're connecting to or exfiltrating.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { vpcs: ["production-vpc"] },
    steps: [
      { number: 1, title: "Check Flow Log Status", description: "Identify VPCs without flow logs.", hint: "Type 'scan' to analyze configuration.", intel: "CIS AWS 3.9: Ensure VPC flow logging is enabled in all VPCs." },
      { number: 2, title: "List VPCs", description: "Review all VPC configurations.", hint: "Type 'aws ec2 describe-vpcs'.", intel: "Production VPCs should always have flow logs." },
      { number: 3, title: "Check Existing Logs", description: "See if any flow logs exist.", hint: "Type 'aws ec2 describe-flow-logs'.", intel: "Flow logs can go to CloudWatch, S3, or both." },
      { number: 4, title: "Create Log Group", description: "Set up CloudWatch log group for flows.", hint: "Type 'aws logs create-flow-log-group'.", intel: "Set appropriate retention to balance cost and forensics needs." },
      { number: 5, title: "Enable Flow Logs", description: "Activate flow logging for the VPC.", hint: "Type 'aws ec2 enable-flow-logs production-vpc'.", intel: "Capture ALL traffic, not just REJECT for security analysis." },
      { number: 6, title: "Verify Logging", description: "Confirm flow logs are capturing traffic.", hint: "Type 'aws ec2 verify-flow-logs production-vpc'.", intel: "Allow a few minutes for logs to appear." }
    ],
    resources: [
      { type: "vpc", name: "production-vpc", config: { flowLogsEnabled: false }, isVulnerable: true, status: "no-logging" }
    ],
    fixCommands: ["aws ec2 enable-flow-logs production-vpc"]
  },
  {
    title: "GuardDuty Threat Detection",
    description: "GuardDuty is not enabled, missing automated threat detection. Enable and configure GuardDuty.",
    briefing: "NO AUTOMATED DETECTION: GuardDuty isn't running. You're relying entirely on manual threat hunting.",
    scenario: "AWS's machine learning-powered threat detection is available - you just haven't turned it on.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { guardduty: ["detector-config"] },
    steps: [
      { number: 1, title: "Check GuardDuty Status", description: "See if GuardDuty is enabled.", hint: "Type 'scan' to analyze.", intel: "GuardDuty analyzes CloudTrail, VPC Flow Logs, and DNS logs." },
      { number: 2, title: "List Detectors", description: "Check for existing detectors.", hint: "Type 'aws guardduty list-detectors'.", intel: "Each region needs its own detector." },
      { number: 3, title: "Enable GuardDuty", description: "Activate GuardDuty in this region.", hint: "Type 'aws guardduty create-detector'.", intel: "GuardDuty starts learning your environment immediately." },
      { number: 4, title: "Configure Data Sources", description: "Enable all threat detection sources.", hint: "Type 'aws guardduty configure-data-sources'.", intel: "S3 protection, EKS protection, and Malware protection are optional add-ons." },
      { number: 5, title: "Set Up Notifications", description: "Configure alerts for findings.", hint: "Type 'aws guardduty configure-notifications'.", intel: "Use EventBridge to route findings to SNS or Lambda." },
      { number: 6, title: "Review Sample Findings", description: "Generate sample findings to test.", hint: "Type 'aws guardduty generate-sample-findings'.", intel: "This helps validate your alerting pipeline." }
    ],
    resources: [
      { type: "guardduty", name: "detector-config", config: { enabled: false }, isVulnerable: true, status: "disabled" }
    ],
    fixCommands: ["aws guardduty create-detector", "aws guardduty configure-notifications"]
  },
  {
    title: "Secrets Manager Rotation",
    description: "Database credentials in Secrets Manager haven't been rotated. Implement automatic rotation.",
    briefing: "STALE SECRETS: Database passwords haven't changed in 6 months. If compromised, attackers have had long-term access.",
    scenario: "Your database password has been the same since launch. How many ex-employees still have it written down?",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { secrets: ["prod-db-credentials"] },
    steps: [
      { number: 1, title: "Inventory Secrets", description: "List all secrets and their rotation status.", hint: "Type 'scan' to analyze.", intel: "Secrets Manager can rotate RDS, Redshift, and DocumentDB credentials automatically." },
      { number: 2, title: "List Secrets", description: "See all secrets in Secrets Manager.", hint: "Type 'aws secretsmanager list-secrets'.", intel: "Check LastRotatedDate for each secret." },
      { number: 3, title: "Check Rotation Config", description: "Review rotation settings for DB credentials.", hint: "Type 'aws secretsmanager get-rotation-config prod-db-credentials'.", intel: "No rotation Lambda means no automatic rotation." },
      { number: 4, title: "Create Rotation Lambda", description: "Set up the rotation function.", hint: "Type 'aws secretsmanager create-rotation-lambda prod-db-credentials'.", intel: "AWS provides rotation templates for common databases." },
      { number: 5, title: "Enable Rotation", description: "Activate automatic rotation.", hint: "Type 'aws secretsmanager enable-rotation prod-db-credentials'.", intel: "Set rotation interval based on compliance requirements." },
      { number: 6, title: "Test Rotation", description: "Trigger a manual rotation to verify.", hint: "Type 'aws secretsmanager rotate-secret prod-db-credentials'.", intel: "Verify applications reconnect successfully after rotation." }
    ],
    resources: [
      { type: "secret", name: "prod-db-credentials", config: { rotationEnabled: false, lastRotated: "180 days ago" }, isVulnerable: true, status: "stale" }
    ],
    fixCommands: ["aws secretsmanager enable-rotation prod-db-credentials", "aws secretsmanager rotate-secret prod-db-credentials"]
  },

  // ADVANCED LABS (4)
  {
    title: "Multi-Account Security Architecture",
    description: "Implement AWS Organizations with SCPs for centralized security governance across multiple accounts.",
    briefing: "ACCOUNT SPRAWL: 15 AWS accounts with inconsistent security controls. Implement centralized governance.",
    scenario: "Each team has their own AWS account with their own rules. It's the Wild West. Time to bring order.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "35-50 minutes",
    initialState: { organization: ["org-root"] },
    steps: [
      { number: 1, title: "Assess Current State", description: "Review organization structure.", hint: "Type 'scan' to analyze.", intel: "Map accounts to business units and security tiers." },
      { number: 2, title: "Review Organization", description: "Check existing OU structure.", hint: "Type 'aws organizations describe-organization'.", intel: "Well-designed OUs enable targeted SCPs." },
      { number: 3, title: "Design OU Structure", description: "Plan organizational units for security.", hint: "Type 'aws organizations list-organizational-units'.", intel: "Separate Production, Development, and Sandbox OUs." },
      { number: 4, title: "Create Security OU", description: "Set up dedicated security account.", hint: "Type 'aws organizations create-security-ou'.", intel: "Security account holds logs, GuardDuty master, etc." },
      { number: 5, title: "Design SCP Strategy", description: "Plan preventive controls.", hint: "Type 'aws organizations plan-scps'.", intel: "SCPs are guardrails that can't be overridden." },
      { number: 6, title: "Create Baseline SCP", description: "Implement foundational restrictions.", hint: "Type 'aws organizations create-baseline-scp'.", intel: "Deny regions, deny disabling CloudTrail, etc." },
      { number: 7, title: "Apply to Production", description: "Attach SCP to production OU.", hint: "Type 'aws organizations attach-scp production-ou'.", intel: "Test in sandbox first to avoid breaking production." },
      { number: 8, title: "Enable Trusted Access", description: "Set up cross-account services.", hint: "Type 'aws organizations enable-trusted-access'.", intel: "Enable for Config, CloudTrail, GuardDuty, Security Hub." },
      { number: 9, title: "Configure Delegated Admin", description: "Delegate security services.", hint: "Type 'aws organizations configure-delegated-admin'.", intel: "Security team manages security services." },
      { number: 10, title: "Test SCPs", description: "Verify controls work as expected.", hint: "Type 'aws organizations test-scps'.", intel: "Try prohibited actions from member accounts." },
      { number: 11, title: "Document Architecture", description: "Generate organization documentation.", hint: "Type 'aws organizations generate-documentation'.", intel: "Include SCP rationale and OU purpose." }
    ],
    resources: [
      { type: "organization", name: "org-root", config: { accounts: 15, scps: 0 }, isVulnerable: true, status: "ungoverned" }
    ],
    fixCommands: ["aws organizations create-baseline-scp", "aws organizations attach-scp production-ou", "aws organizations configure-delegated-admin"]
  },
  {
    title: "Security Hub Centralization",
    description: "Implement AWS Security Hub for centralized security findings aggregation and compliance monitoring.",
    briefing: "FRAGMENTED VISIBILITY: Security findings scattered across GuardDuty, Inspector, Macie, and third-party tools. Centralize everything.",
    scenario: "Your security team checks 5 different dashboards. Critical findings get lost in the noise. Time for a single pane of glass.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "35-50 minutes",
    initialState: { securityHub: ["hub-config"] },
    steps: [
      { number: 1, title: "Assess Current Tools", description: "Inventory security services in use.", hint: "Type 'scan' to analyze.", intel: "Security Hub aggregates from 50+ AWS and third-party sources." },
      { number: 2, title: "Enable Security Hub", description: "Activate Security Hub in the region.", hint: "Type 'aws securityhub enable'.", intel: "Enable in all regions for complete visibility." },
      { number: 3, title: "Enable Standards", description: "Activate compliance standards.", hint: "Type 'aws securityhub enable-standards cis,pci,aws-foundational'.", intel: "Standards provide continuous compliance checking." },
      { number: 4, title: "Configure Integrations", description: "Connect GuardDuty, Inspector, etc.", hint: "Type 'aws securityhub configure-integrations'.", intel: "Most AWS services integrate automatically when enabled." },
      { number: 5, title: "Set Up Cross-Account", description: "Aggregate findings from member accounts.", hint: "Type 'aws securityhub configure-aggregation'.", intel: "Designate a security account as the aggregator." },
      { number: 6, title: "Create Custom Actions", description: "Set up automated response actions.", hint: "Type 'aws securityhub create-custom-actions'.", intel: "Custom actions can trigger Lambda for auto-remediation." },
      { number: 7, title: "Configure Insights", description: "Create finding aggregation insights.", hint: "Type 'aws securityhub create-insights'.", intel: "Insights help identify patterns across findings." },
      { number: 8, title: "Set Up Alerting", description: "Configure notifications for critical findings.", hint: "Type 'aws securityhub configure-alerts'.", intel: "Route CRITICAL and HIGH findings to on-call." },
      { number: 9, title: "Review Baseline", description: "Check initial compliance posture.", hint: "Type 'aws securityhub get-compliance-summary'.", intel: "Expect many findings on first run - prioritize." },
      { number: 10, title: "Create Remediation Plan", description: "Prioritize findings for fix.", hint: "Type 'aws securityhub generate-remediation-plan'.", intel: "Focus on CRITICAL findings first." },
      { number: 11, title: "Document Setup", description: "Generate Security Hub documentation.", hint: "Type 'aws securityhub generate-documentation'.", intel: "Include runbooks for common finding types." }
    ],
    resources: [
      { type: "security_hub", name: "hub-config", config: { enabled: false, standards: 0 }, isVulnerable: true, status: "not-configured" }
    ],
    fixCommands: ["aws securityhub enable", "aws securityhub enable-standards cis,pci,aws-foundational", "aws securityhub configure-aggregation"]
  },
  {
    title: "Infrastructure as Code Security",
    description: "Implement security scanning for CloudFormation and Terraform templates to catch misconfigurations before deployment.",
    briefing: "SHIFT LEFT: Security issues are found in production. Implement IaC scanning to catch problems before deployment.",
    scenario: "Every week, a developer deploys a public S3 bucket. Time to catch these in the PR, not production.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "35-50 minutes",
    initialState: { pipeline: ["ci-cd-pipeline"] },
    steps: [
      { number: 1, title: "Audit Current State", description: "Review existing IaC practices.", hint: "Type 'scan' to analyze.", intel: "What percentage of infrastructure is defined as code?" },
      { number: 2, title: "Inventory Templates", description: "Find all CloudFormation/Terraform.", hint: "Type 'aws cloudformation list-stacks'.", intel: "Include modules and nested stacks." },
      { number: 3, title: "Select Scanner", description: "Choose IaC security scanner.", hint: "Type 'security configure-iac-scanner'.", intel: "Options: cfn-guard, cfn-nag, checkov, tfsec." },
      { number: 4, title: "Create Policy Set", description: "Define security policies to check.", hint: "Type 'security create-iac-policies'.", intel: "Start with CIS benchmarks and custom org policies." },
      { number: 5, title: "Test Scanning", description: "Run scanner on existing templates.", hint: "Type 'security scan-templates'.", intel: "Expect many findings - baseline the noise." },
      { number: 6, title: "Integrate with CI/CD", description: "Add scanning to deployment pipeline.", hint: "Type 'security integrate-ci-cd'.", intel: "Fail builds on HIGH and CRITICAL findings." },
      { number: 7, title: "Configure Exceptions", description: "Set up policy exceptions for edge cases.", hint: "Type 'security configure-exceptions'.", intel: "Exceptions should require approval and have expiry." },
      { number: 8, title: "Set Up Reporting", description: "Configure finding reports.", hint: "Type 'security configure-iac-reporting'.", intel: "Track finding trends over time." },
      { number: 9, title: "Enable Drift Detection", description: "Detect manual changes to IaC resources.", hint: "Type 'aws cloudformation enable-drift-detection'.", intel: "Drift indicates configuration that bypassed IaC." },
      { number: 10, title: "Train Developers", description: "Create developer guidance.", hint: "Type 'security generate-developer-docs'.", intel: "Include examples of secure patterns." },
      { number: 11, title: "Measure Improvement", description: "Track security debt reduction.", hint: "Type 'security generate-iac-metrics'.", intel: "Show ROI of shift-left investment." }
    ],
    resources: [
      { type: "pipeline", name: "ci-cd-pipeline", config: { securityScanning: false }, isVulnerable: true, status: "no-scanning" }
    ],
    fixCommands: ["security configure-iac-scanner", "security integrate-ci-cd", "security generate-iac-metrics"]
  },
  {
    title: "Cloud Security Incident Response",
    description: "Build and test a cloud-native incident response capability with automated containment and forensics.",
    briefing: "IR MATURITY: No cloud-specific incident response plan. When breached, you need automated containment and forensics capability.",
    scenario: "An attacker is in your environment. Do you have automated containment? Can you preserve evidence? Build the capability now.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "40-55 minutes",
    initialState: { irCapability: ["incident-response-setup"] },
    steps: [
      { number: 1, title: "Assess IR Readiness", description: "Evaluate current incident response capability.", hint: "Type 'scan' to analyze.", intel: "NIST CSF RS.RP: Response processes and procedures." },
      { number: 2, title: "Create IR Account", description: "Set up dedicated forensics account.", hint: "Type 'aws organizations create-ir-account'.", intel: "Isolate forensics from production for integrity." },
      { number: 3, title: "Configure Log Aggregation", description: "Centralize logs for investigation.", hint: "Type 'aws logs configure-central-logging'.", intel: "Include CloudTrail, VPC Flow Logs, and application logs." },
      { number: 4, title: "Create Containment Actions", description: "Build automated containment Lambda.", hint: "Type 'aws lambda create-containment-functions'.", intel: "Isolate EC2, revoke keys, snapshot for forensics." },
      { number: 5, title: "Configure Forensics Bucket", description: "Set up immutable evidence storage.", hint: "Type 'aws s3 create-forensics-bucket'.", intel: "Enable object lock and versioning for evidence integrity." },
      { number: 6, title: "Create IR Runbooks", description: "Build step-by-step response procedures.", hint: "Type 'aws ssm create-ir-runbooks'.", intel: "Runbooks in SSM enable automation." },
      { number: 7, title: "Set Up Alerting Pipeline", description: "Configure rapid IR notification.", hint: "Type 'aws events configure-ir-alerts'.", intel: "Critical findings should page immediately." },
      { number: 8, title: "Create Forensics AMI", description: "Build forensics investigation instance.", hint: "Type 'aws ec2 create-forensics-ami'.", intel: "Pre-install tools like Volatility, aws-cli, etc." },
      { number: 9, title: "Test Containment", description: "Simulate incident and test response.", hint: "Type 'aws ir simulate-incident'.", intel: "Tabletop exercises reveal gaps." },
      { number: 10, title: "Measure MTTD/MTTR", description: "Establish response time metrics.", hint: "Type 'aws ir measure-response-times'.", intel: "Mean Time to Detect and Respond are key metrics." },
      { number: 11, title: "Document IR Plan", description: "Generate comprehensive IR documentation.", hint: "Type 'aws ir generate-documentation'.", intel: "Include contacts, escalation, and legal considerations." }
    ],
    resources: [
      { type: "ir_capability", name: "incident-response-setup", config: { automatedContainment: false, forensicsReady: false }, isVulnerable: true, status: "immature" }
    ],
    fixCommands: ["aws lambda create-containment-functions", "aws ssm create-ir-runbooks", "aws ir generate-documentation"]
  }
];

export const allLabs = [
  ...storageSecurityLabs,
  ...networkSecurityLabs,
  ...socOperationsLabs,
  ...socEngineerLabs,
  ...cloudSecurityAnalystLabs,
  ...iamSecurityLabs,
  ...cloudSecurityEngineerLabs,
  ...challengeLabs
];
