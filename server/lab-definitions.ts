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
// Operational security analyst focus: monitoring, detection, investigation, response
// Work with EXISTING environments - not designing infrastructure
// SIEM-based workflows, alert triage, log correlation
// Validate true vs false positives, MITRE ATT&CK mapping
// Incident summaries, timelines, remediation recommendations
// Basic response: credential revocation, access reviews, evidence collection

export const cloudSecurityAnalystLabs: LabDefinition[] = [
  // BEGINNER LABS (4) - Alert triage, basic investigation, documentation
  {
    title: "SIEM Alert Triage and Validation",
    description: "Your SIEM has generated 15 alerts overnight. Triage each alert, validate true positives versus false positives, and document your findings.",
    briefing: "SHIFT HANDOVER: You're taking over the morning shift. The overnight queue has 15 unacknowledged alerts ranging from LOW to HIGH severity. Triage, validate, and clear the queue before the 10 AM standup.",
    scenario: "It's 7:30 AM and you've just logged into the SOC. Your SIEM dashboard shows alerts for failed logins, unusual API calls, and a potential data exfiltration. Most are probably false positives, but one could be real. Your job: find it.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { siem: ["alert-queue"], alerts: ["failed-login-01", "api-anomaly-02", "data-transfer-03"] },
    steps: [
      { number: 1, title: "Review Alert Queue", description: "Access the SIEM and review all pending alerts sorted by severity.", hint: "Type 'siem show-alerts --status pending'.", intel: "Start with HIGH severity alerts - they have the shortest SLA. MITRE ATT&CK T1078: Monitor for unusual account activity." },
      { number: 2, title: "Investigate High Priority", description: "Examine the high-severity API anomaly alert to determine if it's a true positive.", hint: "Type 'siem investigate-alert api-anomaly-02'.", intel: "Check: Is the source IP known? Is the user normally active at this time? Is this API call part of their job function?" },
      { number: 3, title: "Validate or Dismiss", description: "Based on your investigation, mark the alert as true positive or false positive with justification.", hint: "Type 'siem validate-alert api-anomaly-02 --status false-positive --reason normal-automation'.", intel: "Always document your reasoning. 'Looks normal' is not acceptable - cite specific evidence like known IP, approved automation, etc." },
      { number: 4, title: "Document Findings", description: "Complete the alert triage report for the shift handover.", hint: "Type 'siem generate-triage-report'.", intel: "Your report will be reviewed by senior analysts. Include: alerts processed, true positives found, escalations made, patterns noticed." }
    ],
    resources: [
      { type: "alert", name: "failed-login-01", config: { severity: "LOW", source: "CloudTrail", user: "service-account-01" }, isVulnerable: false, status: "pending" },
      { type: "alert", name: "api-anomaly-02", config: { severity: "HIGH", source: "GuardDuty", technique: "T1087" }, isVulnerable: false, status: "pending" },
      { type: "alert", name: "data-transfer-03", config: { severity: "MEDIUM", source: "VPC Flow", bytes: "2.3GB" }, isVulnerable: false, status: "pending" }
    ],
    fixCommands: ["siem validate-alert api-anomaly-02", "siem generate-triage-report"],
    successMessage: "Alert queue cleared. 12 false positives documented, 2 true positives escalated, 1 alert tuned. Ready for shift handover."
  },
  {
    title: "CloudTrail Log Analysis",
    description: "A developer reported their AWS console session felt 'weird' yesterday. Analyze CloudTrail logs to investigate if their credentials were compromised.",
    briefing: "USER REPORT: Developer Sarah Chen says she noticed unfamiliar resources in her console yesterday afternoon. She doesn't remember creating them. Investigate her CloudTrail activity for the past 24 hours.",
    scenario: "Sarah is a backend developer who usually only accesses Lambda and DynamoDB. She called the security hotline because she saw EC2 instances she didn't create. Could be a mistake, could be credential theft.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { logs: ["cloudtrail-sarah"], user: ["sarah.chen"] },
    steps: [
      { number: 1, title: "Query User Activity", description: "Pull all CloudTrail events for Sarah's user in the last 24 hours.", hint: "Type 'aws cloudtrail lookup-events --username sarah.chen --hours 24'.", intel: "Look for the timeline of events. Note any gaps or unusual timing patterns. MITRE ATT&CK T1078.004: Valid cloud accounts." },
      { number: 2, title: "Analyze Source IPs", description: "Check the source IP addresses for Sarah's API calls to identify any anomalies.", hint: "Type 'aws cloudtrail analyze-source-ips sarah.chen'.", intel: "Sarah usually works from the Seattle office (IP range 203.0.113.0/24). Any other locations are suspicious." },
      { number: 3, title: "Identify Unusual Actions", description: "Find API calls that don't match Sarah's normal job function (Lambda/DynamoDB).", hint: "Type 'aws cloudtrail find-anomalous-actions sarah.chen'.", intel: "EC2:RunInstances, IAM:CreateAccessKey, or S3:GetObject on sensitive buckets would all be red flags." },
      { number: 4, title: "Document Investigation", description: "Create an investigation summary with your findings and recommendations.", hint: "Type 'security generate-investigation-summary sarah.chen'.", intel: "Include: timeline, evidence of compromise (or lack thereof), recommended actions, and whether to escalate to IR team." }
    ],
    resources: [
      { type: "user", name: "sarah.chen", config: { role: "developer", normalServices: ["lambda", "dynamodb"], lastLogin: "2024-01-15T14:32:00Z" }, isVulnerable: false, status: "under-investigation" },
      { type: "cloudtrail", name: "cloudtrail-sarah", config: { events: 147, anomalousEvents: 12, unusualIPs: 2 }, isVulnerable: true, status: "suspicious" }
    ],
    fixCommands: ["security generate-investigation-summary sarah.chen"],
    successMessage: "Investigation complete. Found credential compromise via phishing. Sarah's access key was used from Ukraine IP. Escalated to IR for credential rotation and further investigation."
  },
  {
    title: "Public S3 Bucket Alert Investigation",
    description: "GuardDuty detected an S3 bucket that may be publicly accessible. Investigate the alert, assess the exposure, and recommend remediation.",
    briefing: "GUARDDUTY ALERT: Policy:S3/BucketAnonymousAccessGranted detected on bucket 'analytics-export-2024'. Determine if sensitive data is exposed and assess the impact.",
    scenario: "The automated scanner flagged a bucket with anonymous access. Before panicking, you need to determine: What's in the bucket? How long has it been exposed? Has anyone accessed it? Is this intentional (public website assets) or a mistake?",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { guardduty: ["s3-public-finding"], bucket: ["analytics-export-2024"] },
    steps: [
      { number: 1, title: "Review GuardDuty Finding", description: "Examine the GuardDuty finding details to understand what triggered the alert.", hint: "Type 'aws guardduty get-finding s3-public-finding'.", intel: "GuardDuty Policy:S3/BucketAnonymousAccessGranted fires when a bucket policy allows public access. Could be intentional or accidental." },
      { number: 2, title: "Assess Bucket Contents", description: "Check what type of data is stored in the exposed bucket.", hint: "Type 'aws s3 analyze-bucket-contents analytics-export-2024'.", intel: "Look for: PII, credentials, internal documents, or customer data. Public assets (images, JS) are usually acceptable." },
      { number: 3, title: "Check Access Logs", description: "Review S3 access logs to see if any unauthorized parties accessed the data.", hint: "Type 'aws s3 get-access-logs analytics-export-2024'.", intel: "Look for access from unknown IPs, bulk downloads, or access patterns suggesting automated scraping." },
      { number: 4, title: "Document and Recommend", description: "Create a finding report with exposure assessment and remediation recommendation.", hint: "Type 'security generate-finding-report analytics-export-2024'.", intel: "Your report should include: data classification, exposure duration, evidence of access, remediation priority, and recommended actions." }
    ],
    resources: [
      { type: "guardduty_finding", name: "s3-public-finding", config: { severity: 5, type: "Policy:S3/BucketAnonymousAccessGranted" }, isVulnerable: true, status: "active" },
      { type: "s3", name: "analytics-export-2024", config: { publicAccess: true, objectCount: 1247, dataClassification: "internal" }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["security generate-finding-report analytics-export-2024"],
    successMessage: "Investigation complete. Bucket contains internal analytics reports - no PII but business-sensitive. Exposed for 72 hours. 3 external access attempts logged. Recommended immediate remediation - HIGH priority."
  },
  {
    title: "Credential Usage Monitoring",
    description: "Review IAM credential usage reports to identify dormant accounts, unused access keys, and credential hygiene issues.",
    briefing: "WEEKLY REVIEW: Your weekly credential hygiene check is due. Review the IAM credential report and identify accounts that need attention.",
    scenario: "Good security hygiene requires regular credential reviews. Access keys older than 90 days should be rotated. Unused credentials should be disabled. Your job: find the problems and flag them for remediation.",
    difficulty: "Beginner",
    category: "Cloud Security Analyst",
    estimatedTime: "5-10 minutes",
    initialState: { iam: ["credential-report"], users: ["user-list"] },
    steps: [
      { number: 1, title: "Generate Credential Report", description: "Pull the latest IAM credential report for analysis.", hint: "Type 'aws iam generate-credential-report'.", intel: "The credential report shows: password age, access key age, MFA status, last login, and last key usage for all IAM users." },
      { number: 2, title: "Identify Stale Credentials", description: "Find users with access keys older than 90 days or passwords not rotated.", hint: "Type 'aws iam find-stale-credentials --days 90'.", intel: "CIS AWS 1.4: Ensure access keys are rotated every 90 days or less. Old keys increase risk if compromised." },
      { number: 3, title: "Check for Dormant Accounts", description: "Identify accounts that haven't been used in 90+ days.", hint: "Type 'aws iam find-dormant-accounts --days 90'.", intel: "Dormant accounts are prime targets for attackers. If no one is using them, they should be disabled." },
      { number: 4, title: "Generate Hygiene Report", description: "Create a credential hygiene report with findings and recommendations.", hint: "Type 'aws iam generate-hygiene-report'.", intel: "Your report goes to the security team lead. Include: total users, compliant count, violations by type, and priority remediation list." }
    ],
    resources: [
      { type: "credential_report", name: "credential-report", config: { totalUsers: 45, staleKeys: 8, noMFA: 5, dormant: 3 }, isVulnerable: true, status: "review-needed" },
      { type: "user_list", name: "user-list", config: { activeUsers: 42, serviceAccounts: 12 }, isVulnerable: false, status: "active" }
    ],
    fixCommands: ["aws iam generate-hygiene-report"],
    successMessage: "Credential review complete. Identified 8 stale keys, 5 users without MFA, and 3 dormant accounts. Report submitted to security lead for remediation follow-up."
  },

  // INTERMEDIATE LABS (4) - Multi-source correlation, deeper investigation
  {
    title: "Suspicious API Call Investigation",
    description: "CloudTrail detected unusual API calls from a service account at 3 AM. Investigate the activity, correlate with other log sources, and determine if this is malicious.",
    briefing: "ANOMALY DETECTED: Service account 'jenkins-deploy' made 47 DescribeInstances, ListBuckets, and GetCallerIdentity calls at 3:17 AM. This is outside normal CI/CD hours. Investigate immediately.",
    scenario: "Your CI/CD pipeline runs during business hours (9 AM - 6 PM). A service account making reconnaissance-style API calls at 3 AM is a red flag. Either someone is working late, the pipeline is misconfigured, or you have a compromised credential.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { 
      cloudtrail: ["suspicious-api-logs"], 
      siem: ["correlated-events"], 
      user: ["jenkins-deploy"],
      vpc: ["flow-logs"]
    },
    steps: [
      { number: 1, title: "Review Initial Alert", description: "Examine the CloudTrail events that triggered the anomaly detection.", hint: "Type 'aws cloudtrail get-events jenkins-deploy --time 03:00-04:00'.", intel: "MITRE ATT&CK T1087: Account Discovery, T1580: Cloud Infrastructure Discovery. Attackers often enumerate before acting." },
      { number: 2, title: "Analyze Source IP", description: "Check if the API calls came from the expected Jenkins server or an unknown location.", hint: "Type 'aws cloudtrail analyze-source-ip jenkins-deploy'.", intel: "Jenkins server should have a static internal IP. External IPs or Tor exit nodes are immediate red flags." },
      { number: 3, title: "Correlate with VPC Flow Logs", description: "Check network traffic from the source IP around the same timeframe.", hint: "Type 'siem correlate-logs cloudtrail vpc-flow --time 03:00-04:00'.", intel: "Look for: outbound connections to C2 infrastructure, data exfiltration, or lateral movement to other instances." },
      { number: 4, title: "Check for Persistence", description: "Look for any changes the service account made that could indicate persistence.", hint: "Type 'aws cloudtrail find-persistence-indicators jenkins-deploy'.", intel: "T1098: Account Manipulation. Check for CreateAccessKey, AttachUserPolicy, CreateRole, or Lambda modifications." },
      { number: 5, title: "Map to MITRE ATT&CK", description: "Document the observed TTPs and map them to the ATT&CK framework.", hint: "Type 'security map-to-attack jenkins-deploy'.", intel: "Mapping to ATT&CK helps communicate severity and identify gaps in detection coverage." },
      { number: 6, title: "Generate Incident Report", description: "Create a detailed investigation report with timeline, evidence, and recommendations.", hint: "Type 'security generate-incident-report jenkins-deploy'.", intel: "Include: executive summary, detailed timeline, evidence artifacts, MITRE mapping, impact assessment, and containment recommendations." }
    ],
    resources: [
      { type: "service_account", name: "jenkins-deploy", config: { normalHours: "09:00-18:00", suspiciousActivity: true, apiCalls: 47 }, isVulnerable: true, status: "under-investigation" },
      { type: "cloudtrail", name: "suspicious-api-logs", config: { events: 47, techniques: ["T1087", "T1580", "T1078"] }, isVulnerable: true, status: "suspicious" },
      { type: "vpc_flow", name: "flow-logs", config: { suspiciousConnections: 3, externalIPs: 2 }, isVulnerable: true, status: "anomalous" }
    ],
    fixCommands: ["security map-to-attack jenkins-deploy", "security generate-incident-report jenkins-deploy"],
    successMessage: "Investigation complete. Confirmed credential compromise via leaked access key in public repo. Attacker performed reconnaissance but no data exfiltration detected. Recommended: rotate credentials, revoke sessions, enable SCPs."
  },
  {
    title: "Multi-Source Log Correlation",
    description: "An EC2 instance is behaving strangely. Correlate CloudTrail, VPC Flow Logs, and CloudWatch metrics to build a complete picture of the activity.",
    briefing: "BEHAVIORAL ANOMALY: EC2 instance i-0abc123def456 is showing 10x normal CPU usage and unusual network patterns. The application team says they haven't deployed anything new. Investigate.",
    scenario: "Something is wrong with this instance. CPU is maxed out, network traffic is spiking, and no one claims responsibility. Could be a cryptominer, a compromised application, or a runaway process. You need to figure it out fast.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { 
      ec2: ["suspicious-instance"], 
      cloudwatch: ["cpu-metrics", "network-metrics"], 
      vpc: ["instance-flow-logs"],
      cloudtrail: ["instance-api-logs"]
    },
    steps: [
      { number: 1, title: "Establish Baseline", description: "Check the normal behavior pattern for this instance before the anomaly.", hint: "Type 'aws cloudwatch get-baseline i-0abc123def456 --days 7'.", intel: "Understanding normal is crucial. If CPU is usually 20% and now it's 95%, that's a 5x increase - significant deviation." },
      { number: 2, title: "Analyze Network Connections", description: "Review VPC flow logs to identify where the instance is communicating.", hint: "Type 'aws ec2 analyze-flow-logs i-0abc123def456'.", intel: "Look for: connections to known mining pools, C2 IP addresses, or unusual outbound ports (IRC, Tor, cryptocurrency protocols)." },
      { number: 3, title: "Check Instance Changes", description: "Review CloudTrail for any modifications to the instance or its security group.", hint: "Type 'aws cloudtrail get-instance-events i-0abc123def456'.", intel: "T1496: Resource Hijacking. Attackers might have modified security groups to allow their traffic or installed software via SSM." },
      { number: 4, title: "Correlate All Sources", description: "Combine all log sources to build a complete attack timeline.", hint: "Type 'siem correlate-logs cloudtrail vpc-flow cloudwatch --instance i-0abc123def456'.", intel: "The SIEM correlation will show you: when it started, how they got in, what they're doing, and how to stop them." },
      { number: 5, title: "Assess Impact", description: "Determine what data or resources the attacker may have accessed.", hint: "Type 'security assess-impact i-0abc123def456'.", intel: "Check: instance role permissions, attached EBS volumes, network access to other resources, S3 buckets accessible." },
      { number: 6, title: "Recommend Containment", description: "Based on your investigation, recommend immediate containment actions.", hint: "Type 'security recommend-containment i-0abc123def456'.", intel: "Options: isolate via security group, stop instance, snapshot for forensics. Balance between stopping the attack and preserving evidence." }
    ],
    resources: [
      { type: "ec2", name: "suspicious-instance", config: { instanceId: "i-0abc123def456", cpuUsage: "95%", normalCpu: "20%" }, isVulnerable: true, status: "compromised" },
      { type: "cloudwatch", name: "cpu-metrics", config: { currentCpu: 95, baselineCpu: 20, anomalyScore: 8.5 }, isVulnerable: false, status: "alerting" },
      { type: "vpc_flow", name: "instance-flow-logs", config: { suspiciousDestinations: 4, miningPoolConnections: 2 }, isVulnerable: true, status: "suspicious" }
    ],
    fixCommands: ["siem correlate-logs cloudtrail vpc-flow cloudwatch --instance i-0abc123def456", "security recommend-containment i-0abc123def456"],
    successMessage: "Investigation complete. Cryptominer installed via vulnerable web application. Attacker exploited RCE in outdated Tomcat version. Recommended: isolate instance, patch application, rotate instance role credentials."
  },
  {
    title: "GuardDuty Finding Deep Dive",
    description: "GuardDuty generated a HIGH severity finding for unusual console login. Investigate the finding, validate it, and document your analysis.",
    briefing: "GUARDDUTY HIGH: UnauthorizedAccess:IAMUser/ConsoleLogin finding for user 'finance-admin'. Login from new geolocation (Thailand) at unusual hour. User claims they didn't log in.",
    scenario: "The finance admin says she was asleep when this login happened. The login came from Thailand, but she's in Chicago. Either her credentials are compromised, or there's an explanation you haven't found yet (VPN, travel, etc.).",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { 
      guardduty: ["console-login-finding"], 
      cloudtrail: ["login-events"],
      user: ["finance-admin"],
      siem: ["user-activity"]
    },
    steps: [
      { number: 1, title: "Review GuardDuty Finding", description: "Examine the complete GuardDuty finding with all context.", hint: "Type 'aws guardduty get-finding console-login-finding --detail'.", intel: "GuardDuty uses machine learning to establish behavioral baselines. New geolocation logins are flagged when they deviate from patterns." },
      { number: 2, title: "Analyze Login Details", description: "Check CloudTrail for the specific console login event details.", hint: "Type 'aws cloudtrail get-console-login finance-admin'.", intel: "Look at: exact timestamp, source IP, user agent, MFA used (or not), subsequent actions taken after login." },
      { number: 3, title: "Verify with User", description: "Document user verification - confirm they were not traveling or using VPN.", hint: "Type 'security log-user-verification finance-admin'.", intel: "Always verify with the user through a separate channel (phone, in-person). Attackers might control email." },
      { number: 4, title: "Check Post-Login Activity", description: "Review what actions were taken during the suspicious session.", hint: "Type 'aws cloudtrail get-session-activity finance-admin'.", intel: "T1078: If credentials are compromised, attackers typically: enumerate (List/Describe), establish persistence, then access data." },
      { number: 5, title: "Determine True/False Positive", description: "Based on evidence, classify the finding and document your reasoning.", hint: "Type 'aws guardduty classify-finding console-login-finding'.", intel: "True Positive: escalate to IR. False Positive: document reason (travel, VPN). Benign True Positive: expected but unusual activity." },
      { number: 6, title: "Generate Analysis Report", description: "Create a detailed analysis report following the IR playbook format.", hint: "Type 'security generate-analysis-report console-login-finding'.", intel: "Report should include: finding summary, investigation steps taken, evidence collected, classification decision, and next steps." }
    ],
    resources: [
      { type: "guardduty_finding", name: "console-login-finding", config: { severity: 8, type: "UnauthorizedAccess:IAMUser/ConsoleLogin", location: "Thailand" }, isVulnerable: true, status: "active" },
      { type: "user", name: "finance-admin", config: { normalLocation: "Chicago", mfaEnabled: true, role: "FinanceAdmin" }, isVulnerable: true, status: "suspicious" },
      { type: "cloudtrail", name: "login-events", config: { loginTime: "02:34 UTC", userAgent: "Mozilla/5.0", mfaUsed: false }, isVulnerable: true, status: "anomalous" }
    ],
    fixCommands: ["aws guardduty classify-finding console-login-finding", "security generate-analysis-report console-login-finding"],
    successMessage: "Analysis complete. TRUE POSITIVE confirmed - MFA was bypassed using stolen session token. Attacker accessed financial reports. Escalated to IR team. User credentials rotated, sessions revoked."
  },
  {
    title: "False Positive Tuning and Validation",
    description: "The SIEM is generating too many false positive alerts for a specific detection rule. Analyze the noise, create tuning recommendations, and validate improvements.",
    briefing: "ALERT FATIGUE: The 'Unusual S3 Access Pattern' rule fired 347 times last week. The SOC team says 95% are false positives from a legitimate backup job. Your task: tune the rule without losing real detections.",
    scenario: "Alert fatigue is real. When analysts see the same false positive 50 times a day, they start ignoring the alert entirely. That's when the real attack slips through. You need to tune the rule to reduce noise while maintaining detection capability.",
    difficulty: "Intermediate",
    category: "Cloud Security Analyst",
    estimatedTime: "15-25 minutes",
    initialState: { 
      siem: ["noisy-rule", "alert-samples"],
      detection: ["unusual-s3-rule"],
      logs: ["s3-access-logs"]
    },
    steps: [
      { number: 1, title: "Analyze Alert Distribution", description: "Review the alert patterns to understand what's causing the noise.", hint: "Type 'siem analyze-alert-pattern unusual-s3-rule'.", intel: "Look for: common source IPs, users, time patterns, or specific buckets that appear in most false positives." },
      { number: 2, title: "Sample True vs False", description: "Manually review a sample of alerts to identify distinguishing characteristics.", hint: "Type 'siem sample-alerts unusual-s3-rule --count 20'.", intel: "Document what makes true positives different: unusual timing, unknown IPs, sensitive buckets, bulk downloads vs incremental." },
      { number: 3, title: "Identify Tuning Criteria", description: "Define specific exclusion criteria based on your analysis.", hint: "Type 'siem identify-exclusions unusual-s3-rule'.", intel: "Good exclusions: specific service account + specific bucket + specific time window. Bad exclusions: too broad (any service account)." },
      { number: 4, title: "Create Tuning Proposal", description: "Document the proposed rule modifications with justification.", hint: "Type 'siem create-tuning-proposal unusual-s3-rule'.", intel: "Your proposal needs: current rule logic, proposed changes, expected noise reduction, detection coverage preserved, rollback plan." },
      { number: 5, title: "Test in Simulation", description: "Run the tuned rule against historical data to validate it catches real threats.", hint: "Type 'siem test-rule unusual-s3-rule --historical 30d'.", intel: "The tuned rule should: catch all true positives from the last 30 days, reduce false positives by target amount." },
      { number: 6, title: "Document and Deploy", description: "Finalize the tuning documentation and prepare for deployment.", hint: "Type 'siem deploy-tuning unusual-s3-rule'.", intel: "Include: before/after metrics, test results, approval chain, monitoring plan for first week after deployment." }
    ],
    resources: [
      { type: "detection_rule", name: "unusual-s3-rule", config: { alertsLastWeek: 347, falsePositiveRate: "95%", truePositives: 17 }, isVulnerable: false, status: "noisy" },
      { type: "siem", name: "noisy-rule", config: { backupJobAlerts: 330, legitimateAlerts: 17 }, isVulnerable: false, status: "needs-tuning" },
      { type: "logs", name: "s3-access-logs", config: { totalEvents: 1500000, anomalousEvents: 347 }, isVulnerable: false, status: "available" }
    ],
    fixCommands: ["siem create-tuning-proposal unusual-s3-rule", "siem deploy-tuning unusual-s3-rule"],
    successMessage: "Rule tuned successfully. Added exclusion for backup service account during 2-4 AM window. False positives reduced by 92% while maintaining all true positive detections. Monitoring for 7 days."
  },

  // ADVANCED LABS (4) - Complex investigations, incident response, reporting
  {
    title: "Compromised Credential Investigation",
    description: "An access key was found in a public GitHub repository. Investigate the exposure, determine impact, coordinate containment, and produce a comprehensive incident report.",
    briefing: "CREDENTIAL LEAK: GitHub secret scanning detected AWS access key AKIA3EXAMPLE in public repository 'acme-corp/legacy-app'. Key belongs to user 'deployment-service'. Assume compromise - investigate immediately.",
    scenario: "The moment a credential hits a public repo, automated scanners (and attackers) find it within minutes. You're in a race against time. Has the key already been used maliciously? What damage could have been done? You need answers fast.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "30-45 minutes",
    initialState: { 
      iam: ["compromised-key", "deployment-service"],
      cloudtrail: ["key-usage-logs"],
      siem: ["correlated-activity"],
      github: ["exposed-repo"]
    },
    steps: [
      { number: 1, title: "Confirm Exposure", description: "Verify the leaked credential and gather initial context.", hint: "Type 'security confirm-credential-exposure AKIA3EXAMPLE'.", intel: "Document: when was repo made public, when was key committed, what permissions does the key have, is it still active." },
      { number: 2, title: "Timeline Malicious Usage", description: "Query CloudTrail for all usage of the compromised key, especially after exposure.", hint: "Type 'aws cloudtrail get-key-usage AKIA3EXAMPLE --since exposure'.", intel: "Focus on: API calls from unknown IPs, reconnaissance (List/Describe), persistence (CreateKey/CreateRole), data access." },
      { number: 3, title: "Identify Attacker Actions", description: "Map all suspicious activity to understand attacker objectives.", hint: "Type 'security analyze-attacker-actions AKIA3EXAMPLE'.", intel: "T1078.004 + T1087 + T1580: Attackers typically: validate credentials, enumerate access, establish persistence, then pivot to objectives." },
      { number: 4, title: "Assess Data Impact", description: "Determine what sensitive data the attacker could have accessed or exfiltrated.", hint: "Type 'security assess-data-exposure deployment-service'.", intel: "Review: S3 bucket access, database queries, secrets accessed. Check CloudTrail data events if available." },
      { number: 5, title: "Coordinate Containment", description: "Work with the IR playbook to execute containment actions.", hint: "Type 'ir execute-playbook credential-compromise --key AKIA3EXAMPLE'.", intel: "Playbook steps: disable key, revoke sessions, check for persistence, rotate related secrets, notify stakeholders." },
      { number: 6, title: "Check for Persistence", description: "Identify any backdoors or persistence mechanisms the attacker may have created.", hint: "Type 'security find-persistence deployment-service'.", intel: "Check: new IAM users, new access keys, modified roles, Lambda functions, EC2 instances with roles, SSM documents." },
      { number: 7, title: "Collect Evidence", description: "Preserve forensic evidence according to chain of custody requirements.", hint: "Type 'forensics collect-evidence AKIA3EXAMPLE'.", intel: "Evidence: CloudTrail logs, VPC flow logs, S3 access logs, IAM credential reports, GitHub commit history." },
      { number: 8, title: "Map to MITRE ATT&CK", description: "Document observed techniques using the ATT&CK framework.", hint: "Type 'security map-to-attack AKIA3EXAMPLE'.", intel: "Common techniques: T1078.004 (Cloud Accounts), T1087 (Account Discovery), T1580 (Cloud Infrastructure Discovery), T1530 (Data from Cloud Storage)." },
      { number: 9, title: "Create Incident Timeline", description: "Build a detailed timeline of the incident from initial exposure to containment.", hint: "Type 'ir create-timeline AKIA3EXAMPLE'.", intel: "Timeline should include: credential committed, repo made public, first malicious use, detection, containment, and remediation milestones." },
      { number: 10, title: "Generate Incident Report", description: "Produce comprehensive incident report for stakeholders.", hint: "Type 'ir generate-incident-report AKIA3EXAMPLE'.", intel: "Report sections: executive summary, timeline, technical details, impact assessment, containment actions, lessons learned, recommendations." }
    ],
    resources: [
      { type: "access_key", name: "compromised-key", config: { keyId: "AKIA3EXAMPLE", exposedSince: "48 hours", maliciousUsage: true }, isVulnerable: true, status: "compromised" },
      { type: "iam_user", name: "deployment-service", config: { permissions: "S3FullAccess, EC2ReadOnly, IAMReadOnly" }, isVulnerable: true, status: "compromised" },
      { type: "cloudtrail", name: "key-usage-logs", config: { totalEvents: 234, suspiciousEvents: 89, externalIPs: 3 }, isVulnerable: true, status: "analyzed" }
    ],
    fixCommands: ["ir execute-playbook credential-compromise", "ir generate-incident-report AKIA3EXAMPLE"],
    successMessage: "Incident contained. Key disabled, persistence removed, evidence preserved. Attacker accessed 3 S3 buckets but no PII confirmed exfiltrated. Full incident report delivered to CISO within 4-hour SLA."
  },
  {
    title: "Data Exfiltration Detection and Analysis",
    description: "Anomaly detection flagged unusual outbound data transfer from a production database server. Investigate the potential data exfiltration and determine scope of exposure.",
    briefing: "EXFILTRATION ALERT: VPC Flow Logs show 47GB transferred from db-prod-01 to external IP 185.x.x.x over the past 6 hours. Normal daily egress is under 500MB. Investigate immediately.",
    scenario: "Your database server is sending massive amounts of data somewhere it shouldn't. This could be a backup gone wrong, a compromised application, or an insider threat. You need to determine: what data, where did it go, and is it still happening.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "35-50 minutes",
    initialState: { 
      vpc: ["exfil-flow-logs"],
      ec2: ["db-prod-01"],
      database: ["production-db"],
      siem: ["exfil-alerts"],
      threat_intel: ["ip-reputation"]
    },
    steps: [
      { number: 1, title: "Analyze Flow Patterns", description: "Examine VPC flow logs to understand the data transfer pattern.", hint: "Type 'aws ec2 analyze-flows db-prod-01 --destination 185.x.x.x'.", intel: "Look for: connection duration, packet counts, timing patterns (continuous vs bursts), ports used, protocol analysis." },
      { number: 2, title: "Identify Destination", description: "Research the external IP to understand who's receiving the data.", hint: "Type 'threatintel lookup-ip 185.x.x.x'.", intel: "Check: IP reputation, geolocation, hosting provider, known malicious associations, reverse DNS, historical activity." },
      { number: 3, title: "Correlate with Application Logs", description: "Check database and application logs for queries that could explain the data transfer.", hint: "Type 'siem correlate-logs database-logs application-logs --time 6h'.", intel: "Look for: unusual SELECT * queries, database dumps, bulk exports, application-initiated transfers, scheduled jobs." },
      { number: 4, title: "Check for Compromise Indicators", description: "Look for signs that the database server itself may be compromised.", hint: "Type 'security check-compromise-indicators db-prod-01'.", intel: "Check: new processes, network connections, modified files, scheduled tasks, new user accounts, security group changes." },
      { number: 5, title: "Assess Data Classification", description: "Determine what type of data was potentially exfiltrated.", hint: "Type 'security assess-data-classification production-db'.", intel: "Identify: tables accessed, PII/PCI/PHI content, customer data, financial records, intellectual property." },
      { number: 6, title: "Calculate Exposure Scope", description: "Estimate the volume and sensitivity of data potentially exposed.", hint: "Type 'security calculate-exposure-scope db-prod-01 47GB'.", intel: "47GB could be: all customer records, years of transaction data, complete database dump. Quantify the impact." },
      { number: 7, title: "Coordinate Containment", description: "Execute containment actions while preserving forensic evidence.", hint: "Type 'ir contain-exfiltration db-prod-01'.", intel: "Containment options: block destination IP, isolate instance, throttle network, but preserve instance state for forensics." },
      { number: 8, title: "Collect Forensic Evidence", description: "Preserve all relevant evidence for potential legal proceedings.", hint: "Type 'forensics collect-exfiltration-evidence db-prod-01'.", intel: "Collect: memory dump, disk image, network logs, database query logs, authentication logs, file integrity data." },
      { number: 9, title: "Prepare Breach Assessment", description: "Determine if this qualifies as a reportable data breach.", hint: "Type 'compliance assess-breach-notification db-prod-01'.", intel: "Consider: data types exposed, jurisdiction (GDPR, CCPA), notification timelines, regulatory requirements." },
      { number: 10, title: "Generate Executive Report", description: "Create incident report for executive leadership and legal team.", hint: "Type 'ir generate-executive-report db-prod-01'.", intel: "Executive summary: what happened, what was exposed, business impact, customer impact, regulatory implications, remediation status." }
    ],
    resources: [
      { type: "vpc_flow", name: "exfil-flow-logs", config: { bytesTransferred: "47GB", destinationIP: "185.x.x.x", duration: "6 hours" }, isVulnerable: true, status: "active-exfil" },
      { type: "ec2", name: "db-prod-01", config: { type: "database", normalEgress: "500MB/day", currentEgress: "47GB" }, isVulnerable: true, status: "suspicious" },
      { type: "database", name: "production-db", config: { recordCount: 2500000, piiTables: 5, pciTables: 2 }, isVulnerable: true, status: "potentially-exposed" }
    ],
    fixCommands: ["ir contain-exfiltration db-prod-01", "ir generate-executive-report db-prod-01"],
    successMessage: "Exfiltration stopped. Cause: compromised web application with SQL injection leading to database dump. 2.3M customer records potentially exposed. Breach notification process initiated. Full forensic report delivered."
  },
  {
    title: "Cloud Security Incident Investigation",
    description: "Multiple security alerts fired simultaneously across different cloud services. Conduct a coordinated investigation to determine if these are related incidents or a coordinated attack.",
    briefing: "MULTI-VECTOR ALERT: Within 30 minutes: GuardDuty IAM anomaly, S3 public bucket alert, and suspicious EC2 instance. Determine if these are coincidental or a coordinated attack.",
    scenario: "Three different alerts from three different services all within half an hour. Coincidence is possible, but unlikely. If this is a coordinated attack, you need to understand the full scope before the attacker achieves their objective.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "40-55 minutes",
    initialState: { 
      guardduty: ["iam-finding", "ec2-finding"],
      s3: ["public-bucket-alert"],
      cloudtrail: ["unified-logs"],
      siem: ["correlated-timeline"],
      ir: ["investigation-workspace"]
    },
    steps: [
      { number: 1, title: "Gather All Alerts", description: "Collect and review all three alerts with full context.", hint: "Type 'siem gather-related-alerts --time-window 30m'.", intel: "Collect: GuardDuty findings, S3 alerts, EC2 anomalies. Note timestamps, affected resources, and severity." },
      { number: 2, title: "Establish Common Elements", description: "Look for connections between the three incidents.", hint: "Type 'security find-common-indicators'.", intel: "Check for: same IAM principal, same source IP, same time window, linked resources, shared VPC, common tags." },
      { number: 3, title: "Build Unified Timeline", description: "Create a single timeline of all events across all three incidents.", hint: "Type 'ir create-unified-timeline'.", intel: "A unified timeline reveals attack progression: initial access -> privilege escalation -> lateral movement -> objective." },
      { number: 4, title: "Identify Attack Chain", description: "Determine the sequence of attacker actions and map to ATT&CK.", hint: "Type 'security identify-attack-chain'.", intel: "Likely pattern: IAM credential compromise (T1078) -> Reconnaissance (T1580) -> Data access (T1530) -> Covering tracks (T1070)." },
      { number: 5, title: "Assess Full Scope", description: "Determine all resources and data potentially impacted.", hint: "Type 'ir assess-incident-scope'.", intel: "Beyond the three alerts: what else could this principal access? What other resources share network access? What data is at risk?" },
      { number: 6, title: "Execute IR Playbook", description: "Follow the incident response playbook for coordinated attacks.", hint: "Type 'ir execute-playbook coordinated-attack'.", intel: "Playbook priorities: contain all affected resources, preserve evidence, identify all compromise indicators, prevent lateral movement." },
      { number: 7, title: "Hunt for Additional Indicators", description: "Proactively search for compromise indicators beyond the alerts.", hint: "Type 'hunt search-iocs'.", intel: "Hunt for: other users from same IP, other resources in same VPC, similar patterns in other accounts, persistence mechanisms." },
      { number: 8, title: "Document Evidence Chain", description: "Create formal evidence documentation for each finding.", hint: "Type 'forensics document-evidence-chain'.", intel: "For each piece of evidence: source, collection method, hash, chain of custody, relevance to incident." },
      { number: 9, title: "Coordinate Stakeholder Communication", description: "Prepare communications for various stakeholders.", hint: "Type 'ir prepare-stakeholder-comms'.", intel: "Different audiences need different information: SOC (technical details), management (impact), legal (breach implications)." },
      { number: 10, title: "Create Comprehensive Report", description: "Produce the full incident report with all findings and recommendations.", hint: "Type 'ir generate-comprehensive-report'.", intel: "Report must include: executive summary, attack narrative, timeline, impact assessment, response actions, lessons learned, recommendations." },
      { number: 11, title: "Define Remediation Actions", description: "Document specific remediation steps to prevent recurrence.", hint: "Type 'ir define-remediation-plan'.", intel: "Remediation should address: root cause, detection gaps, response improvements, control enhancements." }
    ],
    resources: [
      { type: "guardduty_finding", name: "iam-finding", config: { severity: 8, type: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration" }, isVulnerable: true, status: "active" },
      { type: "guardduty_finding", name: "ec2-finding", config: { severity: 7, type: "Trojan:EC2/DNSDataExfiltration" }, isVulnerable: true, status: "active" },
      { type: "s3_alert", name: "public-bucket-alert", config: { bucket: "internal-reports", exposure: "public" }, isVulnerable: true, status: "exposed" },
      { type: "investigation", name: "investigation-workspace", config: { alerts: 3, correlation: "high" }, isVulnerable: true, status: "in-progress" }
    ],
    fixCommands: ["ir execute-playbook coordinated-attack", "ir generate-comprehensive-report"],
    successMessage: "Coordinated attack confirmed and contained. Attacker gained initial access via phished credentials, escalated via instance role, exfiltrated via DNS tunneling. All three alerts were related. Full containment achieved, comprehensive report delivered."
  },
  {
    title: "Threat Hunting with MITRE ATT&CK",
    description: "Conduct a proactive threat hunt across your cloud environment using MITRE ATT&CK techniques. Search for indicators of undetected compromise.",
    briefing: "PROACTIVE HUNT: No active alerts, but threat intel suggests adversaries are targeting organizations like yours. Conduct a threat hunt focusing on cloud-specific ATT&CK techniques.",
    scenario: "Your SIEM is quiet, but that doesn't mean you're safe. Sophisticated attackers evade detection. Your job: actively search for threats that might be lurking in your environment using structured threat hunting methodology.",
    difficulty: "Advanced",
    category: "Cloud Security Analyst",
    estimatedTime: "45-60 minutes",
    initialState: { 
      cloudtrail: ["hunt-logs"],
      vpc: ["network-logs"],
      siem: ["hunt-workspace"],
      threat_intel: ["current-iocs"],
      mitre: ["cloud-techniques"]
    },
    steps: [
      { number: 1, title: "Define Hunt Hypothesis", description: "Create a structured hypothesis based on threat intelligence and ATT&CK.", hint: "Type 'hunt create-hypothesis'.", intel: "Good hypothesis: 'Attackers may have established persistence via Lambda functions (T1525) based on recent threat reports targeting our industry.'" },
      { number: 2, title: "Select ATT&CK Techniques", description: "Choose specific cloud ATT&CK techniques to hunt for.", hint: "Type 'hunt select-techniques cloud'.", intel: "Priority cloud techniques: T1078.004 (Cloud Accounts), T1530 (Cloud Storage), T1537 (Transfer to Cloud Account), T1525 (Cloud Compute)." },
      { number: 3, title: "Build Hunt Queries", description: "Create specific search queries for each selected technique.", hint: "Type 'hunt build-queries T1078.004 T1530 T1525'.", intel: "Queries should search for: anomalous API patterns, unusual data access, new compute resources, unexpected identity usage." },
      { number: 4, title: "Execute T1078.004 Hunt", description: "Hunt for compromised cloud accounts and credential abuse.", hint: "Type 'hunt execute T1078.004'.", intel: "Look for: impossible travel, unusual login hours, failed then successful auth, API calls from new locations." },
      { number: 5, title: "Execute T1530 Hunt", description: "Hunt for unauthorized access to cloud storage.", hint: "Type 'hunt execute T1530'.", intel: "Look for: bulk downloads, access from unusual IPs, sensitive bucket access by unexpected principals." },
      { number: 6, title: "Execute T1525 Hunt", description: "Hunt for malicious code in cloud compute resources.", hint: "Type 'hunt execute T1525'.", intel: "Look for: new Lambda functions, modified Lambda code, unusual EC2 AMIs, containers from untrusted registries." },
      { number: 7, title: "Analyze Hunt Results", description: "Review findings from all hunt queries.", hint: "Type 'hunt analyze-results'.", intel: "Categorize findings: confirmed malicious, suspicious needs investigation, benign but unusual, known good." },
      { number: 8, title: "Investigate Suspicious Findings", description: "Deep dive on suspicious items that warrant further investigation.", hint: "Type 'hunt investigate-findings'.", intel: "For each suspicious finding: gather additional context, correlate with other data sources, determine true/false positive." },
      { number: 9, title: "Document Discoveries", description: "Record all findings, whether malicious or benign.", hint: "Type 'hunt document-findings'.", intel: "Document everything: confirmed threats, new detection opportunities, gaps in visibility, baseline updates needed." },
      { number: 10, title: "Create Detection Rules", description: "Turn hunt findings into new detection rules.", hint: "Type 'hunt create-detections'.", intel: "Good hunts produce: new SIEM rules, updated baselines, improved alert logic, enhanced monitoring coverage." },
      { number: 11, title: "Generate Hunt Report", description: "Produce formal threat hunt report with methodology and findings.", hint: "Type 'hunt generate-report'.", intel: "Report includes: hypothesis, methodology, techniques hunted, findings, new detections created, recommendations." }
    ],
    resources: [
      { type: "hunt_workspace", name: "hunt-workspace", config: { techniques: ["T1078.004", "T1530", "T1525"], dataSourcesDays: 30 }, isVulnerable: false, status: "active" },
      { type: "cloudtrail", name: "hunt-logs", config: { eventsAvailable: 15000000, daysRetained: 90 }, isVulnerable: false, status: "available" },
      { type: "threat_intel", name: "current-iocs", config: { activeIndicators: 1250, cloudSpecific: 340 }, isVulnerable: false, status: "current" },
      { type: "mitre", name: "cloud-techniques", config: { techniques: 35, detectionCoverage: "60%" }, isVulnerable: false, status: "mapped" }
    ],
    fixCommands: ["hunt create-detections", "hunt generate-report"],
    successMessage: "Hunt complete. Discovered dormant persistence mechanism via old Lambda function with backdoor code - compromised 6 months ago but never detected. Created 4 new detection rules. Detection coverage improved from 60% to 75%."
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
// Production-style labs with proper architecture: VPCs, subnets, routing, compute, load balancers
// IAM with least-privilege, MFA, service identities, privilege escalation detection
// Network security: security groups, firewall rules, flow logs, admin access restriction
// Comprehensive logging: CloudTrail, SIEM integration, MITRE ATT&CK mapped alerts
// Attack scenarios: exposed storage, compromised credentials, lateral movement
// Incident response: automated containment, evidence preservation, forensics
// Data protection: encryption, key management, compliance controls
// Infrastructure as Code: scanning, secure defaults, drift detection

export const cloudSecurityEngineerLabs: LabDefinition[] = [
  // BEGINNER LABS (4) - Quick fixes, foundational security controls
  {
    title: "Production VPC Network Segmentation",
    description: "The production environment runs in a flat network without proper segmentation. Implement a secure multi-tier VPC architecture with public, private, and data subnets.",
    briefing: "ARCHITECTURE REVIEW FAILED: External auditors flagged your network architecture. All tiers run in the same subnet with no network segmentation. An attacker who compromises the web tier has direct access to databases.",
    scenario: "Your three-tier web application (web servers, application servers, databases) all share the same subnet. If an attacker exploits an SSRF in your web app, they can pivot directly to your database. Time to implement proper network isolation.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { vpc: ["prod-vpc"], subnets: ["flat-subnet"], instances: ["web-01", "app-01", "db-01"] },
    steps: [
      { number: 1, title: "Assess Network Architecture", description: "Scan the environment to understand the current network topology and identify segmentation issues.", hint: "Type 'scan' to analyze the infrastructure.", intel: "CIS AWS 5.1: Use network segmentation to isolate sensitive systems. MITRE ATT&CK T1557: Adversaries exploit flat networks for lateral movement." },
      { number: 2, title: "Review VPC Configuration", description: "Examine the current VPC and subnet configuration to understand the architecture.", hint: "Type 'aws ec2 describe-vpc-architecture'.", intel: "A well-designed VPC has public subnets (ALB, bastion), private subnets (app tier), and data subnets (databases) across multiple AZs." },
      { number: 3, title: "Identify Segmentation Gaps", description: "List resources and their current subnet placement to identify what needs to move.", hint: "Type 'aws ec2 list-resource-placement'.", intel: "Web servers should be behind ALB in public subnets, app servers in private subnets, databases in isolated data subnets with no internet access." },
      { number: 4, title: "Implement Network Segmentation", description: "Apply the recommended network architecture with proper tier isolation.", hint: "Type 'aws ec2 implement-network-segmentation prod-vpc'.", intel: "Use NACLs as a second layer of defense. Restrict inter-tier traffic to only required ports (e.g., 443 from web to app, 5432 from app to db)." }
    ],
    resources: [
      { type: "vpc", name: "prod-vpc", config: { cidr: "10.0.0.0/16", segmentation: "flat" }, isVulnerable: true, status: "misconfigured" },
      { type: "subnet", name: "flat-subnet", config: { type: "public", allTiers: true }, isVulnerable: true, status: "flat-network" },
      { type: "ec2", name: "web-01", config: { tier: "web", subnet: "flat-subnet" }, isVulnerable: false, status: "running" },
      { type: "ec2", name: "app-01", config: { tier: "app", subnet: "flat-subnet" }, isVulnerable: false, status: "running" },
      { type: "rds", name: "db-01", config: { tier: "data", subnet: "flat-subnet", publiclyAccessible: true }, isVulnerable: true, status: "exposed" }
    ],
    fixCommands: ["aws ec2 implement-network-segmentation prod-vpc"],
    successMessage: "Network segmentation implemented! Your three-tier architecture now has proper isolation. Web tier in public subnets, app tier in private subnets, data tier in isolated subnets with no internet routes."
  },
  {
    title: "IAM Least Privilege Foundation",
    description: "Service accounts and application roles have overly permissive policies with administrative access. Implement least privilege principles.",
    briefing: "IAM AUDIT CRITICAL: The application service role has AdministratorAccess attached. This violates the principle of least privilege and creates massive blast radius if compromised.",
    scenario: "Your Lambda function only needs to read from S3 and write to DynamoDB, but it has full admin access to all AWS services. If an attacker finds an SSRF or code injection, they own your entire AWS account.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { roles: ["app-service-role", "lambda-execution-role"], policies: ["AdministratorAccess"] },
    steps: [
      { number: 1, title: "Scan for Privilege Issues", description: "Identify overly permissive IAM policies attached to service roles.", hint: "Type 'scan' to analyze IAM configurations.", intel: "CIS AWS 1.16: Ensure IAM policies are attached only to groups or roles. MITRE ATT&CK T1078.004: Attackers target overly permissive cloud accounts." },
      { number: 2, title: "Analyze Role Permissions", description: "Review the current permissions attached to the application service role.", hint: "Type 'aws iam analyze-role-permissions app-service-role'.", intel: "Use AWS IAM Access Analyzer to identify unused permissions. Most applications need less than 10% of the permissions they're granted." },
      { number: 3, title: "Review Actual Usage", description: "Check CloudTrail to see which API calls the role actually makes.", hint: "Type 'aws iam get-service-last-accessed app-service-role'.", intel: "IAM Access Analyzer can generate policies based on actual usage patterns from CloudTrail logs." },
      { number: 4, title: "Implement Least Privilege", description: "Replace overly permissive policies with scoped-down policies based on actual needs.", hint: "Type 'aws iam implement-least-privilege app-service-role'.", intel: "Always use resource-level permissions where possible. Use conditions to restrict by VPC, IP, or time." }
    ],
    resources: [
      { type: "iam_role", name: "app-service-role", config: { policies: ["AdministratorAccess"], lastAccessed: "s3:GetObject, dynamodb:PutItem" }, isVulnerable: true, status: "overly-permissive" },
      { type: "iam_role", name: "lambda-execution-role", config: { policies: ["AdministratorAccess"] }, isVulnerable: true, status: "overly-permissive" }
    ],
    fixCommands: ["aws iam implement-least-privilege app-service-role"],
    successMessage: "Least privilege implemented! Service roles now have only the permissions they actually need. Blast radius significantly reduced."
  },
  {
    title: "CloudTrail Comprehensive Logging",
    description: "CloudTrail is partially configured with gaps in logging coverage. Implement comprehensive audit logging with data events and log file validation.",
    briefing: "VISIBILITY GAP: CloudTrail only logs management events in us-east-1. Attackers could read S3 data, invoke Lambda functions, or operate in other regions completely undetected.",
    scenario: "An insider is exfiltrating customer data from S3. You try to investigate but realize CloudTrail doesn't capture S3 data events. You're flying blind.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { cloudtrail: ["partial-trail"], s3: ["cloudtrail-logs-bucket"] },
    steps: [
      { number: 1, title: "Audit Logging Coverage", description: "Scan for gaps in CloudTrail configuration across all regions and event types.", hint: "Type 'scan' to identify logging gaps.", intel: "CIS AWS 3.1-3.4: CloudTrail should be enabled in all regions with log validation and S3 bucket logging." },
      { number: 2, title: "Review Trail Configuration", description: "Examine the current CloudTrail settings to understand what's being logged.", hint: "Type 'aws cloudtrail describe-trails'.", intel: "A complete trail needs: multi-region, data events for S3/Lambda, management events, log file validation, and encrypted logs." },
      { number: 3, title: "Check Data Event Coverage", description: "Verify if S3 and Lambda data events are being captured for forensic investigations.", hint: "Type 'aws cloudtrail get-event-selectors'.", intel: "Data events show who accessed what data. Essential for insider threat detection and data breach investigations." },
      { number: 4, title: "Enable Comprehensive Logging", description: "Configure complete CloudTrail coverage with all necessary event types and validation.", hint: "Type 'aws cloudtrail enable-comprehensive-logging'.", intel: "Enable CloudTrail Insights for anomaly detection on unusual API activity patterns." }
    ],
    resources: [
      { type: "cloudtrail", name: "partial-trail", config: { multiRegion: false, dataEvents: false, logValidation: false, encrypted: false }, isVulnerable: true, status: "incomplete" },
      { type: "s3", name: "cloudtrail-logs-bucket", config: { encryption: "none", versioning: false }, isVulnerable: true, status: "unprotected" }
    ],
    fixCommands: ["aws cloudtrail enable-comprehensive-logging"],
    successMessage: "Comprehensive logging enabled! CloudTrail now captures all management events, S3/Lambda data events, with log validation and encryption. You have full visibility for security investigations."
  },
  {
    title: "MFA Enforcement for Privileged Access",
    description: "Administrative users and root account lack MFA protection. Enforce multi-factor authentication for all privileged access paths.",
    briefing: "AUTHENTICATION GAP: 5 IAM users with admin privileges have no MFA enabled. One phished password away from full account compromise.",
    scenario: "Your cloud administrator received a convincing phishing email. They entered their password on a fake AWS login page. Without MFA, the attacker now has full admin access.",
    difficulty: "Beginner",
    category: "Cloud Security Engineer",
    estimatedTime: "5-10 minutes",
    initialState: { users: ["cloud-admin", "devops-lead", "security-admin"], root: ["root-account"] },
    steps: [
      { number: 1, title: "Identify MFA Gaps", description: "Scan for privileged users and roles without MFA protection.", hint: "Type 'scan' to analyze authentication configuration.", intel: "CIS AWS 1.5-1.6: Ensure MFA is enabled for root and all IAM users with console access. MITRE ATT&CK T1078: Valid accounts are a top attack vector." },
      { number: 2, title: "Review Privileged Users", description: "List all users with administrative permissions and their MFA status.", hint: "Type 'aws iam list-privileged-users-mfa'.", intel: "Focus on users with admin policies, IAM full access, or ability to modify security controls." },
      { number: 3, title: "Check Root Account", description: "Verify root account MFA and access key status.", hint: "Type 'aws iam get-root-account-summary'.", intel: "Root should have hardware MFA, no access keys, and be used only for tasks that require it." },
      { number: 4, title: "Enforce MFA Policy", description: "Implement organization-wide MFA requirements for all administrative access.", hint: "Type 'aws iam enforce-mfa-policy'.", intel: "Use SCP to deny actions without MFA. Implement MFA for API calls to sensitive resources." }
    ],
    resources: [
      { type: "iam_user", name: "cloud-admin", config: { mfaEnabled: false, adminAccess: true }, isVulnerable: true, status: "no-mfa" },
      { type: "iam_user", name: "devops-lead", config: { mfaEnabled: false, adminAccess: true }, isVulnerable: true, status: "no-mfa" },
      { type: "iam_user", name: "security-admin", config: { mfaEnabled: false, adminAccess: true }, isVulnerable: true, status: "no-mfa" },
      { type: "root_account", name: "root-account", config: { mfaEnabled: false, accessKeys: 1 }, isVulnerable: true, status: "critical-risk" }
    ],
    fixCommands: ["aws iam enforce-mfa-policy"],
    successMessage: "MFA enforcement complete! All privileged users now require MFA for console and API access. Root account secured with hardware MFA and access keys removed."
  },

  // INTERMEDIATE LABS (4) - Multi-phase with verification
  {
    title: "Multi-Tier Security Group Architecture",
    description: "Implement a defense-in-depth security group architecture for a production three-tier application with proper ingress/egress controls, admin access restrictions, and monitoring.",
    briefing: "NETWORK SECURITY OVERHAUL: Security groups are a mess - flat rules, 0.0.0.0/0 ingress, no egress filtering. An attacker who compromises any instance has unrestricted network access.",
    scenario: "Your web servers accept traffic from anywhere on all ports. Database security groups allow SSH from the internet. There's no egress filtering to detect data exfiltration. Time to implement proper network security controls.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { securityGroups: ["web-sg", "app-sg", "db-sg", "bastion-sg"], vpc: ["production-vpc"], instances: ["web-01", "web-02", "app-01", "db-01"] },
    steps: [
      { number: 1, title: "Audit Current Security Groups", description: "Scan all security groups to identify overly permissive rules and exposure.", hint: "Type 'scan' to analyze security group configurations.", intel: "CIS AWS 5.2-5.4: No security groups should allow unrestricted ingress to sensitive ports. MITRE ATT&CK T1190: Attackers exploit exposed services." },
      { number: 2, title: "Map Application Traffic", description: "Understand legitimate traffic patterns between tiers to design proper rules.", hint: "Type 'aws ec2 analyze-traffic-patterns'.", intel: "Document: ALB to web (443), web to app (8080), app to db (5432), all tiers to monitoring (443 outbound)." },
      { number: 3, title: "Design Security Group Hierarchy", description: "Plan the security group architecture with proper tier isolation.", hint: "Type 'aws ec2 plan-security-group-architecture'.", intel: "Use security group references instead of CIDR blocks where possible. SG-to-SG rules are more maintainable." },
      { number: 4, title: "Implement Web Tier SG", description: "Configure web tier security group to only accept traffic from ALB.", hint: "Type 'aws ec2 configure-web-tier-sg'.", intel: "Web tier should only accept 443 from ALB security group. No direct SSH access - use Session Manager." },
      { number: 5, title: "Implement App Tier SG", description: "Configure application tier to only accept traffic from web tier.", hint: "Type 'aws ec2 configure-app-tier-sg'.", intel: "App tier accepts traffic only from web SG on application port. Egress to DB SG on 5432 only." },
      { number: 6, title: "Implement Data Tier SG", description: "Lock down database tier with strict ingress from app tier only.", hint: "Type 'aws ec2 configure-data-tier-sg'.", intel: "Database SG allows 5432 only from app SG. No internet egress. Consider using PrivateLink for AWS service access." },
      { number: 7, title: "Configure Admin Access", description: "Set up secure administrative access through bastion or Session Manager.", hint: "Type 'aws ec2 configure-admin-access'.", intel: "Prefer SSM Session Manager over SSH bastion. If using bastion, restrict to corporate IP ranges only." },
      { number: 8, title: "Verify Segmentation", description: "Test that traffic flows correctly and unauthorized paths are blocked.", hint: "Type 'aws ec2 verify-network-segmentation'.", intel: "Run connectivity tests from each tier to verify rules work as expected. Document any exceptions." }
    ],
    resources: [
      { type: "security_group", name: "web-sg", config: { inbound: [{ port: "0-65535", source: "0.0.0.0/0" }], outbound: "unrestricted" }, isVulnerable: true, status: "permissive" },
      { type: "security_group", name: "app-sg", config: { inbound: [{ port: "0-65535", source: "0.0.0.0/0" }], outbound: "unrestricted" }, isVulnerable: true, status: "permissive" },
      { type: "security_group", name: "db-sg", config: { inbound: [{ port: 22, source: "0.0.0.0/0" }, { port: 5432, source: "0.0.0.0/0" }], outbound: "unrestricted" }, isVulnerable: true, status: "critical" },
      { type: "vpc", name: "production-vpc", config: { flowLogs: false }, isVulnerable: true, status: "no-visibility" }
    ],
    fixCommands: ["aws ec2 configure-web-tier-sg", "aws ec2 configure-app-tier-sg", "aws ec2 configure-data-tier-sg", "aws ec2 configure-admin-access"],
    successMessage: "Security group architecture implemented! Traffic now flows only through approved paths. Admin access restricted to Session Manager. Egress filtered to prevent data exfiltration."
  },
  {
    title: "Encryption and Key Management",
    description: "Implement comprehensive data protection with KMS key management, encryption at rest for all data stores, encryption in transit, and key rotation policies.",
    briefing: "DATA PROTECTION GAP: Customer data is stored unencrypted across S3, RDS, and EBS volumes. Key management is ad-hoc with no rotation. PCI and HIPAA compliance violations.",
    scenario: "An auditor just found PII stored in plaintext S3 buckets and unencrypted RDS snapshots. Your company processes credit cards and health data. This is a compliance nightmare.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "15-25 minutes",
    initialState: { kms: ["aws-managed-keys"], s3: ["customer-data", "app-logs"], rds: ["prod-database"], ebs: ["app-volumes"] },
    steps: [
      { number: 1, title: "Inventory Encryption Status", description: "Scan all data stores to identify unencrypted resources.", hint: "Type 'scan' to analyze encryption configuration.", intel: "PCI DSS 3.4: Render PAN unreadable. HIPAA: Encryption is an addressable safeguard. MITRE ATT&CK T1530: Data from cloud storage." },
      { number: 2, title: "Design KMS Key Strategy", description: "Plan customer-managed KMS keys for different data classifications.", hint: "Type 'aws kms design-key-strategy'.", intel: "Use separate CMKs for different data types: PII, financial, logs. Enable automatic rotation. Define key policies carefully." },
      { number: 3, title: "Create Data Classification Keys", description: "Create KMS keys for each data classification level.", hint: "Type 'aws kms create-classification-keys'.", intel: "Key aliases: alias/pii-data, alias/financial-data, alias/application-data. Grant encrypt/decrypt to appropriate roles only." },
      { number: 4, title: "Enable S3 Encryption", description: "Encrypt all S3 buckets with appropriate KMS keys.", hint: "Type 'aws s3 enable-kms-encryption customer-data'.", intel: "Use bucket default encryption with CMK. Enable bucket keys to reduce KMS API costs. Re-encrypt existing objects." },
      { number: 5, title: "Enable RDS Encryption", description: "Ensure database encryption at rest with KMS.", hint: "Type 'aws rds enable-encryption prod-database'.", intel: "RDS encryption must be enabled at creation. For existing unencrypted DBs, take snapshot, copy with encryption, restore." },
      { number: 6, title: "Enable EBS Encryption", description: "Encrypt all EBS volumes and enable default encryption.", hint: "Type 'aws ec2 enable-ebs-encryption'.", intel: "Enable account-level default encryption so all new volumes are encrypted. Migrate existing unencrypted volumes." },
      { number: 7, title: "Configure Key Rotation", description: "Enable automatic annual rotation for all customer-managed keys.", hint: "Type 'aws kms enable-key-rotation-all'.", intel: "CIS AWS 3.8: Enable KMS CMK rotation. AWS rotates the backing key material annually while keeping the same key ID." },
      { number: 8, title: "Verify Encryption Coverage", description: "Run compliance scan to verify all data stores are encrypted.", hint: "Type 'aws security verify-encryption-compliance'.", intel: "Generate compliance report for auditors. Document any exceptions with compensating controls." }
    ],
    resources: [
      { type: "s3", name: "customer-data", config: { encryption: "none", dataType: "PII" }, isVulnerable: true, status: "unencrypted" },
      { type: "s3", name: "app-logs", config: { encryption: "none", dataType: "logs" }, isVulnerable: true, status: "unencrypted" },
      { type: "rds", name: "prod-database", config: { encrypted: false, dataType: "financial" }, isVulnerable: true, status: "unencrypted" },
      { type: "ebs", name: "app-volumes", config: { encrypted: false, count: 12 }, isVulnerable: true, status: "unencrypted" }
    ],
    fixCommands: ["aws kms create-classification-keys", "aws s3 enable-kms-encryption customer-data", "aws rds enable-encryption prod-database", "aws kms enable-key-rotation-all"],
    successMessage: "Comprehensive encryption implemented! All data at rest encrypted with customer-managed keys. Key rotation enabled. Compliance requirements satisfied."
  },
  {
    title: "SIEM Integration and Alert Tuning",
    description: "Integrate AWS security logs with centralized SIEM, configure detection rules mapped to MITRE ATT&CK, and tune alerts to reduce false positives.",
    briefing: "SOC BLINDSPOT: Security logs exist but aren't being analyzed. No SIEM integration means no correlation, no alerting, no detection. Attackers could dwell for months undetected.",
    scenario: "Your security team doesn't know an attacker is in the environment. CloudTrail shows the reconnaissance. GuardDuty has findings. VPC Flow Logs show lateral movement. But nobody's watching.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "20-30 minutes",
    initialState: { logs: ["cloudtrail", "guardduty", "vpc-flowlogs"], siem: ["siem-config"], alerts: [] },
    steps: [
      { number: 1, title: "Inventory Log Sources", description: "Identify all security-relevant log sources that should feed the SIEM.", hint: "Type 'scan' to analyze available log sources.", intel: "Essential sources: CloudTrail, VPC Flow Logs, GuardDuty, Config, WAF logs, application logs, DNS logs." },
      { number: 2, title: "Configure Log Forwarding", description: "Set up centralized log aggregation for SIEM ingestion.", hint: "Type 'aws logs configure-siem-forwarding'.", intel: "Use CloudWatch Logs subscription filters or S3 event notifications. Consider Kinesis for real-time streaming." },
      { number: 3, title: "Map MITRE ATT&CK Coverage", description: "Identify which attack techniques your current logging can detect.", hint: "Type 'siem analyze-attack-coverage'.", intel: "Map log sources to MITRE ATT&CK: CloudTrail for T1078 (Valid Accounts), Flow Logs for T1046 (Network Scanning)." },
      { number: 4, title: "Create Detection Rules", description: "Build correlation rules for high-fidelity threat detection.", hint: "Type 'siem create-detection-rules'.", intel: "Start with high-confidence detections: impossible travel, console login without MFA, root account usage, resource deletion." },
      { number: 5, title: "Configure Alert Severity", description: "Assign severity levels based on attack impact and confidence.", hint: "Type 'siem configure-alert-severity'.", intel: "CRITICAL: confirmed compromise. HIGH: likely attack. MEDIUM: suspicious activity. LOW: anomaly for investigation." },
      { number: 6, title: "Set Up Alert Routing", description: "Configure notification channels for different severity levels.", hint: "Type 'siem configure-alert-routing'.", intel: "CRITICAL/HIGH: page on-call immediately. MEDIUM: ticket for next business day. LOW: weekly review." },
      { number: 7, title: "Create Investigation Dashboards", description: "Build dashboards for security analyst workflows.", hint: "Type 'siem create-investigation-dashboards'.", intel: "Dashboards: Alert Overview, User Activity Timeline, Network Connections, Resource Changes, Geographic Anomalies." },
      { number: 8, title: "Tune False Positives", description: "Review initial alerts and create tuning rules for known-good patterns.", hint: "Type 'siem tune-detection-rules'.", intel: "Document tuning decisions. Create allowlists for legitimate automation, known scanner IPs, expected admin activity patterns." }
    ],
    resources: [
      { type: "log_source", name: "cloudtrail", config: { enabled: true, siemIntegrated: false }, isVulnerable: false, status: "not-forwarded" },
      { type: "log_source", name: "guardduty", config: { enabled: true, siemIntegrated: false }, isVulnerable: false, status: "not-forwarded" },
      { type: "log_source", name: "vpc-flowlogs", config: { enabled: true, siemIntegrated: false }, isVulnerable: false, status: "not-forwarded" },
      { type: "siem", name: "siem-config", config: { detectionRules: 0, dashboards: 0 }, isVulnerable: true, status: "not-configured" }
    ],
    fixCommands: ["aws logs configure-siem-forwarding", "siem create-detection-rules", "siem configure-alert-routing", "siem create-investigation-dashboards"],
    successMessage: "SIEM integration complete! All security logs flowing to central SIEM with MITRE ATT&CK mapped detection rules. Alert routing configured for rapid response. Investigation dashboards ready."
  },
  {
    title: "Privilege Escalation Detection and Prevention",
    description: "Implement controls to detect and prevent IAM privilege escalation attacks, including policy analysis, permission boundaries, and runtime monitoring.",
    briefing: "PRIVILEGE ESCALATION RISK: IAM analysis reveals 12 escalation paths. A low-privilege attacker could become admin through iam:PassRole, policy attachment, or role assumption chains.",
    scenario: "A developer account has iam:CreatePolicy and iam:AttachUserPolicy. They could create an admin policy and attach it to themselves. Your current controls wouldn't detect or prevent this.",
    difficulty: "Intermediate",
    category: "Cloud Security Engineer",
    estimatedTime: "20-30 minutes",
    initialState: { iam: ["developer-role", "cicd-role", "lambda-role"], policies: ["escalation-paths"], monitoring: ["cloudtrail"] },
    steps: [
      { number: 1, title: "Identify Escalation Paths", description: "Analyze IAM to find all privilege escalation vectors.", hint: "Type 'scan' to analyze privilege escalation paths.", intel: "Common paths: iam:CreatePolicy+AttachPolicy, iam:PassRole+lambda:CreateFunction, iam:CreateAccessKey on admin users." },
      { number: 2, title: "Map Dangerous Permissions", description: "List all principals with IAM modification capabilities.", hint: "Type 'aws iam analyze-escalation-risk'.", intel: "Focus on: iam:*, lambda:CreateFunction+PassRole, ec2:RunInstances+PassRole, glue:CreateDevEndpoint+PassRole." },
      { number: 3, title: "Create Permission Boundaries", description: "Implement permission boundaries to cap maximum permissions.", hint: "Type 'aws iam create-permission-boundaries'.", intel: "Permission boundaries limit what delegated admins can grant. Even if they create admin policies, the boundary caps effective permissions." },
      { number: 4, title: "Apply Boundaries to Roles", description: "Attach permission boundaries to all human and service roles.", hint: "Type 'aws iam apply-permission-boundaries'.", intel: "Boundary should deny: iam:CreateUser, iam:AttachUserPolicy, iam:PutRolePolicy on privileged resources." },
      { number: 5, title: "Create Escalation Detection Rules", description: "Build CloudTrail-based detection for escalation attempts.", hint: "Type 'aws cloudtrail create-escalation-detections'.", intel: "Alert on: CreatePolicy with admin permissions, AttachRolePolicy to privileged roles, AssumeRole to admin roles from unexpected sources." },
      { number: 6, title: "Implement SCPs", description: "Add organization-level guardrails to prevent escalation.", hint: "Type 'aws organizations create-escalation-scp'.", intel: "SCP to deny: modification of admin roles, deletion of security resources, disabling security services." },
      { number: 7, title: "Test Detection", description: "Simulate escalation attempts to verify detection works.", hint: "Type 'aws iam simulate-escalation-attack'.", intel: "Test each escalation path identified. Verify alerts fire and prevention controls block the attempt." },
      { number: 8, title: "Document Controls", description: "Create runbook for responding to escalation alerts.", hint: "Type 'aws iam generate-escalation-runbook'.", intel: "Runbook: verify legitimacy, revoke access if malicious, preserve evidence, investigate scope of compromise." }
    ],
    resources: [
      { type: "iam_role", name: "developer-role", config: { escalationRisk: "high", permissions: ["iam:CreatePolicy", "iam:AttachUserPolicy"] }, isVulnerable: true, status: "risky" },
      { type: "iam_role", name: "cicd-role", config: { escalationRisk: "high", permissions: ["iam:PassRole", "lambda:CreateFunction"] }, isVulnerable: true, status: "risky" },
      { type: "iam_role", name: "lambda-role", config: { escalationRisk: "medium", permissions: ["sts:AssumeRole"] }, isVulnerable: true, status: "moderate" },
      { type: "detection", name: "escalation-paths", config: { pathsIdentified: 12, monitored: 0 }, isVulnerable: true, status: "unmonitored" }
    ],
    fixCommands: ["aws iam create-permission-boundaries", "aws iam apply-permission-boundaries", "aws cloudtrail create-escalation-detections", "aws organizations create-escalation-scp"],
    successMessage: "Privilege escalation controls implemented! Permission boundaries cap maximum permissions, SCPs block dangerous actions, detection rules alert on attempts. 12 escalation paths closed."
  },

  // ADVANCED LABS (4) - Complex multi-resource scenarios with forensics
  {
    title: "Production Security Architecture Assessment",
    description: "Conduct a comprehensive security assessment of a production cloud environment, identifying vulnerabilities across network, IAM, data protection, and logging. Generate professional findings report with remediation priorities.",
    briefing: "EXECUTIVE MANDATE: The board wants a full security assessment before the IPO. Evaluate the production environment against CIS benchmarks, identify risks, and create a prioritized remediation roadmap.",
    scenario: "Your company is preparing for an IPO. Auditors and investors will scrutinize your security posture. You need to find every vulnerability, assess business impact, and create a remediation plan that the CISO can present to the board.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "35-50 minutes",
    initialState: { 
      vpc: ["production-vpc", "management-vpc"], 
      iam: ["admin-users", "service-roles", "policies"],
      data: ["customer-db", "logs-bucket", "backup-bucket"],
      logging: ["cloudtrail", "config", "guardduty"],
      network: ["security-groups", "nacls", "waf"]
    },
    steps: [
      { number: 1, title: "Initialize Assessment", description: "Run comprehensive security scan across all resource types.", hint: "Type 'scan' to perform full environment assessment.", intel: "CIS AWS Benchmark provides 200+ controls. Focus on Level 1 (essential) and Level 2 (defense-in-depth) controls." },
      { number: 2, title: "Assess IAM Security", description: "Evaluate identity and access management configuration.", hint: "Type 'aws iam assess-security-posture'.", intel: "Check: root account usage, MFA coverage, password policy, access key age, overly permissive policies, unused credentials." },
      { number: 3, title: "Assess Network Security", description: "Analyze network architecture and segmentation.", hint: "Type 'aws ec2 assess-network-security'.", intel: "Check: security group rules, NACL configuration, VPC peering risks, public IP exposure, flow log coverage." },
      { number: 4, title: "Assess Data Protection", description: "Evaluate encryption and data classification controls.", hint: "Type 'aws assess-data-protection'.", intel: "Check: S3 bucket policies, RDS encryption, EBS encryption, KMS key management, backup security." },
      { number: 5, title: "Assess Logging Coverage", description: "Verify comprehensive security monitoring.", hint: "Type 'aws assess-logging-coverage'.", intel: "Check: CloudTrail multi-region, data events, Config recording, GuardDuty enabled, log integrity validation." },
      { number: 6, title: "Assess Compliance Status", description: "Check against regulatory frameworks.", hint: "Type 'aws securityhub assess-compliance'.", intel: "Check: CIS AWS Benchmark, PCI-DSS (if processing cards), HIPAA (if health data), SOC 2 controls." },
      { number: 7, title: "Calculate Risk Scores", description: "Assign risk scores based on likelihood and impact.", hint: "Type 'security calculate-risk-scores'.", intel: "Risk = Likelihood x Impact. Consider: exploitability, asset criticality, compensating controls, detection capability." },
      { number: 8, title: "Generate Threat Model", description: "Create threat model for the environment.", hint: "Type 'security generate-threat-model'.", intel: "Map attack paths using STRIDE or MITRE ATT&CK. Identify crown jewels and critical paths to them." },
      { number: 9, title: "Prioritize Findings", description: "Create remediation roadmap based on risk.", hint: "Type 'security prioritize-remediation'.", intel: "Quick wins first, then high-risk items. Consider: business disruption, resource requirements, dependencies." },
      { number: 10, title: "Remediate Critical Issues", description: "Fix the highest priority vulnerabilities.", hint: "Type 'security remediate-critical'.", intel: "Focus on: public exposure, admin access without MFA, unencrypted sensitive data, disabled logging." },
      { number: 11, title: "Generate Executive Report", description: "Create professional assessment report for leadership.", hint: "Type 'security generate-assessment-report'.", intel: "Include: executive summary, risk heatmap, finding details, remediation status, compliance gaps, recommendations." }
    ],
    resources: [
      { type: "environment", name: "production-vpc", config: { securityScore: 42, criticalFindings: 8, highFindings: 23 }, isVulnerable: true, status: "at-risk" },
      { type: "iam", name: "admin-users", config: { mfaCoverage: "60%", accessKeyAge: "180 days" }, isVulnerable: true, status: "gaps" },
      { type: "data", name: "customer-db", config: { encrypted: false, publiclyAccessible: true }, isVulnerable: true, status: "exposed" },
      { type: "logging", name: "cloudtrail", config: { multiRegion: false, dataEvents: false }, isVulnerable: true, status: "incomplete" }
    ],
    fixCommands: ["security remediate-critical", "security generate-assessment-report"],
    successMessage: "Security assessment complete! 42 findings identified, 8 critical issues remediated. Executive report generated with remediation roadmap. Security score improved from 42 to 78."
  },
  {
    title: "Cloud Attack Simulation and Response",
    description: "Simulate a realistic cloud attack scenario including initial access through exposed credentials, privilege escalation, lateral movement, and data exfiltration. Detect, contain, and investigate the attack.",
    briefing: "PURPLE TEAM EXERCISE: Simulate a real attack to test your detection and response capabilities. An attacker obtained leaked credentials and is attempting to exfiltrate customer data.",
    scenario: "AWS access keys were accidentally committed to a public GitHub repo. An attacker found them. They're now in your environment performing reconnaissance, escalating privileges, and moving toward your customer database. Can you detect and stop them?",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "40-55 minutes",
    initialState: { 
      attack: ["compromised-credentials", "reconnaissance", "privilege-escalation", "lateral-movement", "exfiltration"],
      detection: ["cloudtrail", "guardduty", "siem"],
      response: ["containment-lambda", "forensics-bucket"]
    },
    steps: [
      { number: 1, title: "Detect Initial Access", description: "Identify signs of compromised credential usage in logs.", hint: "Type 'scan' to analyze recent security events.", intel: "MITRE ATT&CK T1078.004: Cloud accounts. Look for: unusual source IPs, failed then successful auth, new user agents." },
      { number: 2, title: "Analyze Attack Timeline", description: "Build a timeline of attacker activity from logs.", hint: "Type 'aws cloudtrail analyze-attack-timeline'.", intel: "Focus on: GetCallerIdentity (whoami), DescribeInstances (recon), ListBuckets (targeting), CreateAccessKey (persistence)." },
      { number: 3, title: "Identify Privilege Escalation", description: "Detect attempts to gain higher privileges.", hint: "Type 'aws iam detect-privilege-escalation'.", intel: "Look for: AttachUserPolicy, CreatePolicyVersion, PassRole to admin role, AssumeRole to privileged role." },
      { number: 4, title: "Map Lateral Movement", description: "Trace attacker movement between resources.", hint: "Type 'aws ec2 analyze-lateral-movement'.", intel: "VPC Flow Logs show connections. Look for: unusual instance-to-instance traffic, SSM session abuse, EC2 Instance Connect." },
      { number: 5, title: "Identify Data Access", description: "Determine what data the attacker accessed.", hint: "Type 'aws s3 analyze-data-access'.", intel: "S3 data events show object-level access. Look for: bulk downloads, unusual bucket access patterns, cross-region access." },
      { number: 6, title: "Execute Containment", description: "Isolate compromised resources and revoke attacker access.", hint: "Type 'aws ir execute-containment'.", intel: "Containment: disable compromised credentials, isolate EC2 instances, block attacker IPs, snapshot for forensics." },
      { number: 7, title: "Preserve Evidence", description: "Collect forensic evidence before remediation.", hint: "Type 'aws ir collect-forensic-evidence'.", intel: "Collect: CloudTrail logs, VPC Flow Logs, EC2 memory dump, EBS snapshots, IAM credential reports." },
      { number: 8, title: "Eradicate Persistence", description: "Remove attacker persistence mechanisms.", hint: "Type 'aws ir eradicate-persistence'.", intel: "Check for: new IAM users, new access keys, modified Lambda functions, new EC2 instances, changed security groups." },
      { number: 9, title: "Assess Data Impact", description: "Determine scope of data exposure.", hint: "Type 'aws ir assess-data-impact'.", intel: "List all objects accessed. Classify data types. Determine if PII/PHI/PCI data was accessed. Prepare breach notification if required." },
      { number: 10, title: "Improve Defenses", description: "Implement controls to prevent recurrence.", hint: "Type 'aws ir implement-improvements'.", intel: "Add: credential scanning in CI/CD, MFA for CLI access, permission boundaries, enhanced monitoring for sensitive APIs." },
      { number: 11, title: "Generate Incident Report", description: "Document the incident for stakeholders and lessons learned.", hint: "Type 'aws ir generate-incident-report'.", intel: "Include: timeline, impact assessment, containment actions, root cause, lessons learned, improvement recommendations." }
    ],
    resources: [
      { type: "attack", name: "compromised-credentials", config: { source: "github-leak", accessLevel: "developer" }, isVulnerable: true, status: "active-attack" },
      { type: "attack_phase", name: "reconnaissance", config: { apisUsed: ["DescribeInstances", "ListBuckets", "GetCallerIdentity"] }, isVulnerable: false, status: "completed" },
      { type: "attack_phase", name: "privilege-escalation", config: { technique: "PassRole to admin Lambda" }, isVulnerable: false, status: "in-progress" },
      { type: "detection", name: "guardduty", config: { findings: 5, acknowledged: 0 }, isVulnerable: false, status: "alerting" }
    ],
    fixCommands: ["aws ir execute-containment", "aws ir eradicate-persistence", "aws ir implement-improvements", "aws ir generate-incident-report"],
    successMessage: "Attack contained and eradicated! Attacker access revoked, persistence removed, evidence preserved. Incident report generated. Defense improvements implemented to prevent recurrence."
  },
  {
    title: "Automated Incident Response Pipeline",
    description: "Build a cloud-native automated incident response capability with Lambda-based containment, Step Functions workflows, evidence preservation, and integration with ticketing systems.",
    briefing: "IR AUTOMATION: Manual incident response takes hours. Build automated containment that triggers in seconds when GuardDuty detects a threat.",
    scenario: "It's 3 AM. GuardDuty detects an EC2 instance communicating with a known C2 server. Your on-call engineer is asleep. By the time anyone responds manually, the attacker has exfiltrated data and moved laterally. Time to automate.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "40-55 minutes",
    initialState: { 
      guardduty: ["findings"],
      lambda: ["containment-functions"],
      stepfunctions: ["ir-workflow"],
      eventbridge: ["ir-rules"],
      s3: ["forensics-bucket"]
    },
    steps: [
      { number: 1, title: "Design IR Workflow", description: "Map out the automated incident response workflow.", hint: "Type 'scan' to analyze current IR capability.", intel: "Workflow: Detect -> Triage -> Contain -> Notify -> Investigate -> Remediate -> Report. Different paths for different finding types." },
      { number: 2, title: "Create Containment Functions", description: "Build Lambda functions for automated containment actions.", hint: "Type 'aws lambda create-containment-functions'.", intel: "Functions needed: isolate-ec2 (quarantine SG), revoke-credentials, snapshot-for-forensics, block-ip-address." },
      { number: 3, title: "Create Investigation Functions", description: "Build functions to gather forensic context.", hint: "Type 'aws lambda create-investigation-functions'.", intel: "Functions: get-instance-metadata, get-cloudtrail-activity, get-vpc-flowlogs, get-user-activity, enrich-with-threatintel." },
      { number: 4, title: "Build Step Functions Workflow", description: "Create state machine for IR orchestration.", hint: "Type 'aws stepfunctions create-ir-workflow'.", intel: "Use parallel states for containment + notification. Use choice states for severity-based routing. Include human approval for destructive actions." },
      { number: 5, title: "Configure EventBridge Rules", description: "Set up event-driven triggers from GuardDuty.", hint: "Type 'aws events create-ir-triggers'.", intel: "Route by finding type: EC2 findings -> instance containment, IAM findings -> credential revocation, S3 findings -> bucket lockdown." },
      { number: 6, title: "Create Forensics Pipeline", description: "Set up evidence collection and preservation.", hint: "Type 'aws ir create-forensics-pipeline'.", intel: "S3 bucket with object lock. Automatic collection of logs, snapshots, metadata. Chain of custody documentation." },
      { number: 7, title: "Configure Notifications", description: "Set up multi-channel alerting for incidents.", hint: "Type 'aws ir configure-notifications'.", intel: "SNS for email/SMS, Slack webhook for ChatOps, PagerDuty for on-call escalation, ServiceNow for ticket creation." },
      { number: 8, title: "Create Approval Workflows", description: "Add human approval gates for destructive actions.", hint: "Type 'aws stepfunctions add-approval-gates'.", intel: "Require approval for: instance termination, user deletion, production changes. Timeout and escalate if no response." },
      { number: 9, title: "Test with Simulated Incidents", description: "Generate test findings to validate the pipeline.", hint: "Type 'aws guardduty generate-sample-findings'.", intel: "Test each finding type. Verify containment works. Check notification delivery. Time the response." },
      { number: 10, title: "Measure and Tune", description: "Establish metrics and tune response times.", hint: "Type 'aws ir measure-response-metrics'.", intel: "Track: Mean Time to Detect, Mean Time to Contain, False positive rate. Target: contain within 5 minutes of detection." },
      { number: 11, title: "Document Runbooks", description: "Create runbooks for manual escalation paths.", hint: "Type 'aws ir generate-runbooks'.", intel: "Runbooks for: automated containment failures, unknown finding types, false positive handling, post-incident review." }
    ],
    resources: [
      { type: "ir_automation", name: "current-state", config: { automatedContainment: false, mttc: "4 hours" }, isVulnerable: true, status: "manual" },
      { type: "guardduty", name: "findings", config: { findingsPerDay: 25, autoResponse: 0 }, isVulnerable: false, status: "alerting-only" },
      { type: "lambda", name: "containment-functions", config: { count: 0 }, isVulnerable: true, status: "not-implemented" },
      { type: "stepfunctions", name: "ir-workflow", config: { exists: false }, isVulnerable: true, status: "not-implemented" }
    ],
    fixCommands: ["aws lambda create-containment-functions", "aws stepfunctions create-ir-workflow", "aws events create-ir-triggers", "aws ir generate-runbooks"],
    successMessage: "Automated IR pipeline deployed! GuardDuty findings now trigger automatic containment within seconds. Mean Time to Contain reduced from 4 hours to 2 minutes. 24/7 automated response capability."
  },
  {
    title: "Enterprise Cloud Security Architecture",
    description: "Design and implement a comprehensive enterprise cloud security architecture with multi-account governance, centralized security services, compliance automation, and security operations center integration.",
    briefing: "ENTERPRISE SECURITY: The company is scaling from 5 to 50 AWS accounts. Design a security architecture that scales with the business while maintaining consistent security controls and visibility.",
    scenario: "Each business unit wants their own AWS accounts. Without proper governance, you'll have 50 different security configurations, no central visibility, and compliance chaos. Build an architecture that enables business agility while ensuring security.",
    difficulty: "Advanced",
    category: "Cloud Security Engineer",
    estimatedTime: "45-60 minutes",
    initialState: { 
      organization: ["org-root", "5-accounts"],
      security: ["no-central-services"],
      compliance: ["manual-audits"],
      soc: ["limited-visibility"]
    },
    steps: [
      { number: 1, title: "Design Organization Structure", description: "Plan the AWS Organizations hierarchy for security and governance.", hint: "Type 'scan' to analyze current organization.", intel: "Recommended OUs: Security, Infrastructure, Workloads/Prod, Workloads/Dev, Sandbox. Each OU gets tailored SCPs." },
      { number: 2, title: "Create Security Account", description: "Set up dedicated security tooling account.", hint: "Type 'aws organizations create-security-account'.", intel: "Security account hosts: GuardDuty admin, Security Hub aggregator, CloudTrail org trail, Config aggregator, forensics tools." },
      { number: 3, title: "Create Log Archive Account", description: "Set up immutable log storage account.", hint: "Type 'aws organizations create-log-archive-account'.", intel: "Log archive: no human access, immutable storage, 7-year retention for compliance. All accounts stream logs here." },
      { number: 4, title: "Implement SCPs", description: "Create Service Control Policies for guardrails.", hint: "Type 'aws organizations implement-scps'.", intel: "SCPs: deny region restriction bypass, deny security service disablement, deny root access, deny leaving organization." },
      { number: 5, title: "Deploy GuardDuty Organization", description: "Enable GuardDuty across all accounts.", hint: "Type 'aws guardduty enable-organization'.", intel: "Security account as delegated admin. Auto-enable for new accounts. Configure S3 and EKS protection." },
      { number: 6, title: "Deploy Security Hub Organization", description: "Enable Security Hub with compliance standards.", hint: "Type 'aws securityhub enable-organization'.", intel: "Enable CIS AWS Benchmark and AWS Foundational Security. Aggregate findings to security account." },
      { number: 7, title: "Configure Org CloudTrail", description: "Set up organization-wide CloudTrail.", hint: "Type 'aws cloudtrail enable-organization-trail'.", intel: "Single trail for all accounts. Data events for S3 and Lambda. Logs to log archive account with KMS encryption." },
      { number: 8, title: "Deploy Config Organization", description: "Enable AWS Config across all accounts.", hint: "Type 'aws config enable-organization'.", intel: "Aggregate to security account. Deploy conformance packs for compliance. Auto-remediation for critical rules." },
      { number: 9, title: "Implement Network Security", description: "Deploy centralized network security controls.", hint: "Type 'aws network implement-central-security'.", intel: "Options: Network Firewall in inspection VPC, Transit Gateway for segmentation, centralized egress with NAT Gateway." },
      { number: 10, title: "Configure SOC Integration", description: "Connect all security services to SOC.", hint: "Type 'aws security configure-soc-integration'.", intel: "Stream findings to SIEM. Configure alert routing. Create investigation playbooks. Enable cross-account investigation." },
      { number: 11, title: "Generate Architecture Documentation", description: "Create comprehensive architecture documentation.", hint: "Type 'aws security generate-architecture-docs'.", intel: "Include: architecture diagrams, data flow diagrams, SCP documentation, runbooks, compliance mapping." }
    ],
    resources: [
      { type: "organization", name: "org-root", config: { accounts: 5, securityAccount: false, scps: 0 }, isVulnerable: true, status: "ungoverned" },
      { type: "security_services", name: "no-central-services", config: { guardduty: "per-account", securityhub: "not-enabled", config: "per-account" }, isVulnerable: true, status: "fragmented" },
      { type: "compliance", name: "manual-audits", config: { automated: false, frequency: "quarterly" }, isVulnerable: true, status: "manual" },
      { type: "soc", name: "limited-visibility", config: { accountsCovered: 2, automatedResponse: false }, isVulnerable: true, status: "partial" }
    ],
    fixCommands: ["aws organizations create-security-account", "aws organizations implement-scps", "aws guardduty enable-organization", "aws securityhub enable-organization", "aws security generate-architecture-docs"],
    successMessage: "Enterprise security architecture deployed! Centralized security services, organization-wide visibility, automated compliance, and SOC integration. Ready to scale from 5 to 50+ accounts securely."
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
