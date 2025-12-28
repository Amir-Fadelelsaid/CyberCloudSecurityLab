// Lab Definitions for CyberLab - 30 Labs (10 per category)

export interface LabDefinition {
  title: string;
  description: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  category: "Storage Security" | "Network Security" | "SOC Operations";
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
  fixCommand: string;
}

// ============= STORAGE SECURITY LABS (10) =============
export const storageSecurityLabs: LabDefinition[] = [
  {
    title: "Public S3 Bucket Exposure",
    description: "A sensitive corporate S3 bucket has been accidentally left open to the public. Your mission is to identify the bucket and apply a restrictive bucket policy to secure it.",
    difficulty: "Beginner",
    category: "Storage Security",
    initialState: { buckets: ["corp-payroll-data", "public-assets"] },
    steps: [
      { number: 1, title: "Scan for Vulnerabilities", description: "First, let's identify what's vulnerable in our infrastructure.", hint: "Type 'scan' in the terminal to see all vulnerable resources." },
      { number: 2, title: "List S3 Buckets", description: "Now let's examine our S3 buckets to understand what we're working with.", hint: "Type 'aws s3 ls' to list all available S3 buckets and their security status." },
      { number: 3, title: "Identify the Vulnerable Bucket", description: "Look at the bucket list. One of them is marked as PUBLIC.", hint: "The vulnerable bucket name is 'corp-payroll-data'. Notice it shows [PUBLIC] status." },
      { number: 4, title: "Fix the Vulnerable Bucket", description: "Apply a secure bucket policy to restrict public access.", hint: "Type 'aws s3 fix corp-payroll-data' to apply the security fix." },
      { number: 5, title: "Verify the Fix", description: "Run a final security scan to confirm remediation.", hint: "Type 'scan' again to verify the bucket is now secure." }
    ],
    resources: [
      { type: "s3", name: "corp-payroll-data", config: { access: "public-read" }, isVulnerable: true, status: "active" },
      { type: "s3", name: "public-website-assets", config: { access: "public-read" }, isVulnerable: false, status: "active" }
    ],
    fixCommand: "aws s3 fix corp-payroll-data"
  },
  {
    title: "Unencrypted S3 Bucket",
    description: "A bucket containing customer data lacks server-side encryption. Enable encryption to protect data at rest.",
    difficulty: "Beginner",
    category: "Storage Security",
    initialState: { buckets: ["customer-data-raw"] },
    steps: [
      { number: 1, title: "Scan Infrastructure", description: "Identify security issues in your environment.", hint: "Type 'scan' to find vulnerabilities." },
      { number: 2, title: "Check Encryption Status", description: "List buckets and their encryption status.", hint: "Type 'aws s3 ls-encryption' to see encryption details." },
      { number: 3, title: "Enable Encryption", description: "Apply AES-256 server-side encryption to the bucket.", hint: "Type 'aws s3 enable-encryption customer-data-raw' to enable SSE." },
      { number: 4, title: "Verify Encryption", description: "Confirm encryption is now enabled.", hint: "Type 'scan' to verify the fix." }
    ],
    resources: [
      { type: "s3", name: "customer-data-raw", config: { encryption: "none" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 enable-encryption customer-data-raw"
  },
  {
    title: "S3 Bucket Logging Disabled",
    description: "Access logging is disabled on a sensitive bucket, making it impossible to audit who accessed the data.",
    difficulty: "Beginner",
    category: "Storage Security",
    initialState: { buckets: ["financial-reports"] },
    steps: [
      { number: 1, title: "Scan for Issues", description: "Find buckets missing audit logging.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Logging Status", description: "Review which buckets have logging enabled.", hint: "Type 'aws s3 ls-logging' to see logging configuration." },
      { number: 3, title: "Enable Access Logging", description: "Configure access logging for the bucket.", hint: "Type 'aws s3 enable-logging financial-reports' to enable logging." },
      { number: 4, title: "Verify Logging", description: "Confirm logging is now active.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "financial-reports", config: { logging: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 enable-logging financial-reports"
  },
  {
    title: "S3 Versioning Not Enabled",
    description: "A critical backup bucket doesn't have versioning enabled, risking permanent data loss from accidental deletions.",
    difficulty: "Intermediate",
    category: "Storage Security",
    initialState: { buckets: ["disaster-recovery-backup"] },
    steps: [
      { number: 1, title: "Identify Risk", description: "Scan for buckets without versioning.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Check Versioning Status", description: "List versioning configuration.", hint: "Type 'aws s3 ls-versioning' to see status." },
      { number: 3, title: "Enable Versioning", description: "Turn on versioning to protect against data loss.", hint: "Type 'aws s3 enable-versioning disaster-recovery-backup'." },
      { number: 4, title: "Verify Configuration", description: "Confirm versioning is enabled.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "disaster-recovery-backup", config: { versioning: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 enable-versioning disaster-recovery-backup"
  },
  {
    title: "Overly Permissive Bucket Policy",
    description: "A bucket policy grants s3:* permissions to all principals. Restrict to least privilege access.",
    difficulty: "Intermediate",
    category: "Storage Security",
    initialState: { buckets: ["shared-data-lake"] },
    steps: [
      { number: 1, title: "Scan for Misconfigurations", description: "Find overly permissive policies.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Bucket Policy", description: "Examine the current policy.", hint: "Type 'aws s3 get-policy shared-data-lake' to see the policy." },
      { number: 3, title: "Apply Least Privilege", description: "Restrict the policy to specific actions and principals.", hint: "Type 'aws s3 restrict-policy shared-data-lake'." },
      { number: 4, title: "Verify Policy", description: "Confirm the policy is now restrictive.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "shared-data-lake", config: { policy: "s3:*", principal: "*" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 restrict-policy shared-data-lake"
  },
  {
    title: "Cross-Account Bucket Access Misconfiguration",
    description: "A bucket allows access from an unknown external AWS account. Investigate and restrict cross-account access.",
    difficulty: "Intermediate",
    category: "Storage Security",
    initialState: { buckets: ["partner-data-exchange"] },
    steps: [
      { number: 1, title: "Detect External Access", description: "Scan for buckets with cross-account permissions.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Analyze Access", description: "Check which accounts have access.", hint: "Type 'aws s3 check-access partner-data-exchange'." },
      { number: 3, title: "Remove Unauthorized Access", description: "Revoke access from unknown accounts.", hint: "Type 'aws s3 revoke-external partner-data-exchange'." },
      { number: 4, title: "Verify Remediation", description: "Confirm only authorized accounts remain.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "partner-data-exchange", config: { crossAccount: ["123456789012", "999888777666"] }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 revoke-external partner-data-exchange"
  },
  {
    title: "S3 Object Lock Not Configured",
    description: "Compliance data requires WORM (Write Once Read Many) protection but Object Lock is not configured.",
    difficulty: "Intermediate",
    category: "Storage Security",
    initialState: { buckets: ["compliance-audit-logs"] },
    steps: [
      { number: 1, title: "Identify Compliance Gap", description: "Find buckets missing Object Lock.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Object Lock Status", description: "Review current configuration.", hint: "Type 'aws s3 check-object-lock compliance-audit-logs'." },
      { number: 3, title: "Enable Object Lock", description: "Configure WORM protection.", hint: "Type 'aws s3 enable-object-lock compliance-audit-logs'." },
      { number: 4, title: "Verify Protection", description: "Confirm Object Lock is active.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "compliance-audit-logs", config: { objectLock: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 enable-object-lock compliance-audit-logs"
  },
  {
    title: "S3 Bucket with Block Public Access Disabled",
    description: "The account-level S3 Block Public Access settings are disabled, allowing buckets to be made public.",
    difficulty: "Advanced",
    category: "Storage Security",
    initialState: { buckets: ["prod-application-data"] },
    steps: [
      { number: 1, title: "Detect Public Access Risk", description: "Scan for public access configuration issues.", hint: "Type 'scan' to find vulnerabilities." },
      { number: 2, title: "Check Block Public Access", description: "Review current settings.", hint: "Type 'aws s3 check-block-public prod-application-data'." },
      { number: 3, title: "Enable Block Public Access", description: "Turn on all four Block Public Access settings.", hint: "Type 'aws s3 block-public-access prod-application-data'." },
      { number: 4, title: "Verify Settings", description: "Confirm all settings are enabled.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "prod-application-data", config: { blockPublicAccess: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 block-public-access prod-application-data"
  },
  {
    title: "S3 Replication to Insecure Region",
    description: "Data is being replicated to a region that doesn't meet compliance requirements. Reconfigure replication.",
    difficulty: "Advanced",
    category: "Storage Security",
    initialState: { buckets: ["eu-customer-data"] },
    steps: [
      { number: 1, title: "Identify Compliance Issue", description: "Find buckets with non-compliant replication.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Replication Config", description: "Review where data is being replicated.", hint: "Type 'aws s3 check-replication eu-customer-data'." },
      { number: 3, title: "Fix Replication", description: "Update replication to compliant region.", hint: "Type 'aws s3 fix-replication eu-customer-data'." },
      { number: 4, title: "Verify Compliance", description: "Confirm replication is now compliant.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "eu-customer-data", config: { replication: "us-east-1", required: "eu-west-1" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 fix-replication eu-customer-data"
  },
  {
    title: "S3 Pre-signed URL Expiration Too Long",
    description: "Pre-signed URLs are configured to expire after 7 days, creating a security risk. Reduce expiration time.",
    difficulty: "Advanced",
    category: "Storage Security",
    initialState: { buckets: ["temp-file-sharing"] },
    steps: [
      { number: 1, title: "Detect Long Expiration", description: "Find buckets with risky pre-signed URL settings.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review URL Policy", description: "Check current pre-signed URL configuration.", hint: "Type 'aws s3 check-presigned temp-file-sharing'." },
      { number: 3, title: "Reduce Expiration", description: "Set maximum expiration to 1 hour.", hint: "Type 'aws s3 fix-presigned temp-file-sharing'." },
      { number: 4, title: "Verify Change", description: "Confirm new expiration policy.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "s3", name: "temp-file-sharing", config: { presignedExpiry: "7d" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws s3 fix-presigned temp-file-sharing"
  }
];

// ============= NETWORK SECURITY LABS (10) =============
export const networkSecurityLabs: LabDefinition[] = [
  {
    title: "Insecure Security Group - SSH Exposed",
    description: "An EC2 instance hosting an internal database allows SSH access from 0.0.0.0/0. Restrict the security group rules.",
    difficulty: "Beginner",
    category: "Network Security",
    initialState: { instances: ["db-prod-01"] },
    steps: [
      { number: 1, title: "Understand the Threat", description: "An EC2 instance is exposed to SSH attacks from the internet.", hint: "SSH (port 22) should only be accessible from trusted IPs." },
      { number: 2, title: "Run Security Scan", description: "Scan to identify misconfigured security groups.", hint: "Type 'scan' to see vulnerabilities." },
      { number: 3, title: "Analyze Vulnerability", description: "The security group has overly permissive SSH rules.", hint: "0.0.0.0/0 means anyone can attempt to connect." },
      { number: 4, title: "Restrict SSH Access", description: "Update the security group to allow SSH only from internal networks.", hint: "Type 'aws ec2 restrict-ssh db-prod-01'." },
      { number: 5, title: "Verify Fix", description: "Confirm the SSH rule is now restricted.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "security_group", name: "sg-db-prod-01", config: { ingress: [{ port: 22, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 restrict-ssh db-prod-01"
  },
  {
    title: "Open RDP Port to Internet",
    description: "A Windows server has RDP (port 3389) exposed to 0.0.0.0/0, a common ransomware attack vector.",
    difficulty: "Beginner",
    category: "Network Security",
    initialState: { instances: ["win-admin-01"] },
    steps: [
      { number: 1, title: "Identify Risk", description: "RDP exposed to internet is a major attack vector.", hint: "Type 'scan' to find exposed ports." },
      { number: 2, title: "List Security Groups", description: "Review security group configurations.", hint: "Type 'aws ec2 ls-sg' to list security groups." },
      { number: 3, title: "Restrict RDP Access", description: "Limit RDP to VPN or bastion host only.", hint: "Type 'aws ec2 restrict-rdp win-admin-01'." },
      { number: 4, title: "Verify Remediation", description: "Confirm RDP is no longer publicly accessible.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "security_group", name: "sg-win-admin", config: { ingress: [{ port: 3389, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 restrict-rdp win-admin-01"
  },
  {
    title: "Database Port Exposed",
    description: "MySQL port 3306 is accessible from the internet instead of being restricted to application servers.",
    difficulty: "Beginner",
    category: "Network Security",
    initialState: { instances: ["mysql-prod-01"] },
    steps: [
      { number: 1, title: "Scan for Exposed Ports", description: "Find database ports exposed to internet.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Database SG", description: "Review MySQL security group.", hint: "Type 'aws ec2 describe-sg mysql-prod-01'." },
      { number: 3, title: "Restrict Database Access", description: "Allow MySQL only from app server security group.", hint: "Type 'aws ec2 restrict-db mysql-prod-01'." },
      { number: 4, title: "Verify Change", description: "Confirm database is now properly secured.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "security_group", name: "sg-mysql-prod", config: { ingress: [{ port: 3306, source: "0.0.0.0/0" }] }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 restrict-db mysql-prod-01"
  },
  {
    title: "NACL Allows All Inbound Traffic",
    description: "A Network ACL is configured to allow all inbound traffic (0.0.0.0/0 on all ports).",
    difficulty: "Intermediate",
    category: "Network Security",
    initialState: { nacls: ["acl-public-subnet"] },
    steps: [
      { number: 1, title: "Identify NACL Issue", description: "Scan for overly permissive NACLs.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Review NACL Rules", description: "Check current NACL configuration.", hint: "Type 'aws ec2 describe-nacl acl-public-subnet'." },
      { number: 3, title: "Apply Restrictive Rules", description: "Configure deny-by-default with specific allows.", hint: "Type 'aws ec2 fix-nacl acl-public-subnet'." },
      { number: 4, title: "Verify NACL", description: "Confirm NACL is now restrictive.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "nacl", name: "acl-public-subnet", config: { inbound: "allow-all" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 fix-nacl acl-public-subnet"
  },
  {
    title: "VPC Flow Logs Disabled",
    description: "VPC Flow Logs are not enabled, preventing network traffic analysis for security investigations.",
    difficulty: "Intermediate",
    category: "Network Security",
    initialState: { vpcs: ["vpc-production"] },
    steps: [
      { number: 1, title: "Detect Missing Logs", description: "Scan for VPCs without flow logs.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check VPC Config", description: "Review VPC flow log settings.", hint: "Type 'aws ec2 describe-vpc vpc-production'." },
      { number: 3, title: "Enable Flow Logs", description: "Turn on VPC Flow Logs.", hint: "Type 'aws ec2 enable-flow-logs vpc-production'." },
      { number: 4, title: "Verify Logging", description: "Confirm flow logs are now active.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "vpc", name: "vpc-production", config: { flowLogs: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 enable-flow-logs vpc-production"
  },
  {
    title: "Unrestricted Egress Rules",
    description: "Security groups allow all outbound traffic, enabling data exfiltration and C2 communication.",
    difficulty: "Intermediate",
    category: "Network Security",
    initialState: { instances: ["app-server-01"] },
    steps: [
      { number: 1, title: "Identify Egress Risk", description: "Scan for unrestricted egress.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Check Egress Rules", description: "Review outbound security group rules.", hint: "Type 'aws ec2 describe-egress app-server-01'." },
      { number: 3, title: "Restrict Egress", description: "Allow only necessary outbound traffic.", hint: "Type 'aws ec2 restrict-egress app-server-01'." },
      { number: 4, title: "Verify Egress", description: "Confirm egress is now restricted.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "security_group", name: "sg-app-server", config: { egress: "0.0.0.0/0:all" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 restrict-egress app-server-01"
  },
  {
    title: "Elastic IP Not Associated",
    description: "An Elastic IP is allocated but not associated with any instance, wasting resources and creating confusion.",
    difficulty: "Intermediate",
    category: "Network Security",
    initialState: { eips: ["eip-unattached"] },
    steps: [
      { number: 1, title: "Find Unused EIPs", description: "Scan for unattached Elastic IPs.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "List Elastic IPs", description: "Review all allocated EIPs.", hint: "Type 'aws ec2 describe-eips'." },
      { number: 3, title: "Release Unused EIP", description: "Release the unattached Elastic IP.", hint: "Type 'aws ec2 release-eip eip-unattached'." },
      { number: 4, title: "Verify Cleanup", description: "Confirm EIP is released.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "eip", name: "eip-unattached", config: { associated: false }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 release-eip eip-unattached"
  },
  {
    title: "Load Balancer Without WAF",
    description: "An internet-facing ALB lacks AWS WAF protection, exposing it to web attacks.",
    difficulty: "Advanced",
    category: "Network Security",
    initialState: { loadBalancers: ["alb-web-frontend"] },
    steps: [
      { number: 1, title: "Detect Unprotected ALB", description: "Scan for ALBs without WAF.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check WAF Association", description: "Review ALB WAF configuration.", hint: "Type 'aws waf check-association alb-web-frontend'." },
      { number: 3, title: "Associate WAF", description: "Attach AWS WAF to the ALB.", hint: "Type 'aws waf associate alb-web-frontend'." },
      { number: 4, title: "Verify Protection", description: "Confirm WAF is now protecting the ALB.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "alb", name: "alb-web-frontend", config: { waf: false, internetFacing: true }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws waf associate alb-web-frontend"
  },
  {
    title: "VPC Peering Without Route Restrictions",
    description: "A VPC peering connection allows routing to all subnets instead of specific resources.",
    difficulty: "Advanced",
    category: "Network Security",
    initialState: { peering: ["pcx-partner-connection"] },
    steps: [
      { number: 1, title: "Identify Peering Risk", description: "Scan for overly permissive VPC peering.", hint: "Type 'scan' to find issues." },
      { number: 2, title: "Review Peering Routes", description: "Check peering connection routes.", hint: "Type 'aws ec2 describe-peering pcx-partner-connection'." },
      { number: 3, title: "Restrict Peering Routes", description: "Limit routes to specific subnets.", hint: "Type 'aws ec2 restrict-peering pcx-partner-connection'." },
      { number: 4, title: "Verify Routes", description: "Confirm routes are now restricted.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "vpc_peering", name: "pcx-partner-connection", config: { routes: "0.0.0.0/0" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 restrict-peering pcx-partner-connection"
  },
  {
    title: "Transit Gateway Route Leak",
    description: "A Transit Gateway is propagating routes to all attached VPCs, creating unintended connectivity.",
    difficulty: "Advanced",
    category: "Network Security",
    initialState: { tgw: ["tgw-central-hub"] },
    steps: [
      { number: 1, title: "Detect Route Leak", description: "Scan for Transit Gateway issues.", hint: "Type 'scan' to identify problems." },
      { number: 2, title: "Check TGW Routes", description: "Review Transit Gateway route tables.", hint: "Type 'aws ec2 describe-tgw tgw-central-hub'." },
      { number: 3, title: "Fix Route Propagation", description: "Disable automatic route propagation.", hint: "Type 'aws ec2 fix-tgw-routes tgw-central-hub'." },
      { number: 4, title: "Verify Isolation", description: "Confirm VPCs are properly isolated.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "transit_gateway", name: "tgw-central-hub", config: { propagation: "all-vpcs" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ec2 fix-tgw-routes tgw-central-hub"
  }
];

// ============= SOC OPERATIONS LABS (10) =============
export const socOperationsLabs: LabDefinition[] = [
  {
    title: "CloudTrail Log Analysis - Credential Compromise",
    description: "Your SOC team detected unusual API activity. An attacker may have compromised IAM credentials. Analyze CloudTrail logs to identify the threat actor's actions.",
    difficulty: "Beginner",
    category: "SOC Operations",
    initialState: { logs: ["cloudtrail-events"], compromisedUser: "dev-jenkins-sa" },
    steps: [
      { number: 1, title: "Understand the Alert", description: "GuardDuty flagged suspicious API activity.", hint: "MITRE ATT&CK T1078: Valid Accounts." },
      { number: 2, title: "Query CloudTrail Logs", description: "Examine recent API calls.", hint: "Type 'aws cloudtrail lookup-events'." },
      { number: 3, title: "Identify Suspicious Activity", description: "Look for unusual patterns.", hint: "Focus on CreateAccessKey, AssumeRole calls." },
      { number: 4, title: "Determine Compromised Credentials", description: "Identify the compromised user.", hint: "Type 'aws iam list-compromised'." },
      { number: 5, title: "Revoke Credentials", description: "Revoke the compromised access keys.", hint: "Type 'aws iam revoke-keys dev-jenkins-sa'." }
    ],
    resources: [
      { type: "cloudtrail", name: "suspicious-api-activity", config: { events: [
        { eventName: "CreateAccessKey", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:23:15Z" },
        { eventName: "AssumeRole", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", targetRole: "AdminRole", timestamp: "2025-01-15T08:24:02Z" }
      ]}, isVulnerable: true, status: "active" },
      { type: "iam_user", name: "dev-jenkins-sa", config: { accessKeyAge: "180 days", permissions: ["s3:*", "iam:CreateAccessKey"] }, isVulnerable: true, status: "compromised" }
    ],
    fixCommand: "aws iam revoke-keys dev-jenkins-sa"
  },
  {
    title: "CloudTrail Logging Disabled",
    description: "An attacker has disabled CloudTrail logging to hide their activities. Re-enable logging and investigate.",
    difficulty: "Beginner",
    category: "SOC Operations",
    initialState: { trails: ["main-trail"] },
    steps: [
      { number: 1, title: "Detect Disabled Logging", description: "Scan for CloudTrail issues.", hint: "Type 'scan' to identify problems." },
      { number: 2, title: "Check Trail Status", description: "Review CloudTrail configuration.", hint: "Type 'aws cloudtrail status main-trail'." },
      { number: 3, title: "Enable Logging", description: "Turn CloudTrail logging back on.", hint: "Type 'aws cloudtrail enable main-trail'." },
      { number: 4, title: "Verify Logging", description: "Confirm logging is active.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "cloudtrail", name: "main-trail", config: { logging: false }, isVulnerable: true, status: "disabled" }
    ],
    fixCommand: "aws cloudtrail enable main-trail"
  },
  {
    title: "GuardDuty Finding - Crypto Mining",
    description: "GuardDuty detected EC2 instances communicating with known cryptocurrency mining pools.",
    difficulty: "Beginner",
    category: "SOC Operations",
    initialState: { instances: ["web-server-03"] },
    steps: [
      { number: 1, title: "Review GuardDuty Alert", description: "Analyze the crypto mining finding.", hint: "Type 'aws guardduty get-findings'." },
      { number: 2, title: "Identify Affected Instance", description: "Find which instance is compromised.", hint: "Type 'scan' to see affected resources." },
      { number: 3, title: "Isolate Instance", description: "Quarantine the compromised instance.", hint: "Type 'aws ec2 isolate web-server-03'." },
      { number: 4, title: "Verify Isolation", description: "Confirm instance is isolated.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "ec2", name: "web-server-03", config: { mining: true, pool: "pool.minexmr.com" }, isVulnerable: true, status: "compromised" }
    ],
    fixCommand: "aws ec2 isolate web-server-03"
  },
  {
    title: "Unauthorized IAM Policy Change",
    description: "An IAM policy was modified to grant administrative access. Investigate and revert the change.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    initialState: { policies: ["developer-policy"] },
    steps: [
      { number: 1, title: "Detect Policy Change", description: "Scan for unauthorized policy modifications.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Policy History", description: "Check policy version history.", hint: "Type 'aws iam get-policy-versions developer-policy'." },
      { number: 3, title: "Revert Policy", description: "Restore the previous policy version.", hint: "Type 'aws iam revert-policy developer-policy'." },
      { number: 4, title: "Verify Reversion", description: "Confirm policy is reverted.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "iam_policy", name: "developer-policy", config: { modified: true, grants: "AdministratorAccess" }, isVulnerable: true, status: "modified" }
    ],
    fixCommand: "aws iam revert-policy developer-policy"
  },
  {
    title: "Suspicious SSM Session",
    description: "AWS Systems Manager sessions were initiated from an unusual location. Investigate and terminate.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    initialState: { sessions: ["ssm-session-xyz"] },
    steps: [
      { number: 1, title: "Detect Suspicious Session", description: "Scan for unusual SSM activity.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Active Sessions", description: "List all SSM sessions.", hint: "Type 'aws ssm list-sessions'." },
      { number: 3, title: "Terminate Session", description: "End the suspicious session.", hint: "Type 'aws ssm terminate ssm-session-xyz'." },
      { number: 4, title: "Verify Termination", description: "Confirm session is ended.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "ssm_session", name: "ssm-session-xyz", config: { sourceIP: "185.220.101.42", user: "unknown" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws ssm terminate ssm-session-xyz"
  },
  {
    title: "KMS Key Scheduled for Deletion",
    description: "A critical KMS key is scheduled for deletion, which would make encrypted data unrecoverable.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    initialState: { keys: ["kms-prod-encryption"] },
    steps: [
      { number: 1, title: "Detect Pending Deletion", description: "Scan for keys scheduled for deletion.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Check Key Status", description: "Review KMS key configuration.", hint: "Type 'aws kms describe-key kms-prod-encryption'." },
      { number: 3, title: "Cancel Deletion", description: "Stop the key deletion.", hint: "Type 'aws kms cancel-deletion kms-prod-encryption'." },
      { number: 4, title: "Verify Key", description: "Confirm key is no longer pending deletion.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "kms_key", name: "kms-prod-encryption", config: { pendingDeletion: true, deletionDate: "2025-02-01" }, isVulnerable: true, status: "pending-deletion" }
    ],
    fixCommand: "aws kms cancel-deletion kms-prod-encryption"
  },
  {
    title: "Root Account Activity Detected",
    description: "The AWS root account was used to perform actions. Investigate and ensure it's secured.",
    difficulty: "Intermediate",
    category: "SOC Operations",
    initialState: { accounts: ["root"] },
    steps: [
      { number: 1, title: "Detect Root Usage", description: "Scan for root account activity.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Root Activity", description: "Check what actions root performed.", hint: "Type 'aws cloudtrail lookup-root'." },
      { number: 3, title: "Secure Root Account", description: "Enable MFA and remove access keys.", hint: "Type 'aws iam secure-root'." },
      { number: 4, title: "Verify Security", description: "Confirm root is now secured.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "iam_root", name: "root-account", config: { mfa: false, accessKeys: true }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws iam secure-root"
  },
  {
    title: "Cross-Account Role Assumption Attack",
    description: "An attacker is using a compromised role to pivot to other AWS accounts. Investigate the assume role chain.",
    difficulty: "Advanced",
    category: "SOC Operations",
    initialState: { roles: ["cross-account-role"] },
    steps: [
      { number: 1, title: "Detect Cross-Account Activity", description: "Scan for suspicious role assumptions.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Trace Role Chain", description: "Follow the assume role events.", hint: "Type 'aws cloudtrail trace-roles'." },
      { number: 3, title: "Revoke Trust Policy", description: "Remove external account trust.", hint: "Type 'aws iam revoke-trust cross-account-role'." },
      { number: 4, title: "Verify Revocation", description: "Confirm trust is revoked.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "iam_role", name: "cross-account-role", config: { trustedAccounts: ["999888777666"] }, isVulnerable: true, status: "compromised" }
    ],
    fixCommand: "aws iam revoke-trust cross-account-role"
  },
  {
    title: "EventBridge Rule Persistence",
    description: "An attacker created an EventBridge rule to maintain persistence by triggering on security changes.",
    difficulty: "Advanced",
    category: "SOC Operations",
    initialState: { rules: ["malicious-persistence-rule"] },
    steps: [
      { number: 1, title: "Detect Malicious Rule", description: "Scan for suspicious EventBridge rules.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Analyze Rule", description: "Review the rule configuration.", hint: "Type 'aws events describe-rule malicious-persistence-rule'." },
      { number: 3, title: "Delete Rule", description: "Remove the malicious persistence mechanism.", hint: "Type 'aws events delete-rule malicious-persistence-rule'." },
      { number: 4, title: "Verify Deletion", description: "Confirm rule is removed.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "eventbridge_rule", name: "malicious-persistence-rule", config: { pattern: "iam:*", target: "malicious-lambda" }, isVulnerable: true, status: "active" }
    ],
    fixCommand: "aws events delete-rule malicious-persistence-rule"
  },
  {
    title: "Data Exfiltration via DataSync",
    description: "An attacker is using AWS DataSync to exfiltrate data to an external location. Stop the transfer.",
    difficulty: "Advanced",
    category: "SOC Operations",
    initialState: { tasks: ["datasync-exfil-task"] },
    steps: [
      { number: 1, title: "Detect Data Transfer", description: "Scan for suspicious DataSync activity.", hint: "Type 'scan' to identify issues." },
      { number: 2, title: "Review Task", description: "Check DataSync task configuration.", hint: "Type 'aws datasync describe-task datasync-exfil-task'." },
      { number: 3, title: "Stop Task", description: "Terminate the data transfer.", hint: "Type 'aws datasync stop-task datasync-exfil-task'." },
      { number: 4, title: "Verify Stop", description: "Confirm transfer is stopped.", hint: "Type 'scan' to verify." }
    ],
    resources: [
      { type: "datasync_task", name: "datasync-exfil-task", config: { destination: "external-bucket", status: "running" }, isVulnerable: true, status: "running" }
    ],
    fixCommand: "aws datasync stop-task datasync-exfil-task"
  }
];

export const allLabs = [
  ...storageSecurityLabs,
  ...networkSecurityLabs,
  ...socOperationsLabs
];
