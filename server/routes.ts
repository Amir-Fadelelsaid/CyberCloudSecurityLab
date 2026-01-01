import type { Express } from "express";
import type { Server } from "http";
import { WebSocketServer, WebSocket } from "ws";
import { storage } from "./storage";
import { db } from "./db";
import { badges } from "@shared/schema";
import { eq } from "drizzle-orm";
import { setupAuth, isAuthenticated, registerAuthRoutes } from "./replit_integrations/auth";
import { api } from "@shared/routes";
import { allLabs } from "./lab-definitions";
import { allBadgeDefinitions, calculateLevel } from "./badge-definitions";
import { getUncachableGitHubClient } from "./github";
import * as fs from "fs";

let leaderboardClients: Set<WebSocket> | null = null;

export function broadcastLeaderboardUpdate() {
  if (!leaderboardClients) return;
  
  storage.getLeaderboard().then(leaderboard => {
    const message = JSON.stringify({ type: 'leaderboard_update', data: leaderboard });
    leaderboardClients?.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(message);
        } catch (e) {
          console.error("Failed to send leaderboard update to client:", e);
        }
      }
    });
  }).catch(err => {
    console.error("Failed to fetch leaderboard for broadcast:", err);
  });
}

// Remediation verification details by resource type
const getRemediationDetails = (resourceType: string, resourceName: string, config: Record<string, any>): string => {
  const details: Record<string, string[]> = {
    s3: [
      `Bucket: ${resourceName}`,
      `Verification: Block Public Access enabled`,
      `Verification: Server-side encryption configured`,
      `CIS Control: 2.1.1 - Ensure S3 bucket access is restricted`,
      `MITRE ATT&CK: T1530 - Data from Cloud Storage Object mitigated`
    ],
    security_group: [
      `Security Group: ${resourceName}`,
      `Verification: Ingress rules restricted to authorized CIDR ranges`,
      `Verification: No 0.0.0.0/0 rules on sensitive ports`,
      `CIS Control: 5.2 - Ensure no security groups allow ingress from 0.0.0.0/0`,
      `MITRE ATT&CK: T1190 - Exploit Public-Facing Application mitigated`
    ],
    iam_role: [
      `IAM Role: ${resourceName}`,
      `Verification: Least privilege permissions applied`,
      `Verification: Trust policy restricted to authorized principals`,
      `CIS Control: 1.16 - Ensure IAM policies are attached only to groups or roles`,
      `MITRE ATT&CK: T1078 - Valid Accounts mitigated`
    ],
    cloudtrail: [
      `CloudTrail: ${resourceName}`,
      `Verification: Multi-region logging enabled`,
      `Verification: Log file validation active`,
      `CIS Control: 3.1 - Ensure CloudTrail is enabled in all regions`,
      `MITRE ATT&CK: T1562.008 - Disable Cloud Logs mitigated`
    ],
    vpc: [
      `VPC: ${resourceName}`,
      `Verification: Flow logs enabled`,
      `Verification: Network segmentation validated`,
      `CIS Control: 3.9 - Ensure VPC flow logging is enabled`,
      `MITRE ATT&CK: T1046 - Network Service Discovery visibility improved`
    ],
    vpn_connection: [
      `VPN Connection: ${resourceName}`,
      `Verification: Both IPsec tunnels operational (UP/UP)`,
      `Verification: IKE Phase 1 and Phase 2 negotiation successful`,
      `Verification: BGP sessions established (if applicable)`,
      `CIS Control: 12.4 - Establish and maintain network device configuration standards`,
      `MITRE ATT&CK: T1016 - System Network Configuration Discovery blocked`
    ],
    nat_gateway: [
      `NAT Gateway: ${resourceName}`,
      `Verification: Port allocation errors resolved`,
      `Verification: Multi-AZ architecture implemented for high availability`,
      `Verification: Route tables updated for AZ-local routing`,
      `CIS Control: 13.4 - Perform traffic filtering on network services`,
      `MITRE ATT&CK: T1041 - Exfiltration Over C2 Channel detection enabled`
    ],
    resolver_endpoint: [
      `Resolver Endpoint: ${resourceName}`,
      `Verification: DNS forwarding operational`,
      `Verification: Security group rules allow UDP/TCP 53`,
      `Verification: Hybrid DNS resolution working`,
      `CIS Control: 12.1 - Ensure Network Infrastructure is Up-to-Date`,
      `MITRE ATT&CK: T1071.004 - DNS Protocol monitoring enabled`
    ],
    target_group: [
      `Target Group: ${resourceName}`,
      `Verification: Health check path and port corrected`,
      `Verification: All targets reporting healthy`,
      `Verification: Load balancer serving traffic`,
      `CIS Control: 9.1 - Associate Active Ports, Services, and Protocols`,
      `MITRE ATT&CK: T1190 - Exploit Public-Facing Application mitigated`
    ],
    ec2: [
      `EC2 Instance: ${resourceName}`,
      `Verification: Instance isolated from network`,
      `Verification: Security group changed to deny-all`,
      `Verification: Instance preserved for forensic analysis`,
      `CIS Control: 7.7 - Remediate Vulnerabilities within Defined Timeframes`,
      `MITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol blocked`
    ]
  };
  
  return (details[resourceType] || [`Resource: ${resourceName}`, `Verification: Security configuration applied`]).join('\n');
};

// Generic command handler for fixing resources with enhanced verification
const handleFixCommand = async (
  resourceType: string,
  resourceName: string,
  resources: any[],
  labId: number,
  userId: string
) => {
  const resource = resources.find(r => r.type === resourceType && r.name === resourceName);
  
  if (!resource) {
    return { output: `[ERROR] Resource ${resourceName} not found.\n\nHint: Use 'scan' to list available resources.`, success: false, labCompleted: false };
  }
  
  if (!resource.isVulnerable) {
    return { output: `[INFO] ${resourceName} is already secure.\n\nNo further action required.`, success: false, labCompleted: false };
  }
  
  await storage.updateResource(resource.id, { isVulnerable: false, status: 'secured' });
  
  const remaining = resources.filter(r => r.id !== resource.id && r.isVulnerable);
  let labCompleted = false;
  
  const remediationDetails = getRemediationDetails(resourceType, resourceName, resource.config || {});
  
  let output = `${'='.repeat(60)}
[REMEDIATION VERIFIED]
${'='.repeat(60)}
${remediationDetails}
${'='.repeat(60)}

Status: SECURED
Previous State: VULNERABLE
Current State: COMPLIANT
`;
  
  if (remaining.length > 0) {
    output += `\n[REMAINING] ${remaining.length} vulnerable resource(s) require attention.`;
  } else {
    labCompleted = true;
    output += `
${'='.repeat(60)}
[MISSION COMPLETE] All vulnerabilities remediated!
${'='.repeat(60)}

All security controls have been verified and validated.
Your progress has been recorded.
`;
    await storage.updateProgress(userId, labId, true);
    broadcastLeaderboardUpdate();
  }
  
  return { output, success: true, labCompleted };
};

// Simulated command processor
const processCommand = async (command: string, labId: number, userId: string) => {
  const resources = await storage.getResources(labId, userId);
  const lowerCmd = command.toLowerCase().trim();
  
  let output = "";
  let success = false;
  let labCompleted = false;

  // HELP command
  if (lowerCmd === "help") {
    output = `Available commands:
  scan                       Run security scan
  
  SOC Commands:
  siem list-sources          List integrated log sources
  siem add-source <source>   Add log source to SIEM
  siem alerts                List SIEM alerts queue
  siem triage <alert-id>     Investigate an alert
  siem enrich <alert-id>     Get threat intel enrichment
  siem escalate <alert-id>   Escalate to Tier 2
  siem classify <alert-id>   Classify alert type
  siem close <alert-id>      Close alert with resolution
  logs search <query>        Search log events
  logs recent                Show recent log events
  endpoint list              List monitored endpoints
  endpoint status <host>     Get endpoint details
  endpoint isolate <host>    Isolate compromised endpoint
  network flows              Show network flow summary
  network investigate <ip>   Analyze IP traffic
  network block <ip>         Block malicious IP
  incident create            Create new incident
  incident note <text>       Add investigation note
  incident timeline          View incident timeline
  
  S3 Commands:
  aws s3 ls                  List S3 buckets
  aws s3 fix <bucket>        Apply secure bucket policy
  aws s3 enable-encryption <bucket>   Enable SSE encryption
  aws s3 enable-logging <bucket>      Enable access logging
  aws s3 enable-versioning <bucket>   Enable bucket versioning
  aws s3 restrict-policy <bucket>     Apply least privilege policy
  aws s3 revoke-external <bucket>     Remove external account access
  aws s3 enable-object-lock <bucket>  Enable WORM protection
  aws s3 block-public-access <bucket> Enable block public access
  aws s3 fix-replication <bucket>     Fix replication region
  aws s3 fix-presigned <bucket>       Fix pre-signed URL expiry
  
  EC2/Network Commands:
  aws ec2 ls                 List EC2 instances
  aws ec2 restrict-ssh <id>  Restrict SSH access
  aws ec2 restrict-rdp <id>  Restrict RDP access
  aws ec2 restrict-db <id>   Restrict database port access
  aws ec2 fix-nacl <nacl>    Fix Network ACL rules
  aws ec2 enable-flow-logs <vpc>      Enable VPC Flow Logs
  aws ec2 restrict-egress <id>        Restrict egress traffic
  aws ec2 release-eip <eip>  Release unused Elastic IP
  aws ec2 restrict-peering <pcx>      Restrict VPC peering routes
  aws ec2 fix-tgw-routes <tgw>        Fix Transit Gateway routes
  aws ec2 isolate <instance> Isolate compromised instance
  
  WAF Commands:
  aws waf associate <alb>    Associate WAF with ALB
  
  IAM Commands:
  aws iam list-compromised   Show compromised credentials
  aws iam revoke-keys <user> Revoke user's access keys
  aws iam revert-policy <policy>      Revert policy to previous version
  aws iam secure-root        Secure root account
  aws iam revoke-trust <role>         Revoke external trust
  
  CloudTrail Commands:
  aws cloudtrail lookup-events    View recent API activity
  aws cloudtrail enable <trail>   Enable CloudTrail logging
  aws cloudtrail lookup-root      View root account activity
  aws cloudtrail trace-roles      Trace role assumption chain
  
  GuardDuty Commands:
  aws guardduty get-findings      View GuardDuty findings
  
  SSM Commands:
  aws ssm list-sessions      List active SSM sessions
  aws ssm terminate <session>     Terminate SSM session
  
  KMS Commands:
  aws kms cancel-deletion <key>   Cancel key deletion
  
  EventBridge Commands:
  aws events delete-rule <rule>   Delete EventBridge rule
  
  DataSync Commands:
  aws datasync stop-task <task>   Stop DataSync task
  
  report incident            Generate incident report`;
  }
  // SCAN command
  else if (lowerCmd === "scan") {
    const vulnerabilities = resources.filter(r => r.isVulnerable);
    if (vulnerabilities.length > 0) {
      output = "SECURITY ALERT: Vulnerabilities detected!\n" + vulnerabilities.map(v => 
        `- ${v.type.toUpperCase()}: ${v.name} is misconfigured`
      ).join('\n');
    } else {
      output = "Scan complete. No vulnerabilities found. System secure.";
    }
  }
  else if (lowerCmd === "scan verify" || lowerCmd === "verify") {
    const vulnerabilities = resources.filter(r => r.isVulnerable);
    if (vulnerabilities.length > 0) {
      output = `=== Security Verification ===

Status: INCOMPLETE
Remaining Issues: ${vulnerabilities.length}

${vulnerabilities.map(v => `[!] ${v.type.toUpperCase()}: ${v.name} - requires remediation`).join('\n')}

Run 'help' to see available remediation commands.`;
    } else {
      output = `=== Security Verification ===

Status: VERIFIED
All Resources: COMPLIANT

Security controls validated successfully.`;
      success = true;
    }
  }
  // S3 Commands
  else if (lowerCmd === "aws s3 ls") {
    const buckets = resources.filter(r => r.type === 's3');
    if (buckets.length > 0) {
      output = buckets.map(b => `${b.name} [${b.isVulnerable ? 'VULNERABLE' : 'SECURE'}]`).join('\n');
    } else {
      output = "No S3 buckets found.";
    }
  }
  else if (lowerCmd === "aws s3 ls-encryption") {
    const buckets = resources.filter(r => r.type === 's3');
    if (buckets.length > 0) {
      output = "=== S3 Bucket Encryption Status ===\n\n" + buckets.map(b => {
        const config = b.config as any;
        const encrypted = config.encryption !== 'none' && config.encryption !== undefined;
        return `${b.name}: ${encrypted || !b.isVulnerable ? 'AES-256 (Enabled)' : 'NONE (Not Encrypted)'}`;
      }).join('\n');
    } else {
      output = "No S3 buckets found.";
    }
  }
  else if (lowerCmd === "aws s3 ls-logging") {
    const buckets = resources.filter(r => r.type === 's3');
    if (buckets.length > 0) {
      output = "=== S3 Bucket Logging Status ===\n\n" + buckets.map(b => {
        const config = b.config as any;
        const logging = config.logging !== false || !b.isVulnerable;
        return `${b.name}: ${logging ? 'Enabled' : 'DISABLED - No access logs'}`;
      }).join('\n');
    } else {
      output = "No S3 buckets found.";
    }
  }
  else if (lowerCmd === "aws s3 ls-versioning") {
    const buckets = resources.filter(r => r.type === 's3');
    if (buckets.length > 0) {
      output = "=== S3 Bucket Versioning Status ===\n\n" + buckets.map(b => {
        const config = b.config as any;
        const versioning = config.versioning !== false || !b.isVulnerable;
        return `${b.name}: ${versioning ? 'Enabled' : 'DISABLED - No version history'}`;
      }).join('\n');
    } else {
      output = "No S3 buckets found.";
    }
  }
  else if (lowerCmd.startsWith("aws s3 get-policy ")) {
    const bucketName = lowerCmd.replace("aws s3 get-policy ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      const config = bucket.config as any;
      output = `=== Bucket Policy: ${bucketName} ===\n\n`;
      if (bucket.isVulnerable) {
        output += `{\n  "Effect": "Allow",\n  "Principal": "${config.principal || '*'}",\n  "Action": "${config.policy || 's3:*'}",\n  "Resource": "arn:aws:s3:::${bucketName}/*"\n}\n\n[!] WARNING: Policy is overly permissive`;
      } else {
        output += `{\n  "Effect": "Allow",\n  "Principal": {"AWS": "arn:aws:iam::123456789012:root"},\n  "Action": ["s3:GetObject"],\n  "Resource": "arn:aws:s3:::${bucketName}/*"\n}\n\n[OK] Policy follows least privilege`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 check-access ")) {
    const bucketName = lowerCmd.replace("aws s3 check-access ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      const config = bucket.config as any;
      if (bucket.isVulnerable && config.crossAccount) {
        output = `=== Cross-Account Access: ${bucketName} ===\n\nAuthorized Accounts:\n  - 123456789012 (This Account)\n\nUnauthorized/Unknown Accounts:\n  - ${config.crossAccount.filter((a: string) => a !== '123456789012').join('\n  - ')}\n\n[!] WARNING: Unknown external accounts have access`;
      } else {
        output = `=== Cross-Account Access: ${bucketName} ===\n\nOnly authorized accounts have access.`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 check-object-lock ")) {
    const bucketName = lowerCmd.replace("aws s3 check-object-lock ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      output = `=== Object Lock Status: ${bucketName} ===\n\nObject Lock: ${bucket.isVulnerable ? 'DISABLED' : 'ENABLED'}\n${bucket.isVulnerable ? '\n[!] WARNING: Data can be deleted without WORM protection' : '\n[OK] Compliance mode active'}`;
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 check-block-public ")) {
    const bucketName = lowerCmd.replace("aws s3 check-block-public ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      output = `=== Block Public Access: ${bucketName} ===\n\n`;
      if (bucket.isVulnerable) {
        output += `BlockPublicAcls: false\nIgnorePublicAcls: false\nBlockPublicPolicy: false\nRestrictPublicBuckets: false\n\n[!] WARNING: Bucket can be made public`;
      } else {
        output += `BlockPublicAcls: true\nIgnorePublicAcls: true\nBlockPublicPolicy: true\nRestrictPublicBuckets: true\n\n[OK] All public access blocked`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 check-replication ")) {
    const bucketName = lowerCmd.replace("aws s3 check-replication ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      const config = bucket.config as any;
      output = `=== Replication Configuration: ${bucketName} ===\n\n`;
      if (bucket.isVulnerable) {
        output += `Destination Region: ${config.replication || 'us-east-1'}\nRequired Region: ${config.required || 'eu-west-1'}\n\n[!] WARNING: Data being replicated to non-compliant region`;
      } else {
        output += `Destination Region: ${config.required || 'eu-west-1'}\n\n[OK] Replication configured to compliant region`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 check-presigned ")) {
    const bucketName = lowerCmd.replace("aws s3 check-presigned ", "").trim();
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    if (bucket) {
      const config = bucket.config as any;
      output = `=== Pre-signed URL Policy: ${bucketName} ===\n\n`;
      if (bucket.isVulnerable) {
        output += `Maximum Expiration: ${config.presignedExpiry || '7d'}\n\n[!] WARNING: Long expiration creates security risk`;
      } else {
        output += `Maximum Expiration: 1h\n\n[OK] Short expiration reduces risk`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws s3 fix ")) {
    const bucketName = lowerCmd.replace("aws s3 fix ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 enable-encryption ")) {
    const bucketName = lowerCmd.replace("aws s3 enable-encryption ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] AES-256 server-side encryption enabled for ${bucketName}.\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 enable-logging ")) {
    const bucketName = lowerCmd.replace("aws s3 enable-logging ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Access logging enabled for ${bucketName}.\n  - Logs delivered to ${bucketName}-access-logs\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 enable-versioning ")) {
    const bucketName = lowerCmd.replace("aws s3 enable-versioning ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Versioning enabled for ${bucketName}.\n  - All objects will now maintain version history\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 restrict-policy ")) {
    const bucketName = lowerCmd.replace("aws s3 restrict-policy ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Bucket policy restricted for ${bucketName}.\n  - Removed wildcard (*) permissions\n  - Applied least privilege access\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 revoke-external ")) {
    const bucketName = lowerCmd.replace("aws s3 revoke-external ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] External account access revoked for ${bucketName}.\n  - Removed unauthorized cross-account access\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 enable-object-lock ")) {
    const bucketName = lowerCmd.replace("aws s3 enable-object-lock ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Object Lock enabled for ${bucketName}.\n  - WORM (Write Once Read Many) protection active\n  - Compliance mode configured\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 block-public-access ")) {
    const bucketName = lowerCmd.replace("aws s3 block-public-access ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Block Public Access enabled for ${bucketName}.\n  - BlockPublicAcls: true\n  - IgnorePublicAcls: true\n  - BlockPublicPolicy: true\n  - RestrictPublicBuckets: true\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 fix-replication ")) {
    const bucketName = lowerCmd.replace("aws s3 fix-replication ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Replication configuration fixed for ${bucketName}.\n  - Destination changed to compliant region (eu-west-1)\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  else if (lowerCmd.startsWith("aws s3 fix-presigned ")) {
    const bucketName = lowerCmd.replace("aws s3 fix-presigned ", "").trim();
    const result = await handleFixCommand("s3", bucketName, resources, labId, userId);
    if (result.success) {
      result.output = `[SUCCESS] Pre-signed URL policy updated for ${bucketName}.\n  - Maximum expiration reduced to 1 hour\n` + 
        (result.labCompleted ? "\n[MISSION COMPLETE] All vulnerabilities remediated!" : "");
    }
    return result;
  }
  // EC2 Diagnostic Commands
  else if (lowerCmd === "aws ec2 ls-sg" || lowerCmd === "aws ec2 ls") {
    const sgs = resources.filter(r => r.type === 'security_group' || r.type === 'ec2');
    if (sgs.length > 0) {
      output = "=== Security Groups / Instances ===\n\n" + sgs.map(sg => {
        const config = sg.config as any;
        const ingress = config.ingress ? config.ingress.map((r: any) => `Port ${r.port} from ${r.source}`).join(', ') : 'N/A';
        return `${sg.name}: ${sg.isVulnerable ? '[VULNERABLE]' : '[SECURE]'}\n  Ingress: ${ingress}`;
      }).join('\n\n');
    } else {
      output = "No security groups found.";
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-sg ")) {
    const instanceId = lowerCmd.replace("aws ec2 describe-sg ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg) {
      const config = sg.config as any;
      output = `=== Security Group: ${sg.name} ===\n\n`;
      if (sg.isVulnerable) {
        output += `Inbound Rules:\n`;
        (config.ingress || []).forEach((r: any) => {
          output += `  - Port ${r.port} from ${r.source} [${r.source === '0.0.0.0/0' ? 'OPEN TO INTERNET' : 'OK'}]\n`;
        });
        output += `\n[!] WARNING: Overly permissive rules detected`;
      } else {
        output += `Inbound Rules:\n  - All traffic restricted to internal networks\n\n[OK] Security group properly configured`;
      }
    } else {
      output = `Error: No security group found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-nacl ")) {
    const naclName = lowerCmd.replace("aws ec2 describe-nacl ", "").trim();
    const nacl = resources.find(r => r.type === 'nacl' && r.name === naclName);
    if (nacl) {
      output = `=== Network ACL: ${naclName} ===\n\n`;
      if (nacl.isVulnerable) {
        output += `Inbound Rules:\n  - Rule 100: ALLOW all traffic from 0.0.0.0/0\n\n[!] WARNING: All inbound traffic allowed`;
      } else {
        output += `Inbound Rules:\n  - Rule 100: ALLOW HTTPS (443) from 0.0.0.0/0\n  - Rule 200: ALLOW ephemeral ports from 0.0.0.0/0\n  - Rule *: DENY all\n\n[OK] NACL properly configured`;
      }
    } else {
      output = `Error: NACL ${naclName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-vpc ")) {
    const vpcName = lowerCmd.replace("aws ec2 describe-vpc ", "").trim();
    const vpc = resources.find(r => r.type === 'vpc' && r.name === vpcName);
    if (vpc) {
      output = `=== VPC: ${vpcName} ===\n\nFlow Logs: ${vpc.isVulnerable ? 'DISABLED' : 'ENABLED'}\n${vpc.isVulnerable ? '\n[!] WARNING: No network traffic visibility' : '\n[OK] Traffic logging active'}`;
    } else {
      output = `Error: VPC ${vpcName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-egress ")) {
    const instanceId = lowerCmd.replace("aws ec2 describe-egress ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg) {
      const config = sg.config as any;
      output = `=== Egress Rules for ${instanceId} ===\n\n`;
      if (sg.isVulnerable) {
        output += `Outbound: ${config.egress || '0.0.0.0/0:all'}\n\n[!] WARNING: All outbound traffic allowed - data exfiltration risk`;
      } else {
        output += `Outbound: HTTPS (443) to AWS services only\n\n[OK] Egress properly restricted`;
      }
    } else {
      output = `Error: Instance ${instanceId} not found.`;
    }
  }
  else if (lowerCmd === "aws ec2 describe-eips") {
    const eips = resources.filter(r => r.type === 'eip');
    if (eips.length > 0) {
      output = "=== Elastic IPs ===\n\n" + eips.map(eip => {
        const config = eip.config as any;
        return `${eip.name}: ${config.associated ? 'Associated' : 'NOT ASSOCIATED'} ${eip.isVulnerable ? '[WASTED RESOURCE]' : ''}`;
      }).join('\n');
    } else {
      output = "No Elastic IPs found.";
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-peering ")) {
    const pcxName = lowerCmd.replace("aws ec2 describe-peering ", "").trim();
    const peering = resources.find(r => r.type === 'vpc_peering' && r.name === pcxName);
    if (peering) {
      const config = peering.config as any;
      output = `=== VPC Peering: ${pcxName} ===\n\nRoutes: ${config.routes}\n${peering.isVulnerable ? '\n[!] WARNING: All subnets accessible via peering' : '\n[OK] Routes restricted to specific subnets'}`;
    } else {
      output = `Error: Peering ${pcxName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-tgw ")) {
    const tgwName = lowerCmd.replace("aws ec2 describe-tgw ", "").trim();
    const tgw = resources.find(r => r.type === 'transit_gateway' && r.name === tgwName);
    if (tgw) {
      const config = tgw.config as any;
      output = `=== Transit Gateway: ${tgwName} ===\n\nRoute Propagation: ${config.propagation}\n${tgw.isVulnerable ? '\n[!] WARNING: Routes propagating to all VPCs' : '\n[OK] Manual route configuration'}`;
    } else {
      output = `Error: Transit Gateway ${tgwName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws waf check-association ")) {
    const albName = lowerCmd.replace("aws waf check-association ", "").trim();
    const alb = resources.find(r => r.type === 'alb' && r.name === albName);
    if (alb) {
      output = `=== WAF Association: ${albName} ===\n\nWAF: ${alb.isVulnerable ? 'NOT ASSOCIATED' : 'ASSOCIATED'}\n${alb.isVulnerable ? '\n[!] WARNING: No web application firewall protection' : '\n[OK] WAF rules active'}`;
    } else {
      output = `Error: ALB ${albName} not found.`;
    }
  }
  // EC2/Network Commands
  else if (lowerCmd.startsWith("aws ec2 restrict-ssh ") || lowerCmd === "aws ec2 restrict-ssh") {
    const instanceId = lowerCmd.replace("aws ec2 restrict-ssh ", "").trim() || "instance";
    const sg = resources.find(r => r.type === 'security_group' && r.isVulnerable);
    const anyVulnerable = resources.find(r => r.isVulnerable);
    const targetResource = sg || anyVulnerable;
    if (targetResource && targetResource.isVulnerable) {
      await storage.updateResource(targetResource.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Security group updated for ${instanceId}\n  - SSH restricted to 10.0.0.0/8 (internal only)\n  - Removed 0.0.0.0/0 from ingress`;
      success = true;
      const remaining = resources.filter(r => r.id !== targetResource.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else if (sg) {
      output = `Info: Security group for ${instanceId} is already secure.`;
    } else {
      output = `[SUCCESS] SSH access restricted for ${instanceId}.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-rdp ")) {
    const instanceId = lowerCmd.replace("aws ec2 restrict-rdp ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Security group updated for ${instanceId}\n  - RDP restricted to VPN CIDR (10.0.0.0/8)\n  - Removed 0.0.0.0/0 from port 3389`;
      success = true;
      const remaining = resources.filter(r => r.id !== sg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Instance ${instanceId} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-db ")) {
    const instanceId = lowerCmd.replace("aws ec2 restrict-db ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Security group updated for ${instanceId}\n  - Database port restricted to app server security group\n  - Removed public internet access`;
      success = true;
      const remaining = resources.filter(r => r.id !== sg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Instance ${instanceId} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 fix-nacl ")) {
    const naclName = lowerCmd.replace("aws ec2 fix-nacl ", "").trim();
    const nacl = resources.find(r => r.type === 'nacl' && r.name === naclName);
    if (nacl && nacl.isVulnerable) {
      await storage.updateResource(nacl.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Network ACL ${naclName} updated\n  - Deny-by-default rule applied\n  - Only essential ports allowed`;
      success = true;
      const remaining = resources.filter(r => r.id !== nacl.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: NACL ${naclName} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 enable-flow-logs ")) {
    const vpcName = lowerCmd.replace("aws ec2 enable-flow-logs ", "").trim();
    const vpc = resources.find(r => r.type === 'vpc' && r.name === vpcName);
    if (vpc && vpc.isVulnerable) {
      await storage.updateResource(vpc.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] VPC Flow Logs enabled for ${vpcName}\n  - Logs delivered to CloudWatch Logs\n  - Retention: 30 days`;
      success = true;
      const remaining = resources.filter(r => r.id !== vpc.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: VPC ${vpcName} not found or already has flow logs.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-egress ")) {
    const instanceId = lowerCmd.replace("aws ec2 restrict-egress ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Egress rules restricted for ${instanceId}\n  - Only HTTPS (443) to AWS services allowed\n  - All other outbound traffic blocked`;
      success = true;
      const remaining = resources.filter(r => r.id !== sg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Instance ${instanceId} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 release-eip ")) {
    const eipName = lowerCmd.replace("aws ec2 release-eip ", "").trim();
    const eip = resources.find(r => r.type === 'eip' && r.name === eipName);
    if (eip && eip.isVulnerable) {
      await storage.updateResource(eip.id, { isVulnerable: false, status: 'released' });
      output = `[SUCCESS] Elastic IP ${eipName} released\n  - IP returned to AWS pool\n  - No longer incurring charges`;
      success = true;
      const remaining = resources.filter(r => r.id !== eip.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: EIP ${eipName} not found or already released.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-peering ")) {
    const pcxName = lowerCmd.replace("aws ec2 restrict-peering ", "").trim();
    const peering = resources.find(r => r.type === 'vpc_peering' && r.name === pcxName);
    if (peering && peering.isVulnerable) {
      await storage.updateResource(peering.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] VPC Peering ${pcxName} routes restricted\n  - Only specific subnets allowed\n  - Removed 0.0.0.0/0 route`;
      success = true;
      const remaining = resources.filter(r => r.id !== peering.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Peering ${pcxName} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 fix-tgw-routes ")) {
    const tgwName = lowerCmd.replace("aws ec2 fix-tgw-routes ", "").trim();
    const tgw = resources.find(r => r.type === 'transit_gateway' && r.name === tgwName);
    if (tgw && tgw.isVulnerable) {
      await storage.updateResource(tgw.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Transit Gateway ${tgwName} routes fixed\n  - Automatic route propagation disabled\n  - Static routes configured for intended VPCs only`;
      success = true;
      const remaining = resources.filter(r => r.id !== tgw.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Transit Gateway ${tgwName} not found or already secure.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 isolate ")) {
    const instanceName = lowerCmd.replace("aws ec2 isolate ", "").trim();
    const instance = resources.find(r => r.type === 'ec2' && r.name === instanceName);
    if (instance && instance.isVulnerable) {
      await storage.updateResource(instance.id, { isVulnerable: false, status: 'isolated' });
      const remediationDetails = getRemediationDetails('ec2', instanceName, instance.config || {});
      output = `${'='.repeat(60)}
[REMEDIATION VERIFIED]
${'='.repeat(60)}
${remediationDetails}
${'='.repeat(60)}

Status: ISOLATED
Previous State: COMPROMISED
Current State: CONTAINED`;
      success = true;
      const remaining = resources.filter(r => r.id !== instance.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += `

${'='.repeat(60)}
[MISSION COMPLETE] Threat contained!
${'='.repeat(60)}

All security controls have been verified and validated.
Your progress has been recorded.`;
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: Instance ${instanceName} not found or already isolated.`;
    }
  }
  // WAF Commands
  else if (lowerCmd.startsWith("aws waf associate ")) {
    const albName = lowerCmd.replace("aws waf associate ", "").trim();
    const alb = resources.find(r => r.type === 'alb' && r.name === albName);
    if (alb && alb.isVulnerable) {
      await storage.updateResource(alb.id, { isVulnerable: false, status: 'protected' });
      output = `[SUCCESS] AWS WAF associated with ${albName}\n  - Managed rule groups enabled:\n    - AWSManagedRulesCommonRuleSet\n    - AWSManagedRulesKnownBadInputsRuleSet\n    - AWSManagedRulesSQLiRuleSet`;
      success = true;
      const remaining = resources.filter(r => r.id !== alb.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: ALB ${albName} not found or already protected.`;
    }
  }
  // IAM Diagnostic Commands
  else if (lowerCmd.startsWith("aws iam get-policy-versions ")) {
    const policyName = lowerCmd.replace("aws iam get-policy-versions ", "").trim();
    const policy = resources.find(r => r.type === 'iam_policy' && r.name === policyName);
    if (policy) {
      output = `=== Policy Versions: ${policyName} ===\n\nVersion 1 (Original): ReadOnlyAccess\nVersion 2 (Current): AdministratorAccess [MODIFIED]\n\n[!] WARNING: Policy was escalated to admin privileges`;
    } else {
      output = `Error: Policy ${policyName} not found.`;
    }
  }
  // IAM Commands
  else if (lowerCmd === "aws iam list-compromised") {
    const iamUser = resources.find(r => r.type === 'iam_user' && r.status === 'compromised');
    if (iamUser) {
      const config = iamUser.config as any;
      output = `=== Compromised Credentials Analysis ===\n\n[CRITICAL] User: ${iamUser.name}\n  Status: COMPROMISED\n  Access Key Age: ${config.accessKeyAge || 'Unknown'}\n  Permissions: ${(config.permissions || []).join(', ')}\n\n[!] Recommendation: Immediately revoke access keys for ${iamUser.name}`;
    } else {
      output = "No compromised credentials detected.";
    }
  }
  else if (lowerCmd.startsWith("aws iam revoke-keys ")) {
    const userName = lowerCmd.replace("aws iam revoke-keys ", "").trim();
    const iamUser = resources.find(r => r.type === 'iam_user' && r.name === userName);
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    
    if (iamUser && iamUser.isVulnerable) {
      await storage.updateResource(iamUser.id, { isVulnerable: false, status: 'secured' });
      if (cloudtrailRes && cloudtrailRes.isVulnerable) {
        await storage.updateResource(cloudtrailRes.id, { isVulnerable: false, status: 'investigated' });
      }
      output = `[SUCCESS] Access keys revoked for user: ${userName}\n  - All active access keys deactivated\n  - Session tokens invalidated\n  - User flagged for credential rotation`;
      success = true;
      
      const remaining = resources.filter(r => 
        r.id !== iamUser.id && r.id !== (cloudtrailRes?.id || 0) && r.isVulnerable
      );
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Incident contained! All compromised credentials revoked.";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else if (iamUser) {
      output = `Info: Access keys for ${userName} have already been revoked.`;
    } else {
      output = `Error: User ${userName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws iam revert-policy ")) {
    const policyName = lowerCmd.replace("aws iam revert-policy ", "").trim();
    const policy = resources.find(r => r.type === 'iam_policy' && r.name === policyName);
    if (policy && policy.isVulnerable) {
      await storage.updateResource(policy.id, { isVulnerable: false, status: 'reverted' });
      output = `[SUCCESS] Policy ${policyName} reverted to previous version\n  - Unauthorized changes removed\n  - Original permissions restored`;
      success = true;
      const remaining = resources.filter(r => r.id !== policy.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Policy ${policyName} not found or already at correct version.`;
    }
  }
  else if (lowerCmd === "aws iam secure-root") {
    const root = resources.find(r => r.type === 'iam_root' || r.type === 'root' || r.name?.includes('root'));
    if (root && root.isVulnerable) {
      await storage.updateResource(root.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Root account secured\n  - MFA enabled\n  - Access keys deleted\n  - Strong password policy enforced`;
      success = true;
      const remaining = resources.filter(r => r.id !== root.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      // Fallback - mark all vulnerable resources as fixed
      const vulnRes = resources.find(r => r.isVulnerable);
      if (vulnRes) {
        for (const res of resources.filter(r => r.isVulnerable)) {
          await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
        }
        output = `=== Root Account Secured ===

[OK] Hardware MFA enabled
[OK] Access keys deleted
[OK] Password rotated
[OK] Contact info verified
[OK] Root account now protected

Root account hardened against compromise.`;
        success = true;
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Root account secured!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      } else {
        output = "Root account is already secured.";
      }
    }
  }
  else if (lowerCmd.startsWith("aws iam revoke-trust ")) {
    const roleName = lowerCmd.replace("aws iam revoke-trust ", "").trim();
    const role = resources.find(r => r.type === 'iam_role' && r.name === roleName);
    if (role && role.isVulnerable) {
      await storage.updateResource(role.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Trust policy revoked for ${roleName}\n  - External account access removed\n  - Only internal accounts can now assume this role`;
      success = true;
      const remaining = resources.filter(r => r.id !== role.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: Role ${roleName} not found or already secure.`;
    }
  }
  // CloudTrail Diagnostic Commands
  else if (lowerCmd.startsWith("aws cloudtrail status ")) {
    const trailName = lowerCmd.replace("aws cloudtrail status ", "").trim();
    const trail = resources.find(r => r.type === 'cloudtrail' && r.name === trailName);
    if (trail) {
      output = `=== CloudTrail Status: ${trailName} ===\n\nLogging: ${trail.isVulnerable ? 'DISABLED' : 'ENABLED'}\n${trail.isVulnerable ? '\n[!] CRITICAL: CloudTrail logging disabled - no audit trail' : '\n[OK] Logging active'}`;
    } else {
      output = `Error: Trail ${trailName} not found.`;
    }
  }
  else if (lowerCmd === "aws cloudtrail lookup-root") {
    output = `=== Root Account Activity ===\n\nRecent API calls by root:\n  [2025-01-15T02:14:00Z] ConsoleLogin - IP: 203.0.113.50\n  [2025-01-15T02:15:30Z] CreateUser - User: backdoor-admin\n  [2025-01-15T02:16:00Z] AttachUserPolicy - Policy: AdministratorAccess\n\n[!] CRITICAL: Root account used for administrative tasks`;
  }
  else if (lowerCmd === "aws cloudtrail trace-roles") {
    output = `=== Role Assumption Chain ===\n\nInitial: arn:aws:iam::123456789012:user/developer\n  |\n  v AssumeRole\narn:aws:iam::123456789012:role/cross-account-role\n  |\n  v AssumeRole (Cross-Account)\narn:aws:iam::999888777666:role/external-admin\n\n[!] CRITICAL: Credentials used to pivot to external account`;
  }
  // CloudTrail Commands
  else if (lowerCmd === "aws cloudtrail lookup-events") {
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    if (cloudtrailRes) {
      const events = (cloudtrailRes.config as any).events || [];
      if (events.length > 0) {
        output = "=== CloudTrail Event History ===\n\n" + events.map((e: any) => 
          `[${e.timestamp}] ${e.eventName}\n  User: ${e.userIdentity}\n  Source IP: ${e.sourceIP}${e.targetRole ? '\n  Target Role: ' + e.targetRole : ''}${e.bucket ? '\n  Bucket: ' + e.bucket : ''}`
        ).join('\n\n');
        output += "\n\n[!] ALERT: Multiple events from suspicious IP 185.220.101.42 (Known Tor exit node)";
      } else {
        output = "No CloudTrail events recorded.";
      }
    } else {
      // Default CloudTrail output for SOC scenarios
      output = `=== CloudTrail Event History ===

Recent API Activity (last 24h):

[2025-12-30T03:42:00Z] AssumeRole
  User: arn:aws:iam::123456789012:user/compromised
  Source IP: 198.51.100.45 (Suspicious)
  Target Role: cross-account-admin

[2025-12-30T03:43:00Z] ListBuckets
  User: arn:aws:sts::123456789012:assumed-role/cross-account-admin
  Source IP: 198.51.100.45

[2025-12-30T03:44:00Z] GetObject
  User: arn:aws:sts::123456789012:assumed-role/cross-account-admin
  Source IP: 198.51.100.45
  Bucket: sensitive-data-bucket

[2025-12-30T03:45:00Z] CreateAccessKey
  User: arn:aws:iam::123456789012:user/admin
  Source IP: 198.51.100.45

[!] ALERT: Unusual API activity from IP 198.51.100.45
[!] Pattern suggests credential compromise and data access`;
    }
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail enable ")) {
    const trailName = lowerCmd.replace("aws cloudtrail enable ", "").trim();
    const trail = resources.find(r => r.type === 'cloudtrail' && r.name === trailName);
    if (trail && trail.isVulnerable) {
      await storage.updateResource(trail.id, { isVulnerable: false, status: 'enabled' });
      output = `[SUCCESS] CloudTrail ${trailName} enabled\n  - Logging to S3 bucket\n  - Management events: All\n  - Data events: S3, Lambda`;
      success = true;
      const remaining = resources.filter(r => r.id !== trail.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Trail ${trailName} not found or already enabled.`;
    }
  }
  // GuardDuty Commands
  else if (lowerCmd === "aws guardduty get-findings") {
    const ec2 = resources.find(r => r.type === 'ec2' && r.isVulnerable);
    if (ec2) {
      const config = ec2.config as any;
      output = `=== GuardDuty Findings ===\n\nFinding Type: CryptoCurrency:EC2/BitcoinTool.B!DNS\nSeverity: HIGH\n\nAffected Resource:\n  Instance: ${ec2.name}\n  ${config.mining ? `Mining Pool: ${config.pool}` : ''}\n\nDescription:\nThis EC2 instance is querying a domain name associated with Bitcoin or other cryptocurrency mining activity.\n\n[!] Recommendation: Isolate the instance immediately.`;
    } else {
      output = "No GuardDuty findings for this lab.";
    }
  }
  // SSM Commands
  else if (lowerCmd === "aws ssm list-sessions") {
    const session = resources.find(r => r.type === 'ssm_session');
    if (session) {
      const config = session.config as any;
      output = `=== Active SSM Sessions ===\n\nSession ID: ${session.name}\n  Source IP: ${config.sourceIP}\n  User: ${config.user}\n  Status: ${session.status}\n\n[!] WARNING: Session originated from suspicious IP address`;
    } else {
      output = "No active SSM sessions.";
    }
  }
  else if (lowerCmd.startsWith("aws ssm terminate ")) {
    const sessionName = lowerCmd.replace("aws ssm terminate ", "").trim();
    const session = resources.find(r => r.type === 'ssm_session' && r.name === sessionName);
    if (session && session.isVulnerable) {
      await storage.updateResource(session.id, { isVulnerable: false, status: 'terminated' });
      output = `[SUCCESS] SSM session ${sessionName} terminated\n  - Connection forcefully closed\n  - Session logged for investigation`;
      success = true;
      const remaining = resources.filter(r => r.id !== session.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Threat contained!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Session ${sessionName} not found or already terminated.`;
    }
  }
  // KMS Diagnostic Commands
  else if (lowerCmd.startsWith("aws kms describe-key ")) {
    const keyName = lowerCmd.replace("aws kms describe-key ", "").trim();
    const key = resources.find(r => r.type === 'kms_key' && r.name === keyName);
    if (key) {
      const config = key.config as any;
      output = `=== KMS Key: ${keyName} ===\n\nStatus: ${key.isVulnerable ? 'PENDING DELETION' : 'ENABLED'}\n${config.deletionDate ? `Deletion Date: ${config.deletionDate}` : ''}\n${key.isVulnerable ? '\n[!] CRITICAL: Key will be deleted - all encrypted data will be lost' : '\n[OK] Key is active'}`;
    } else {
      output = `Error: Key ${keyName} not found.`;
    }
  }
  // KMS Commands
  else if (lowerCmd.startsWith("aws kms cancel-deletion ")) {
    const keyName = lowerCmd.replace("aws kms cancel-deletion ", "").trim();
    const key = resources.find(r => r.type === 'kms_key' && r.name === keyName);
    if (key && key.isVulnerable) {
      await storage.updateResource(key.id, { isVulnerable: false, status: 'enabled' });
      output = `[SUCCESS] Key deletion cancelled for ${keyName}\n  - Key is now enabled\n  - All encrypted data remains accessible`;
      success = true;
      const remaining = resources.filter(r => r.id !== key.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Key ${keyName} not found or not pending deletion.`;
    }
  }
  // EventBridge Diagnostic Commands
  else if (lowerCmd.startsWith("aws events describe-rule ")) {
    const ruleName = lowerCmd.replace("aws events describe-rule ", "").trim();
    const rule = resources.find(r => r.type === 'eventbridge_rule' && r.name === ruleName);
    if (rule) {
      const config = rule.config as any;
      output = `=== EventBridge Rule: ${ruleName} ===\n\nEvent Pattern: ${config.pattern}\nTarget: ${config.target}\n\n[!] CRITICAL: This rule triggers on security-related events and invokes a suspicious Lambda function`;
    } else {
      output = `Error: Rule ${ruleName} not found.`;
    }
  }
  // EventBridge Commands
  else if (lowerCmd.startsWith("aws events delete-rule ")) {
    const ruleName = lowerCmd.replace("aws events delete-rule ", "").trim();
    const rule = resources.find(r => r.type === 'eventbridge_rule' && r.name === ruleName);
    if (rule && rule.isVulnerable) {
      await storage.updateResource(rule.id, { isVulnerable: false, status: 'deleted' });
      output = `[SUCCESS] EventBridge rule ${ruleName} deleted\n  - Persistence mechanism removed\n  - Associated targets detached`;
      success = true;
      const remaining = resources.filter(r => r.id !== rule.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Persistence mechanism eliminated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Rule ${ruleName} not found or already deleted.`;
    }
  }
  // DataSync Diagnostic Commands
  else if (lowerCmd.startsWith("aws datasync describe-task ")) {
    const taskName = lowerCmd.replace("aws datasync describe-task ", "").trim();
    const task = resources.find(r => r.type === 'datasync_task' && r.name === taskName);
    if (task) {
      const config = task.config as any;
      output = `=== DataSync Task: ${taskName} ===\n\nDestination: ${config.destination}\nStatus: ${config.status}\nData Transferred: 2.4 TB\n\n[!] CRITICAL: Large data transfer to external location detected`;
    } else {
      output = `Error: Task ${taskName} not found.`;
    }
  }
  // DataSync Commands
  else if (lowerCmd.startsWith("aws datasync stop-task ")) {
    const taskName = lowerCmd.replace("aws datasync stop-task ", "").trim();
    const task = resources.find(r => r.type === 'datasync_task' && r.name === taskName);
    if (task && task.isVulnerable) {
      await storage.updateResource(task.id, { isVulnerable: false, status: 'stopped' });
      output = `[SUCCESS] DataSync task ${taskName} stopped\n  - Data transfer halted\n  - Exfiltration prevented`;
      success = true;
      const remaining = resources.filter(r => r.id !== task.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Data exfiltration stopped!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Error: Task ${taskName} not found or already stopped.`;
    }
  }
  // ============= SOC SIMULATION COMMANDS =============
  // SIEM Commands
  else if (lowerCmd === "siem connect" || lowerCmd === "siem login") {
    output = `=== SIEM Console Connection ===

[OK] Authenticating to CloudShield SIEM...
[OK] Loading user profile: soc-analyst-01
[OK] Fetching dashboard configuration...
[OK] Synchronizing alert queue...

Connected to SIEM Dashboard
  Workspace: Production SOC
  Role: Tier 1 Analyst
  Alert Queue: 5 pending alerts
  Last Login: ${new Date(Date.now() - 86400000).toISOString()}

Quick Actions:
  siem list-rules     - View detection rules
  siem alerts         - View alert queue
  siem list-sources   - Check log sources`;
    success = true;
  }
  else if (lowerCmd === "siem list-rules" || lowerCmd === "siem rules") {
    output = `=== Detection Rules ===

ACTIVE RULES (12):
  [CRIT] R001 | Unauthorized Root Login
         Trigger: root console login from new IP
         Last Hit: 2h ago | Hits (24h): 3
         
  [HIGH] R002 | Failed Login Spike
         Trigger: >5 failed logins in 5 minutes
         Last Hit: 15m ago | Hits (24h): 7
         
  [HIGH] R003 | S3 Public Access Enabled
         Trigger: bucket ACL set to public
         Last Hit: 1d ago | Hits (24h): 1
         
  [MED]  R004 | Security Group Modified
         Trigger: 0.0.0.0/0 ingress rule added
         Last Hit: 3h ago | Hits (24h): 4
         
  [MED]  R005 | IAM Policy Attached
         Trigger: Admin policy attached to user
         Last Hit: 6h ago | Hits (24h): 2

  ... and 7 more rules

Commands:
  siem create-rule <name>  - Create new detection rule
  siem test-rule <name>    - Test rule against historical data`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem create-rule ")) {
    const ruleName = lowerCmd.replace("siem create-rule ", "").trim();
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_rules' || r.type === 'siem_alert' || r.type === 'siem_alerts') && r.isVulnerable);
    if (siemRes) {
      await storage.updateResource(siemRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Creating Detection Rule: ${ruleName} ===

[OK] Rule template initialized
[OK] Setting trigger conditions...
[OK] Configuring alert severity: HIGH
[OK] Adding MITRE ATT&CK mapping: T1110

Rule Created Successfully:
  Name: ${ruleName}
  Status: ACTIVE
  Severity: HIGH
  
Trigger Conditions:
  - Event type: Failed authentication
  - Threshold: 5+ events
  - Time window: 5 minutes
  - Source: Any
  
Actions:
  - Generate alert
  - Notify SOC queue
  - Log to audit trail

Rule is now monitoring for matches.`;
      success = true;
      const remaining = resources.filter(r => r.id !== siemRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Detection rule "${ruleName}" created and active.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("siem test-rule ")) {
    const ruleName = lowerCmd.replace("siem test-rule ", "").trim().split(" ")[0];
    output = `=== Testing Rule: ${ruleName} ===

Running against historical data (30 days)...

Results:
  Total Matches: 147
  True Positives: 89 (60.5%)
  False Positives: 58 (39.5%)
  
Sample Matches:
  [MATCH] 2024-01-15 03:22:15 - 8 failed logins from 45.33.22.11
  [MATCH] 2024-01-14 14:55:02 - 12 failed logins from 192.168.1.50
  [MATCH] 2024-01-12 22:10:33 - 6 failed logins from 10.0.0.15

Recommendations:
  - Consider increasing threshold to reduce false positives
  - Add IP whitelist for internal testing systems
  - Enable account lockout correlation`;
    success = true;
  }
  else if (lowerCmd === "siem show-alerts --status pending" || lowerCmd === "siem pending-alerts") {
    output = `=== Pending Alerts ===

[CRIT] ALT-001 | API Key Abuse | 2m ago
[HIGH] ALT-002 | S3 Policy Change | 5m ago  
[HIGH] ALT-003 | EC2 Cryptomining | 10m ago
[MED]  ALT-004 | Brute Force | 15m ago
[MED]  ALT-005 | SG Rule Added | 20m ago

Total Pending: 5 | Avg Age: 10.4 minutes
SLA Status: 4 within SLA, 1 approaching breach`;
    success = true;
  }
  else if (lowerCmd === "siem show-severity-config" || lowerCmd === "siem severity-config") {
    output = `=== Severity Configuration ===

CRITICAL:
  SLA: 15 minutes
  Notification: PagerDuty + Slack + Email
  Auto-escalate: After 10 minutes
  
HIGH:
  SLA: 1 hour
  Notification: Slack + Email
  Auto-escalate: After 45 minutes
  
MEDIUM:
  SLA: 4 hours
  Notification: Email
  Auto-escalate: After 3 hours
  
LOW:
  SLA: 24 hours
  Notification: Daily digest
  Auto-escalate: Never`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem fix-severity ") || lowerCmd === "siem configure-alert-severity") {
    const alertRes = resources.find(r => (r.type === 'alert_config' || r.type === 'siem_alert' || r.type === 'siem_alerts' || r.type === 'siem') && r.isVulnerable);
    if (alertRes) {
      await storage.updateResource(alertRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Severity Configuration Updated ===

[OK] Critical alerts: PagerDuty notification enabled
[OK] High alerts: 1-hour SLA enforced
[OK] Auto-escalation rules configured
[OK] Notification channels verified

Severity matrix aligned with incident response playbook.`;
      success = true;
      const remaining = resources.filter(r => r.id !== alertRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Severity configuration updated.`;
      success = true;
    }
  }
  else if (lowerCmd === "siem configure-alert-routing" || lowerCmd.startsWith("siem configure-alert-routing ")) {
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_config' || r.type === 'alerts' || r.type === 'logs' || r.name?.includes('siem') || r.name?.includes('log')) && r.isVulnerable);
    if (siemRes) {
      await storage.updateResource(siemRes.id, { isVulnerable: false, status: 'configured' });
      output = `=== Alert Routing Configuration ===

[OK] Critical -> Tier 2 + On-call (PagerDuty)
[OK] High -> Tier 1 Queue (15 min SLA)
[OK] Medium -> Tier 1 Queue (batched, 1 hour)
[OK] Low -> Daily Review Queue
[OK] Per-tenant routing configured
[OK] SLA tracking enabled
[OK] Escalation paths defined

Alert routing configuration complete.`;
      success = true;
      const remaining = resources.filter(r => r.id !== siemRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] SIEM integration complete!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== Alert Routing Configuration ===

[OK] Critical -> Tier 2 + On-call
[OK] High -> Tier 1 Queue
[OK] Medium -> Tier 1 Queue (batched)
[OK] Low -> Daily Review Queue

Alert routing configuration complete.`;
      success = true;
    }
  }
  else if (lowerCmd === "siem create-detection-rules") {
    output = `=== Detection Rules Created ===

Created 15 detection rules mapped to MITRE ATT&CK:

Initial Access:
  [OK] T1078 - Valid Accounts (Unusual login location)
  [OK] T1190 - Exploit Public-Facing Application
  
Persistence:
  [OK] T1098 - Account Manipulation
  [OK] T1136 - Create Account
  
Privilege Escalation:
  [OK] T1484 - Domain Policy Modification
  
Defense Evasion:
  [OK] T1562 - Impair Defenses (CloudTrail disabled)
  
Credential Access:
  [OK] T1110 - Brute Force
  [OK] T1552 - Unsecured Credentials
  
Exfiltration:
  [OK] T1537 - Transfer Data to Cloud Account
  
All rules are now active and monitoring.`;
    success = true;
  }
  else if (lowerCmd === "siem create-investigation-dashboards") {
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_config' || r.type === 'logs' || r.name?.includes('siem') || r.name?.includes('log')) && r.isVulnerable);
    if (siemRes) {
      await storage.updateResource(siemRes.id, { isVulnerable: false, status: 'configured' });
      output = `=== Investigation Dashboards Created ===

[OK] SOC Overview Dashboard
     - Alert volume trends
     - MTTR metrics
     - Analyst workload
     
[OK] Threat Hunting Dashboard
     - Anomaly detection
     - IOC matches
     - Behavioral analytics
     
[OK] Incident Timeline Dashboard
     - Event correlation view
     - Attack chain visualization
     - Evidence collection

[OK] Compliance Dashboard
     - SLA adherence
     - Alert closure rates
     - False positive trends

Dashboards available in SIEM console.`;
      success = true;
      const remaining = resources.filter(r => r.id !== siemRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] SIEM integration complete!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== Investigation Dashboards Created ===

[OK] SOC Overview Dashboard
[OK] Threat Hunting Dashboard
[OK] Incident Timeline Dashboard
[OK] Compliance Dashboard

Dashboards available in SIEM console.`;
      success = true;
    }
  }
  else if (lowerCmd === "siem tune-detection-rules") {
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_config' || r.type === 'logs' || r.name?.includes('siem') || r.name?.includes('log')) && r.isVulnerable);
    if (siemRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'tuned' });
      }
      output = `=== Detection Rule Tuning Complete ===

Analyzing alert patterns from past 30 days...

Tuning Applied:
  [OK] R002 - Threshold adjusted (5 -> 10 failed logins)
  [OK] R004 - Exclusion added for admin IPs
  [OK] R007 - Time window optimized (1h -> 15m)
  [OK] R011 - Baseline updated for traffic patterns
  [OK] R015 - False positive patterns excluded

Results:
  Rules tuned: 8
  False positive reduction: 35%
  Detection coverage: Maintained
  Alert quality: Significantly improved`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] SIEM tuning complete!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Detection Rule Tuning ===

Tuning Recommendations Applied:
  [OK] R002 - Increased threshold
  [OK] R004 - Added exclusions
  [OK] R007 - Reduced time window
       
Results:
  Rules tuned: 8
  Expected FP reduction: 35%`;
      success = true;
    }
  }
  else if (lowerCmd === "siem analyze-attack-coverage" || lowerCmd === "siem attack-coverage") {
    output = `=== MITRE ATT&CK Coverage Analysis ===

Tactics Coverage:
  Initial Access:       ████████░░ 80%
  Execution:            ██████░░░░ 60%
  Persistence:          █████████░ 90%
  Privilege Escalation: ████████░░ 80%
  Defense Evasion:      ██████░░░░ 60%
  Credential Access:    █████████░ 90%
  Discovery:            ████░░░░░░ 40%
  Lateral Movement:     █████░░░░░ 50%
  Collection:           ████░░░░░░ 40%
  Exfiltration:         ████████░░ 80%
  Impact:               ███████░░░ 70%

Overall Coverage: 67%

Gaps Identified:
  [!] T1046 - Network Service Scanning (no VPC flow analysis)
  [!] T1087 - Account Discovery (limited IAM monitoring)
  [!] T1083 - File and Directory Discovery (no endpoint agent)`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem correlate-logs ")) {
    output = `=== Log Correlation Results ===

Correlated Events (Last 24h):
  CloudTrail + VPC Flow Logs + CloudWatch

Timeline:
  [03:15:22] Suspicious API call from 198.51.100.45
  [03:15:24] VPC flow: Connection to 10.0.1.50:22
  [03:15:30] CloudWatch: CPU spike on i-0abc123
  [03:15:45] API: DescribeInstances from same IP
  [03:16:02] VPC flow: Outbound 443 to external IP

Correlation Analysis:
  Pattern: Reconnaissance -> Access -> Execution
  Confidence: 87%
  MITRE Chain: T1595 -> T1190 -> T1059

Recommended Actions:
  1. Isolate affected instance
  2. Block source IP
  3. Review compromised credentials`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem analyze-pattern ")) {
    const pattern = lowerCmd.replace("siem analyze-pattern ", "").trim();
    output = `=== Pattern Analysis: ${pattern} ===

Pattern detected in last 7 days:
  Occurrences: 23
  Affected Resources: 8
  Success Rate: 35%

Behavioral Indicators:
  - Unusual timing (off-hours activity)
  - Geographic anomalies
  - Privilege escalation attempts
  
Associated MITRE Techniques:
  T1021 - Remote Services
  T1570 - Lateral Tool Transfer
  T1018 - Remote System Discovery

Risk Assessment: HIGH
Recommendation: Implement network segmentation`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem create-correlation ")) {
    const chainName = lowerCmd.replace("siem create-correlation ", "").trim();
    output = `=== Correlation Rule Created: ${chainName} ===

[OK] Rule ${chainName} created
[OK] Event chain configured
[OK] Time window: 5 minutes (default)
[OK] Severity: HIGH

Use 'siem set-window ${chainName} <seconds>' to adjust timing.
Use 'siem add-chain-event ${chainName} <event>' to add events.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem set-window ")) {
    const parts = lowerCmd.replace("siem set-window ", "").trim().split(" ");
    output = `=== Time Window Updated ===

Correlation: ${parts[0]}
New Window: ${parts[1] || '300s'}

Configuration applied.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem add-chain-event ")) {
    const parts = lowerCmd.replace("siem add-chain-event ", "").trim().split(" ");
    output = `=== Chain Event Added ===

Correlation: ${parts[0]}
Added Event: ${parts[1] || 'event'}

Chain now monitors for this event sequence.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem generate-triage-report") || lowerCmd === "siem triage-report") {
    output = `=== Triage Report Generated ===

Report ID: TR-${Date.now().toString(36).toUpperCase()}
Generated: ${new Date().toISOString()}

Summary:
  Total Alerts Analyzed: 47
  Confirmed Incidents: 3
  False Positives: 12
  Pending Review: 32

Key Findings:
  1. Credential compromise detected (P1)
  2. Data exfiltration attempt blocked
  3. Cryptomining on EC2 instance

Report exported to: /reports/triage-${new Date().toISOString().split('T')[0]}.pdf`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem investigate-alert ")) {
    const alertId = lowerCmd.replace("siem investigate-alert ", "").trim();
    output = `=== Alert Investigation: ${alertId} ===

Status: Under Investigation
Analyst: Current User
Started: ${new Date().toISOString()}

Evidence Collected:
  - CloudTrail logs (47 events)
  - VPC Flow logs (1,234 flows)
  - GuardDuty findings (2 related)

Timeline constructed. See 'siem gather-related-alerts' for context.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem gather-related-alerts")) {
    output = `=== Related Alerts ===

Primary Alert: ALT-001
Time Window: ±30 minutes

Related Alerts Found (3):
  [HIGH] ALT-007 - Same source IP
  [MED]  ALT-012 - Same target resource
  [MED]  ALT-015 - Same user account

Correlation Score: 89%
Attack Chain Probability: HIGH`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem validate-alert ")) {
    const parts = lowerCmd.replace("siem validate-alert ", "").trim();
    output = `=== Alert Validation ===

Alert validated as: FALSE POSITIVE
Reason: Normal automation activity
Analyst: Current User

[OK] Alert closed
[OK] Tuning recommendation created
[OK] Similar future alerts will be auto-suppressed`;
    success = true;
  }
  // Multi-tenant SIEM commands
  else if (lowerCmd === "siem design-tenant-schema") {
    output = `=== Multi-Tenant Schema Design ===

[OK] Tenant isolation model: Index-per-tenant
[OK] Naming convention: {tenant_id}_{log_type}_{date}
[OK] Retention policy: Per-tenant configurable
[OK] Access control: RBAC with tenant scoping

Schema ready for implementation.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem configure-isolation ")) {
    output = `=== Data Isolation Configured ===

[OK] Index-level isolation enabled
[OK] Query filters enforced
[OK] Cross-tenant queries blocked
[OK] Audit logging for all access

Data isolation verified.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem configure-rbac ")) {
    output = `=== RBAC Configuration ===

[OK] Tenant admin role created
[OK] Tenant analyst role created
[OK] Tenant viewer role created
[OK] Permission boundaries enforced

Role-based access control active.`;
    success = true;
  }
  else if (lowerCmd === "siem create-tenant-dashboards") {
    output = `=== Tenant Dashboards Created ===

[OK] Tenant overview dashboard
[OK] Tenant security posture
[OK] Tenant-specific alerts
[OK] Custom report templates

Dashboards available per tenant.`;
    success = true;
  }
  else if (lowerCmd === "siem configure-rate-limits") {
    output = `=== Rate Limits Configured ===

[OK] Query rate: 100/minute per tenant
[OK] Ingestion rate: 10,000 events/second
[OK] Storage quota: Per-tenant limits
[OK] Alert throttling: Enabled

Noisy neighbor protection active.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem onboard-tenant ")) {
    const tenant = lowerCmd.replace("siem onboard-tenant ", "").trim();
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_config' || r.type === 'siemCluster' || r.name?.includes('siem') || r.name?.includes('tenant')) && r.isVulnerable);
    if (siemRes) {
      await storage.updateResource(siemRes.id, { isVulnerable: false, status: 'onboarded' });
      output = `=== Tenant Onboarded: ${tenant} ===

[OK] Tenant ID created: ${tenant}
[OK] Dedicated indexes provisioned
[OK] RBAC roles configured
[OK] Tenant dashboards deployed
[OK] Alert routing configured
[OK] Welcome email sent

Tenant ${tenant} is ready for log ingestion.`;
      success = true;
      const remaining = resources.filter(r => r.id !== siemRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Tenant onboarding complete!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== Tenant Onboarded: ${tenant} ===

[OK] Tenant ID created: ${tenant}
[OK] Indexes provisioned
[OK] RBAC configured
[OK] Dashboards deployed
[OK] Welcome email sent

Tenant ${tenant} is ready for log ingestion.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("siem test-isolation ")) {
    const tenant = lowerCmd.replace("siem test-isolation ", "").trim();
    const siemRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_config' || r.type === 'siemCluster' || r.name?.includes('siem') || r.name?.includes('cluster')) && r.isVulnerable);
    if (siemRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'verified' });
      }
      output = `=== Isolation Test: ${tenant} ===

Running cross-tenant access tests...

[PASS] Direct query blocked: tenant-b indexes
[PASS] API access denied: other tenant data
[PASS] Dashboard isolation verified
[PASS] Search results filtered correctly
[PASS] Alert routing isolated
[PASS] No data leakage detected

All isolation tests passed for ${tenant}.
Multi-tenant architecture validated.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Multi-tenant SIEM architecture complete!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Isolation Test: ${tenant} ===

Running cross-tenant access tests...

[PASS] Direct query blocked: tenant-b indexes
[PASS] API access denied: other tenant data
[PASS] Dashboard isolation verified
[PASS] Search results filtered correctly

All isolation tests passed for ${tenant}.`;
      success = true;
    }
  }
  // Alert tuning commands
  else if (lowerCmd.startsWith("siem sample-alerts ")) {
    output = `=== Alert Samples ===

Sampling 20 alerts from rule...

Sample Results:
  True Positives: 8 (40%)
  False Positives: 12 (60%)
  
Common False Positive Patterns:
  - Automated backup processes
  - CI/CD pipeline activity
  - Monitoring health checks

Recommendation: Create exclusions for known-good patterns.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem analyze-alert-pattern ")) {
    output = `=== Alert Pattern Analysis ===

Analyzing false positive patterns...

Identified Patterns:
  1. Service account automation (45%)
  2. Scheduled tasks (30%)
  3. Monitoring systems (25%)

Suggested Exclusions:
  - Source: svc-automation@company.com
  - Time: 02:00-04:00 (maintenance window)
  - IP: Internal monitoring subnet`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem identify-exclusions ")) {
    output = `=== Exclusion Candidates ===

Based on historical analysis:

Recommended Exclusions:
  [1] Source IP: 10.0.0.0/8 (internal network)
      Reduction: ~35% false positives
      
  [2] User: svc-* (service accounts)
      Reduction: ~25% false positives
      
  [3] Time: Maintenance windows
      Reduction: ~15% false positives

Total expected FP reduction: 60%`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem create-tuning-proposal ")) {
    output = `=== Tuning Proposal Created ===

Proposal ID: TP-${Date.now().toString(36).toUpperCase()}

Changes:
  - Add 3 exclusion patterns
  - Increase threshold from 5 to 10
  - Add time-based suppression

Expected Impact:
  - FP reduction: 60%
  - Detection rate: Maintained
  
Use 'siem deploy-tuning <rule>' to apply.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem deploy-tuning ")) {
    const ruleName = lowerCmd.replace("siem deploy-tuning ", "").trim();
    output = `=== Tuning Deployed: ${ruleName} ===

[OK] Exclusion patterns applied
[OK] Thresholds updated
[OK] Rule recompiled
[OK] Historical validation passed

Tuning is now active.`;
    success = true;
  }
  else if (lowerCmd === "siem list-sources" || lowerCmd === "siem list source" || lowerCmd === "siem sources") {
    output = `=== Integrated Log Sources ===

CONNECTED:
  [OK] CloudTrail         - AWS API activity logs
  [OK] GuardDuty          - Threat detection findings
  [OK] VPC Flow Logs      - Network traffic metadata
  [OK] AWS Config         - Resource configuration changes

NOT INTEGRATED:
  [!] Firewall Logs       - Perimeter traffic not visible
  [!] Endpoint Logs       - Host-based detection limited
  [!] Application Logs    - Business logic events missing

Coverage Analysis:
  Cloud API Activity:    100%
  Network Visibility:     60%
  Endpoint Visibility:    20%
  Application Layer:       0%

[!] RECOMMENDATION: Add missing log sources to improve detection coverage.
    Use 'siem add-source <source-name>' to integrate.`;
    success = true;
  }
  else if (lowerCmd === "siem list-alerts" || lowerCmd === "siem alerts") {
    output = `=== SIEM Alert Queue ===
    
[CRITICAL] ALT-001 | Unauthorized API Key Usage Detected
  Source: CloudTrail | IP: 198.51.100.45 | Status: NEW
  MITRE: T1552 (Credential Access)
  
[HIGH] ALT-002 | S3 Bucket Policy Modified  
  Source: AWS Config | Status: NEW
  MITRE: T1567 (Exfiltration)

[HIGH] ALT-003 | Unusual EC2 Instance Launch
  Source: GuardDuty | IP: 10.0.1.50 | Status: INVESTIGATING
  MITRE: T1496 (Resource Hijacking)

[MEDIUM] ALT-004 | Failed Login Attempts Spike
  Source: IAM | IP: 203.0.113.100 | Status: NEW
  MITRE: T1110 (Brute Force)

[MEDIUM] ALT-005 | Security Group Rule Added
  Source: VPC Flow Logs | Status: NEW
  MITRE: T1098 (Account Manipulation)

Total: 5 alerts | Critical: 1 | High: 2 | Medium: 2

Type 'siem triage <alert-id>' to begin investigation`;
  }
  else if (lowerCmd.startsWith("siem triage ") || lowerCmd.startsWith("siem investigate ")) {
    const alertId = lowerCmd.replace("siem triage ", "").replace("siem investigate ", "").trim().toUpperCase();
    output = `=== Alert Investigation: ${alertId} ===

Alert Details:
  Severity: HIGH
  First Seen: ${new Date(Date.now() - 300000).toISOString()}
  Last Updated: ${new Date().toISOString()}
  Status: INVESTIGATING (updated)

Event Timeline:
  [08:23:15] Initial detection - Anomalous API pattern
  [08:23:45] Correlation - Similar activity from same IP
  [08:24:02] Enrichment - IP reputation: MALICIOUS (Tor exit)
  [08:24:30] Context - User has no prior activity from this IP

Recommended Actions:
  1. siem enrich ${alertId}     - Get threat intel enrichment
  2. logs search ip:198.51.100.45  - Search related logs
  3. siem escalate ${alertId}  - Escalate to Tier 2
  4. siem close ${alertId}     - Close with resolution

[!] Alert status updated to INVESTIGATING`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem enrich ")) {
    const alertId = lowerCmd.replace("siem enrich ", "").trim().toUpperCase();
    output = `=== Threat Intelligence Enrichment: ${alertId} ===

IP Analysis: 198.51.100.45
  Reputation: MALICIOUS
  Category: Tor Exit Node
  First Seen: 2024-06-15
  Reports: 1,247 abuse reports
  
ASN Information:
  AS: AS12345 - CloudProvider Inc.
  Country: Netherlands
  
Related IOCs:
  - Associated with APT-29 campaigns
  - Previously used in credential theft
  - Known C2 communication endpoint

MITRE ATT&CK Mapping:
  T1078 - Valid Accounts
  T1552 - Unsecured Credentials
  T1071 - Application Layer Protocol

Recommendation: HIGH CONFIDENCE malicious activity`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem escalate ")) {
    const alertId = lowerCmd.replace("siem escalate ", "").trim().toUpperCase();
    const alertRes = resources.find(r => r.type === 'siem_alert');
    if (alertRes && alertRes.isVulnerable) {
      await storage.updateResource(alertRes.id, { isVulnerable: false, status: 'escalated' });
      output = `[SUCCESS] Alert ${alertId} escalated to Tier 2

Escalation Details:
  Assigned To: Senior Analyst
  Priority: P1 - Critical
  SLA: 30 minutes
  
Notification sent to:
  - SOC Manager
  - Incident Response Team
  - Security Operations Slack channel

Next Steps:
  - Continue monitoring for related activity
  - Document findings in incident notes
  - Await Tier 2 response`;
      success = true;
      const remaining = resources.filter(r => r.id !== alertRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Alert properly escalated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Alert ${alertId} escalated to Tier 2 for further analysis.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("siem close ")) {
    const parts = lowerCmd.replace("siem close ", "").trim().split(" ");
    const alertId = parts[0].toUpperCase();
    const resolution = parts.slice(1).join(" ") || "Resolved";
    const alertRes = resources.find(r => r.type === 'siem_alert');
    if (alertRes && alertRes.isVulnerable) {
      await storage.updateResource(alertRes.id, { isVulnerable: false, status: 'closed' });
      output = `[SUCCESS] Alert ${alertId} closed

Resolution: ${resolution}
Closed By: ${userId}
Closed At: ${new Date().toISOString()}

Alert archived for compliance retention.`;
      success = true;
      const remaining = resources.filter(r => r.id !== alertRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All alerts resolved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Alert ${alertId} closed successfully.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("siem classify ")) {
    const parts = lowerCmd.replace("siem classify ", "").trim().split(" ");
    const alertId = parts[0].toUpperCase();
    const classification = parts[1] || "true-positive";
    output = `[SUCCESS] Alert ${alertId} classified as: ${classification.toUpperCase()}

Classification Options:
  true-positive  - Confirmed malicious activity
  false-positive - Benign activity incorrectly flagged
  benign         - Known safe activity
  suspicious     - Requires further investigation

Alert classification recorded for ML model training.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem add-source ")) {
    const sourceName = lowerCmd.replace("siem add-source ", "").trim();
    const siemRes = resources.find(r => (r.type === 'siem_config' || r.type === 'siem_alert' || r.type === 'log_source') && r.name.includes(sourceName.split('-')[0])) 
      || resources.find(r => r.type === 'siem_config' || r.type === 'siem_alert' || r.type === 'log_source');
    if (siemRes && siemRes.isVulnerable) {
      await storage.updateResource(siemRes.id, { isVulnerable: false, status: 'configured' });
      output = `[SUCCESS] Log source "${sourceName}" integrated with SIEM

Configuration:
  Source Type: ${sourceName}
  Parser: Auto-detected
  Normalization: Enabled
  Indexing: Real-time

Log Categories Enabled:
  - Connection events
  - Blocked traffic
  - Policy violations
  - Threat detections

[i] Log correlation now active for ${sourceName}. Alerts will be generated based on cross-source analysis.`;
      success = true;
      const remaining = resources.filter(r => r.id !== siemRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] SIEM integration complete!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Log source "${sourceName}" added to SIEM

Source Status: CONNECTED
Events Received: Streaming...
Parser: Auto-configured`;
      success = true;
    }
  }
  // Log Search Commands
  else if (lowerCmd.startsWith("logs search ")) {
    const query = lowerCmd.replace("logs search ", "").trim();
    output = `=== Log Search Results: "${query}" ===

Found 47 matching events in last 24 hours:

[2025-01-15T08:23:15Z] cloudtrail | AssumeRole
  user: compromised-user | ip: 198.51.100.45
  role: arn:aws:iam::123456789012:role/AdminAccess
  
[2025-01-15T08:23:45Z] cloudtrail | CreateAccessKey
  user: compromised-user | ip: 198.51.100.45
  target: backdoor-user
  
[2025-01-15T08:24:02Z] vpc-flowlogs | ACCEPT
  src: 198.51.100.45 | dst: 10.0.1.50 | port: 443
  bytes: 15234
  
[2025-01-15T08:24:30Z] guardduty | UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
  ip: 198.51.100.45 | severity: HIGH

... and 43 more events

Tip: Use 'logs export ${query}' to download full results`;
    success = true;
  }
  else if (lowerCmd === "logs recent" || lowerCmd === "logs tail") {
    output = `=== Recent Log Events ===

[${new Date(Date.now() - 30000).toISOString()}] ERROR cloudtrail
  DeleteTrail API called by user 'unknown-admin'
  
[${new Date(Date.now() - 60000).toISOString()}] WARN guardduty
  CryptoMining DNS request detected from i-0abc123
  
[${new Date(Date.now() - 90000).toISOString()}] WARN vpc-flow
  Unusual outbound traffic volume detected (2.4GB/hr)
  
[${new Date(Date.now() - 120000).toISOString()}] INFO iam
  AssumeRole successful for role 'AdminAccess'
  
[${new Date(Date.now() - 150000).toISOString()}] INFO s3
  GetBucketAcl called on 'prod-data-bucket'

Showing last 5 events. Use 'logs search <query>' for filtered results.`;
  }
  // Endpoint Commands
  else if (lowerCmd === "endpoint list" || lowerCmd === "endpoints") {
    output = `=== Monitored Endpoints ===

Hostname           Status      Last Check    Alerts
---------          ------      ----------    ------
web-server-01      NORMAL      2m ago        0
web-server-02      NORMAL      2m ago        0
web-server-03      CRITICAL    1m ago        3
db-server-01       NORMAL      3m ago        0
app-server-02      SUSPICIOUS  5m ago        1
bastion-01         NORMAL      1m ago        0

Total: 6 endpoints | 1 Critical | 1 Suspicious

Type 'endpoint status <hostname>' for details`;
  }
  else if (lowerCmd.startsWith("endpoint status ")) {
    const hostname = lowerCmd.replace("endpoint status ", "").trim();
    const isCritical = hostname.includes("03") || hostname.includes("compromised");
    
    if (isCritical) {
      output = `=== Endpoint Status: ${hostname} ===

Status: CRITICAL
Agent: Online
Last Heartbeat: ${new Date().toISOString()}

Active Alerts:
  [CRITICAL] Crypto mining process detected
  [HIGH] Outbound connection to known C2
  [MEDIUM] Unauthorized process execution

Recent Process Activity:
  PID 4521 | xmrig       | www-data | MALICIOUS
  PID 4520 | curl        | www-data | SUSPICIOUS
  PID 4519 | bash        | www-data | NORMAL

Recommended: Isolate this endpoint immediately
Command: aws ec2 isolate ${hostname}`;
    } else {
      output = `=== Endpoint Status: ${hostname} ===

Status: NORMAL
Agent: Online
Last Heartbeat: ${new Date().toISOString()}

No active alerts.

Recent Activity:
  - Standard application processes running
  - No suspicious network connections
  - All security controls active`;
    }
    success = true;
  }
  else if (lowerCmd.startsWith("endpoint isolate ")) {
    const hostname = lowerCmd.replace("endpoint isolate ", "").trim();
    const ec2 = resources.find(r => r.type === 'ec2' && r.name === hostname);
    if (ec2 && ec2.isVulnerable) {
      await storage.updateResource(ec2.id, { isVulnerable: false, status: 'isolated' });
      output = `[SUCCESS] Endpoint ${hostname} isolated

Actions Taken:
  - Security group replaced with isolation-sg
  - All inbound/outbound traffic blocked
  - Instance tagged: "Quarantine=true"
  - Forensic snapshot initiated

The endpoint is now isolated from the network.
Run 'endpoint status ${hostname}' to verify.`;
      success = true;
      const remaining = resources.filter(r => r.id !== ec2.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Threat contained!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `Endpoint ${hostname} isolation initiated.`;
      success = true;
    }
  }
  // Network Commands
  else if (lowerCmd === "network flows" || lowerCmd === "netflow") {
    output = `=== Network Flow Summary ===

Top Talkers (Last Hour):
  10.0.1.50      -> 198.51.100.45   | 2.4GB  | SUSPICIOUS
  10.0.2.100     -> pool.minexmr.com | 156MB  | BLOCKED
  10.0.1.25      -> s3.amazonaws.com | 89MB   | NORMAL

Blocked Connections:
  203.0.113.50   -> 10.0.1.10:3389  | RDP    | DENIED
  198.51.100.45  -> 10.0.1.50:22    | SSH    | DENIED

Anomalies Detected:
  [!] Unusual data volume to external IP
  [!] Connection attempts to crypto mining pool
  
Type 'network investigate <ip>' for IP analysis`;
  }
  else if (lowerCmd.startsWith("network investigate ") || lowerCmd.startsWith("network flows ")) {
    const ip = lowerCmd.replace("network investigate ", "").replace("network flows ", "").trim();
    output = `=== Network Analysis: ${ip} ===

Connection Summary:
  Total Flows: 147
  Bytes In: 45.2 MB
  Bytes Out: 2.4 GB
  First Seen: 08:23:15
  Last Seen: ${new Date().toISOString()}

Top Destination Ports:
  443 (HTTPS)  - 89 connections
  22 (SSH)     - 23 connections
  3333 (Mining) - 35 connections

Geo Location:
  Country: Netherlands
  ISP: Anonymous VPN Provider
  
Threat Intel:
  Reputation: MALICIOUS
  Category: Tor Exit Node / C2

[!] Recommend blocking this IP at firewall level`;
    success = true;
  }
  else if (lowerCmd.startsWith("network block ")) {
    const ip = lowerCmd.replace("network block ", "").trim();
    const sgRes = resources.find(r => r.type === 'security_group' || r.type === 'nacl');
    if (sgRes && sgRes.isVulnerable) {
      await storage.updateResource(sgRes.id, { isVulnerable: false, status: 'blocked' });
      output = `[SUCCESS] IP ${ip} blocked

Firewall Rule Added:
  Action: DENY
  Source: ${ip}/32
  Destination: All internal subnets
  Ports: ALL

Rule propagated to:
  - Network ACLs
  - Security Groups
  - WAF IP Sets`;
      success = true;
      const remaining = resources.filter(r => r.id !== sgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Network threat blocked!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = `IP ${ip} added to block list.`;
      success = true;
    }
  }
  // Incident Documentation Commands
  else if (lowerCmd === "incident create" || lowerCmd === "incident new") {
    output = `=== New Incident Created ===

Incident ID: INC-${Date.now().toString().slice(-6)}
Created: ${new Date().toISOString()}
Status: OPEN
Severity: Pending Classification

Available Commands:
  incident note <text>     - Add investigation note
  incident severity <1-5>  - Set severity level
  incident assign <user>   - Assign to analyst
  incident timeline        - View event timeline
  incident close           - Close incident

[!] Remember to document all investigation steps`;
    success = true;
  }
  else if (lowerCmd.startsWith("incident note ")) {
    const note = lowerCmd.replace("incident note ", "").trim();
    output = `[SUCCESS] Note added to incident

Timestamp: ${new Date().toISOString()}
Author: ${userId}
Note: "${note}"

All notes are timestamped and immutable for audit trail.`;
    success = true;
  }
  else if (lowerCmd === "incident timeline") {
    output = `=== Incident Timeline ===

[08:23:00] DETECTION
  GuardDuty alert triggered
  Severity: HIGH
  
[08:23:15] TRIAGE
  Alert assigned to Tier 1
  Initial classification: True Positive
  
[08:24:00] INVESTIGATION
  IP reputation checked: MALICIOUS
  Related logs identified
  
[08:25:30] CONTAINMENT
  Compromised credentials revoked
  Affected endpoint isolated
  
[08:26:00] ERADICATION
  Malicious processes terminated
  Persistence mechanisms removed
  
[PENDING] RECOVERY
  Awaiting system restoration
  
[PENDING] LESSONS LEARNED
  Post-incident review scheduled`;
  }
  // Report incident command
  else if (lowerCmd === "report incident") {
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    if (cloudtrailRes) {
      output = `=== INCIDENT REPORT ===
Generated: ${new Date().toISOString()}

SUMMARY:
Credential compromise detected for IAM user.
Attacker used compromised credentials to escalate privileges and access data.

TIMELINE:
08:23:15 - CreateAccessKey: Attacker created new access key
08:24:02 - AssumeRole: Escalated to AdminRole
08:25:30 - ListBuckets: Enumerated S3 buckets
08:26:45 - GetObject: Accessed sensitive data bucket

INDICATORS OF COMPROMISE (IOCs):
- Source IP: 185.220.101.42 (Known Tor exit node)
- MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation)

REMEDIATION STATUS:
Credentials revoked: ${resources.find(r => r.type === 'iam_user')?.isVulnerable ? 'PENDING' : 'COMPLETE'}`;
      success = true;
    } else {
      output = "No incident data available for this lab.";
    }
  }
  // VPN Commands
  else if (lowerCmd.startsWith("aws ec2 describe-vpn ")) {
    const vpnName = lowerCmd.replace("aws ec2 describe-vpn ", "").trim();
    const vpn = resources.find(r => r.type === 'vpn_connection' && r.name === vpnName);
    if (vpn) {
      const config = vpn.config as any;
      output = `=== VPN Connection: ${vpnName} ===\n\nState: ${vpn.isVulnerable ? 'DOWN' : 'AVAILABLE'}\nType: ${config.type || 'ipsec.1'}\nTunnel 1: ${config.tunnel1 || 'UP'}\nTunnel 2: ${config.tunnel2 || 'UP'}\n\n${vpn.isVulnerable ? '[!] CRITICAL: VPN tunnels are DOWN. Connectivity to on-premises lost.' : '[OK] VPN connection is healthy.'}`;
    } else {
      output = `Error: VPN connection ${vpnName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 reset-vpn ")) {
    const vpnName = lowerCmd.replace("aws ec2 reset-vpn ", "").trim();
    const vpn = resources.find(r => r.type === 'vpn_connection' && r.name === vpnName);
    if (vpn && vpn.isVulnerable) {
      await storage.updateResource(vpn.id, { isVulnerable: false, status: 'available' });
      output = `[SUCCESS] VPN connection ${vpnName} reset initiated\n  - IKE renegotiation in progress\n  - Tunnel 1: ESTABLISHING... UP\n  - Tunnel 2: ESTABLISHING... UP\n  - Connectivity restored`;
      success = true;
      const remaining = resources.filter(r => r.id !== vpn.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] VPN connectivity restored!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: VPN ${vpnName} not found or already operational.`;
    }
  }
  // NAT Gateway Commands
  else if (lowerCmd.startsWith("aws ec2 describe-nat ")) {
    const natName = lowerCmd.replace("aws ec2 describe-nat ", "").trim();
    const nat = resources.find(r => r.type === 'nat_gateway' && r.name === natName);
    if (nat) {
      const config = nat.config as any;
      output = `=== NAT Gateway: ${natName} ===\n\nState: ${nat.isVulnerable ? 'DEGRADED' : 'AVAILABLE'}\nActive Connections: ${config.activeConnections || 0}\nError Port Allocation: ${config.errorPortAllocation || 0}\n\n${nat.isVulnerable ? `[!] WARNING: High port allocation errors detected (${config.errorPortAllocation}). Port exhaustion likely.` : '[OK] NAT Gateway operating normally.'}`;
    } else {
      output = `Error: NAT Gateway ${natName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 create-nat ")) {
    const parts = lowerCmd.replace("aws ec2 create-nat ", "").trim().split(' ');
    const natName = parts[0];
    const subnetName = parts[1];
    output = `[SUCCESS] NAT Gateway ${natName} created\n  - Subnet: ${subnetName || 'subnet-public-2'}\n  - Elastic IP allocated\n  - State: AVAILABLE`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 update-routes-multi-nat ")) {
    const vpcName = lowerCmd.replace("aws ec2 update-routes-multi-nat ", "").trim();
    // Fix ALL vulnerable NAT gateways as this is a multi-NAT architecture fix
    const natGateways = resources.filter(r => r.type === 'nat_gateway' && r.isVulnerable);
    if (natGateways.length > 0) {
      for (const nat of natGateways) {
        await storage.updateResource(nat.id, { isVulnerable: false, status: 'optimized' });
      }
      output = `[SUCCESS] Multi-NAT routing configured for ${vpcName}\n  - Route table rtb-private-1 updated to use nat-prod-01\n  - Route table rtb-private-2 updated to use nat-prod-02\n  - Traffic distribution optimized across AZs\n  - ${natGateways.length} NAT gateway(s) now operating efficiently`;
      success = true;
      const remaining = resources.filter(r => !natGateways.map(n => n.id).includes(r.id) && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] NAT Gateway architecture optimized!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: VPC ${vpcName} not found or already configured.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 scale-nat ")) {
    const natName = lowerCmd.replace("aws ec2 scale-nat ", "").trim();
    const nat = resources.find(r => r.type === 'nat_gateway' && r.name === natName);
    if (nat && nat.isVulnerable) {
      await storage.updateResource(nat.id, { isVulnerable: false, status: 'optimized' });
      output = `[SUCCESS] NAT Gateway ${natName} scaling initiated\n  - Additional NAT Gateway created in alternate AZ\n  - Route tables updated for AZ-local routing\n  - Port allocation pressure reduced`;
      success = true;
      const remaining = resources.filter(r => r.id !== nat.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] NAT Gateway capacity restored!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: NAT Gateway ${natName} not found or already optimized.`;
    }
  }
  // Route 53 Resolver Commands
  else if (lowerCmd.startsWith("aws route53resolver describe-endpoint ")) {
    const endpointName = lowerCmd.replace("aws route53resolver describe-endpoint ", "").trim();
    const endpoint = resources.find(r => r.type === 'resolver_endpoint' && r.name === endpointName);
    if (endpoint) {
      const config = endpoint.config as any;
      output = `=== Resolver Endpoint: ${endpointName} ===\n\nDirection: ${config.direction || 'OUTBOUND'}\nStatus: ${endpoint.isVulnerable ? 'DEGRADED' : 'OPERATIONAL'}\nIP Addresses: ${(config.ips || []).join(', ')}\n\n${endpoint.isVulnerable ? '[!] WARNING: DNS resolution failures detected.' : '[OK] Resolver endpoint operational.'}`;
    } else {
      output = `Error: Resolver endpoint ${endpointName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 fix-resolver-sg ")) {
    const sgName = lowerCmd.replace("aws ec2 fix-resolver-sg ", "").trim();
    const sg = resources.find(r => r.type === 'security_group' && r.name === sgName);
    const endpoint = resources.find(r => r.type === 'resolver_endpoint');
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      if (endpoint && endpoint.isVulnerable) {
        await storage.updateResource(endpoint.id, { isVulnerable: false, status: 'operational' });
      }
      output = `[SUCCESS] Resolver security group ${sgName} fixed\n  - Inbound: UDP/TCP 53 from VPC CIDR allowed\n  - Outbound: UDP/TCP 53 to on-prem DNS (192.168.1.10, 192.168.1.11) allowed\n  - DNS resolution restored`;
      success = true;
      const remaining = resources.filter(r => r.id !== sg.id && r.id !== (endpoint?.id || 0) && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Hybrid DNS resolution working!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: Security group ${sgName} not found or already correct.`;
    }
  }
  else if (lowerCmd.startsWith("aws route53resolver enable-logging ")) {
    const endpointName = lowerCmd.replace("aws route53resolver enable-logging ", "").trim();
    output = `[SUCCESS] Query logging enabled for ${endpointName}\n  - Log destination: CloudWatch Log Group /aws/route53resolver/queries\n  - Query logging active`;
    success = true;
  }
  // ALB/ELBv2 Commands
  else if (lowerCmd.startsWith("aws elbv2 describe-target-health ")) {
    const tgName = lowerCmd.replace("aws elbv2 describe-target-health ", "").trim();
    const tg = resources.find(r => r.type === 'target_group' && r.name === tgName);
    if (tg) {
      const config = tg.config as any;
      output = `=== Target Health: ${tgName} ===\n\nHealthy Targets: ${config.healthyTargets || 0}\nUnhealthy Targets: ${tg.isVulnerable ? '2' : '0'}\n\nHealth Check Configuration:\n  Path: ${config.healthCheckPath || '/health'}\n  Port: ${config.healthCheckPort || 80}\n  Status: ${tg.isVulnerable ? 'FAILING' : 'PASSING'}\n\n${tg.isVulnerable ? '[!] WARNING: All targets failing health checks. Check path and port configuration.' : '[OK] All targets healthy.'}`;
    } else {
      output = `Error: Target group ${tgName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws elbv2 describe-target-group ")) {
    const tgName = lowerCmd.replace("aws elbv2 describe-target-group ", "").trim();
    const tg = resources.find(r => r.type === 'target_group' && r.name === tgName);
    if (tg) {
      const config = tg.config as any;
      output = `=== Target Group: ${tgName} ===\n\nProtocol: HTTP\nPort: 80\nVPC: vpc-production\n\nHealth Check:\n  Protocol: HTTP\n  Path: ${config.healthCheckPath || '/health'}\n  Port: ${config.healthCheckPort || 80}\n  Interval: 30 seconds\n  Timeout: 5 seconds\n  Healthy Threshold: 5\n  Unhealthy Threshold: 2`;
    } else {
      output = `Error: Target group ${tgName} not found.`;
    }
  }
  else if (lowerCmd.includes("aws elbv2 modify-target-group ")) {
    const match = lowerCmd.match(/aws elbv2 modify-target-group (\S+)/);
    const tgName = match ? match[1] : '';
    const tg = resources.find(r => r.type === 'target_group' && r.name === tgName);
    if (tg && tg.isVulnerable) {
      await storage.updateResource(tg.id, { isVulnerable: false, status: 'healthy' });
      output = `[SUCCESS] Target group ${tgName} modified\n  - Health check path updated to /api/health\n  - Health check port updated to 8080\n  - Targets becoming healthy...`;
      success = true;
      const remaining = resources.filter(r => r.id !== tg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All targets healthy, API serving traffic!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `Error: Target group ${tgName} not found or already configured correctly.`;
    }
  }
  // Traffic Mirroring Commands
  else if (lowerCmd.startsWith("aws ec2 create-traffic-mirror ")) {
    const instanceName = lowerCmd.replace("aws ec2 create-traffic-mirror ", "").trim();
    output = `[SUCCESS] Traffic mirror session created for ${instanceName}\n  - Mirror target: network-ids-interface\n  - Filter: Capture all traffic\n  - Session active`;
    success = true;
  }
  // WAF IP Blocklist
  else if (lowerCmd.startsWith("aws waf add-ip-blocklist ")) {
    const ipAddress = lowerCmd.replace("aws waf add-ip-blocklist ", "").trim();
    // Check if there are vulnerable security groups to fix as part of blocking
    const vulnerableSg = resources.find(r => r.type === 'security_group' && r.isVulnerable);
    if (vulnerableSg) {
      await storage.updateResource(vulnerableSg.id, { isVulnerable: false, status: 'secured' });
    }
    output = `[SUCCESS] IP ${ipAddress} added to WAF blocklist\n  - Rule: BlockMaliciousIPs\n  - Action: BLOCK\n  - Applies to: All associated resources`;
    success = true;
    const remaining = resources.filter(r => r.id !== (vulnerableSg?.id || 0) && r.isVulnerable);
    if (remaining.length === 0) {
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Threat blocked!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    }
  }
  // CloudWatch NAT metrics
  else if (lowerCmd.startsWith("aws cloudwatch get-nat-metrics ")) {
    const natName = lowerCmd.replace("aws cloudwatch get-nat-metrics ", "").trim();
    const nat = resources.find(r => r.type === 'nat_gateway' && r.name === natName);
    if (nat) {
      const config = nat.config as any;
      output = `=== NAT Gateway Metrics: ${natName} ===\n\nActiveConnectionCount: ${config.activeConnections || 48500}\nPacketsDropCount: ${config.errorPortAllocation ? 127 : 0}\nErrorPortAllocation: ${config.errorPortAllocation || 0}\nBytesOutToDestination: 2.3 TB\n\n${nat.isVulnerable ? '[!] HIGH ERROR PORT ALLOCATION - Port exhaustion in progress!' : '[OK] Metrics within normal range.'}`;
    } else {
      output = `Error: NAT Gateway ${natName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws cloudwatch get-vpn-metrics ")) {
    const vpnName = lowerCmd.replace("aws cloudwatch get-vpn-metrics ", "").trim();
    const vpn = resources.find(r => r.type === 'vpn_connection' && r.name === vpnName);
    if (vpn) {
      output = `=== VPN Metrics: ${vpnName} ===\n\nTunnelState:\n  Tunnel 1: ${vpn.isVulnerable ? '0 (DOWN)' : '1 (UP)'}\n  Tunnel 2: ${vpn.isVulnerable ? '0 (DOWN)' : '1 (UP)'}\nTunnelDataIn: ${vpn.isVulnerable ? '0 bytes' : '1.2 GB'}\nTunnelDataOut: ${vpn.isVulnerable ? '0 bytes' : '890 MB'}\n\n${vpn.isVulnerable ? '[!] CRITICAL: Both tunnels showing DOWN state since 03:47:22 UTC' : '[OK] VPN metrics healthy.'}`;
    } else {
      output = `Error: VPN connection ${vpnName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 describe-cgw ")) {
    const cgwName = lowerCmd.replace("aws ec2 describe-cgw ", "").trim();
    const cgw = resources.find(r => r.type === 'customer_gateway' && r.name === cgwName);
    if (cgw) {
      const config = cgw.config as any;
      output = `=== Customer Gateway: ${cgwName} ===\n\nIP Address: ${config.ip || '203.0.113.50'}\nBGP ASN: ${config.bgpAsn || 65000}\nState: AVAILABLE\nType: ipsec.1`;
    } else {
      output = `Error: Customer gateway ${cgwName} not found.`;
    }
  }
  else if (lowerCmd === "aws ec2 describe-route-tables --vpn" || lowerCmd === "aws ec2 describe-route-tables --nat") {
    output = `=== Route Tables ===\n\nrtb-private-1:\n  Destination: 0.0.0.0/0\n  Target: nat-prod-01\n  Status: active\n  \nrtb-private-2:\n  Destination: 0.0.0.0/0\n  Target: nat-prod-01\n  Status: active (suboptimal - cross-AZ)\n\n[!] Both private subnets routing through single NAT Gateway`;
  }
  // Service Account Credential Commands
  else if (lowerCmd.startsWith("aws iam list-access-keys --user ")) {
    const userName = lowerCmd.replace("aws iam list-access-keys --user ", "").trim();
    const account = resources.find(r => (r.type === 'service_account' || r.type === 'iam_user') && r.name === userName);
    if (account) {
      const config = account.config as any;
      output = `=== Access Keys for ${userName} ===\n\nAccessKeyId: AKIA${userName.toUpperCase().replace(/-/g, '')}KEY1\nStatus: Active\nCreateDate: ${config.keyAge ? new Date(Date.now() - config.keyAge * 24 * 60 * 60 * 1000).toISOString().split('T')[0] : 'Unknown'}\nKey Age: ${config.keyAge || 0} days\n\n${config.keyAge > 90 ? '[!] KEY ROTATION OVERDUE - Keys should be rotated every 90 days (CIS AWS 1.14)' : '[OK] Key age within policy limits'}`;
    } else {
      output = `Error: User ${userName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws iam get-service-last-accessed ")) {
    const serviceName = lowerCmd.replace("aws iam get-service-last-accessed ", "").trim();
    const account = resources.find(r => (r.type === 'service_account' || r.type === 'iam_role') && r.name === serviceName);
    if (account) {
      const config = account.config as any;
      const permissions = config.permissions || [];
      output = `=== Service Last Accessed Report: ${serviceName} ===\n\nGranted Permissions Analysis:\n`;
      if (Array.isArray(permissions)) {
        permissions.forEach((p: string) => {
          output += `  ${p}: Last used ${config.lastUsed || '1 hour ago'}\n`;
        });
      } else {
        output += `  ${permissions}: Last used ${config.lastUsed || '1 hour ago'}\n`;
      }
      output += `\n[i] Use this data to right-size permissions based on actual usage.`;
    } else {
      output = `Error: Service ${serviceName} not found.`;
    }
  }
  else if (lowerCmd.startsWith("aws iam rotate-service-credentials ")) {
    const serviceName = lowerCmd.replace("aws iam rotate-service-credentials ", "").trim();
    const account = resources.find(r => r.type === 'service_account' && r.name === serviceName && r.isVulnerable);
    if (account) {
      await storage.updateResource(account.id, { isVulnerable: false, status: 'credentials-rotated' });
      output = `[SUCCESS] Credentials rotated for ${serviceName}\n\nActions Taken:\n  - Created new access key: AKIA${serviceName.toUpperCase().replace(/-/g, '')}NEW1\n  - Deactivated old access key\n  - Key age reset to 0 days\n\n[!] IMPORTANT: Update application configurations with new credentials before deleting old key.`;
      success = true;
      const remaining = resources.filter(r => r.id !== account.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Service account credentials secured!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else if (resources.find(r => r.type === 'service_account' && r.name === serviceName)) {
      output = `Credentials for ${serviceName} are already current (within 90-day rotation policy).`;
    } else {
      output = `Error: Service account ${serviceName} not found.`;
    }
  }
  // Role Chain Analysis Commands
  else if (lowerCmd.startsWith("aws iam analyze-path ")) {
    const parts = lowerCmd.replace("aws iam analyze-path ", "").trim().split(" ");
    const fromRole = parts[0];
    const toRole = parts[1];
    output = `=== Role Chain Analysis: ${fromRole} -> ${toRole} ===\n\nEscalation Path Detected:\n\n  Step 1: ${fromRole}\n    |-- sts:AssumeRole -> deploy-role\n    |   Condition: None (UNRESTRICTED)\n    |\n  Step 2: deploy-role\n    |-- sts:AssumeRole -> ${toRole}\n    |   Condition: None (UNRESTRICTED)\n    |\n  Step 3: ${toRole}\n    |-- Permissions: AdministratorAccess\n\n[CRITICAL] Low-privilege role can reach admin through 2 hops!\n\nRecommendation: Add conditions to deploy-role trust policy to prevent app-role from assuming it without MFA or from specific principals only.`;
  }
  else if (lowerCmd.startsWith("aws iam break-role-chain ")) {
    const roleName = lowerCmd.replace("aws iam break-role-chain ", "").trim();
    const role = resources.find(r => r.type === 'iam_role' && r.name === roleName && r.isVulnerable);
    if (role) {
      await storage.updateResource(role.id, { isVulnerable: false, status: 'chain-broken' });
      const adminRole = resources.find(r => r.type === 'iam_role' && r.name === 'admin-role' && r.isVulnerable);
      if (adminRole) {
        await storage.updateResource(adminRole.id, { isVulnerable: false, status: 'secured' });
      }
      output = `[SUCCESS] Role chain broken at ${roleName}\n\nChanges Applied:\n  - Added condition: aws:PrincipalTag/role-chain-authorized = true\n  - Restricted assumable principals to explicit list\n  - Added MFA requirement for cross-role assumption\n\n[i] app-role can no longer chain through deploy-role to admin-role.`;
      success = true;
      const remaining = resources.filter(r => r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Role escalation paths eliminated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else if (resources.find(r => r.type === 'iam_role' && r.name === roleName)) {
      output = `Role chain for ${roleName} has already been secured.`;
    } else {
      output = `Error: Role ${roleName} not found.`;
    }
  }
  // IAM Identity Investigation Commands
  else if (lowerCmd === "aws iam list-identity-providers") {
    const providers = resources.filter(r => r.type === 'identity_provider');
    if (providers.length > 0) {
      output = `=== Federated Identity Providers ===\n\n` + providers.map(p => {
        const config = p.config as any;
        return `Provider: ${p.name}\n  Type: ${config.type || 'SAML'}\n  Users: ${config.users || 0}\n  MFA Enforced: ${config.mfaEnforced ? 'Yes' : 'No'}\n  Status: ${p.status}`;
      }).join('\n\n');
    } else {
      output = "No federated identity providers configured.";
    }
  }
  else if (lowerCmd === "aws iam analyze-user-permissions") {
    const users = resources.filter(r => r.type === 'iam_user');
    if (users.length > 0) {
      output = `=== User Permission Analysis ===\n\n` + users.map(u => {
        const config = u.config as any;
        const issues = [];
        if (config.directPolicies > 0) issues.push("Direct policies attached (use groups instead)");
        if (!config.mfaEnabled) issues.push("MFA not enabled");
        if (config.lastActivity?.includes('days')) issues.push("Inactive account");
        return `User: ${u.name}\n  Groups: ${(config.groups || []).join(', ')}\n  MFA: ${config.mfaEnabled ? 'Enabled' : 'DISABLED'}\n  Last Activity: ${config.lastActivity || 'Unknown'}\n  Direct Policies: ${config.directPolicies || 0}\n  Status: ${u.isVulnerable ? '[!] ISSUES FOUND' : 'Compliant'}\n  ${issues.length > 0 ? 'Issues: ' + issues.join(', ') : ''}`;
      }).join('\n\n');
    } else {
      output = "No IAM users found.";
    }
  }
  else if (lowerCmd === "aws iam audit-service-accounts") {
    const serviceAccounts = resources.filter(r => r.type === 'service_account');
    if (serviceAccounts.length > 0) {
      output = `=== Service Account Audit ===\n\n` + serviceAccounts.map(sa => {
        const config = sa.config as any;
        const issues = [];
        if (config.keyAge > 90) issues.push(`Key age ${config.keyAge} days exceeds 90-day rotation policy`);
        if (config.lastUsed?.includes('90')) issues.push("Credential unused for 90+ days");
        if ((config.permissions || []).some((p: string) => p.includes('*'))) issues.push("Wildcard permissions detected");
        return `Service Account: ${sa.name}\n  Key Age: ${config.keyAge || 0} days\n  Last Used: ${config.lastUsed || 'Unknown'}\n  Permissions: ${(config.permissions || []).join(', ')}\n  Can Assume Roles: ${(config.canAssumeRoles || []).join(', ') || 'None'}\n  Status: ${sa.isVulnerable ? '[!] AT RISK' : 'Compliant'}\n  ${issues.length > 0 ? 'Issues: ' + issues.join('; ') : ''}`;
      }).join('\n\n');
    } else {
      output = "No service accounts found.";
    }
  }
  else if (lowerCmd === "aws iam trace-role-chains") {
    const roles = resources.filter(r => r.type === 'iam_role');
    const serviceAccounts = resources.filter(r => r.type === 'service_account');
    output = `=== Role Assumption Chain Analysis ===\n\nIdentified Privilege Escalation Paths:\n\n`;
    
    const escalationPaths: string[] = [];
    roles.forEach(role => {
      const config = role.config as any;
      if (config.canAssumeAdmin) {
        escalationPaths.push(`  [!] ${role.name} -> AdminRole (ESCALATION PATH)`);
      }
    });
    serviceAccounts.forEach(sa => {
      const config = sa.config as any;
      if (config.canAssumeRoles && config.canAssumeRoles.length > 0) {
        config.canAssumeRoles.forEach((r: string) => {
          escalationPaths.push(`  ${sa.name} -> ${r}`);
        });
      }
    });
    
    if (escalationPaths.length > 0) {
      output += escalationPaths.join('\n');
      output += `\n\n[!] WARNING: ${escalationPaths.filter(p => p.includes('ESCALATION')).length} privilege escalation path(s) detected!`;
    } else {
      output += "No role assumption chains detected.";
    }
  }
  else if (lowerCmd === "aws iam analyze-trust-policies") {
    const roles = resources.filter(r => r.type === 'iam_role');
    output = `=== Trust Policy Analysis ===\n\n`;
    
    const issues: string[] = [];
    roles.forEach(role => {
      const config = role.config as any;
      const trustPolicy = config.trustPolicy;
      if (trustPolicy === '*' || (typeof trustPolicy === 'string' && trustPolicy.includes('*:root'))) {
        issues.push(`[CRITICAL] ${role.name}: Wildcard trust allows ANY AWS account to assume this role`);
      }
      if (!config.conditions || config.conditions.length === 0) {
        issues.push(`[HIGH] ${role.name}: No conditions on trust policy - missing MFA requirement, IP restriction, or source constraints`);
      }
    });
    
    if (issues.length > 0) {
      output += issues.join('\n\n');
      output += `\n\n=== MITRE ATT&CK: T1098 - Account Manipulation ===\nAttackers exploit overly permissive trust policies to assume roles and escalate privileges.`;
    } else {
      output += "All trust policies appear properly configured.";
    }
  }
  else if (lowerCmd === "aws iam check-conditional-access") {
    const roles = resources.filter(r => r.type === 'iam_role');
    const groups = resources.filter(r => r.type === 'iam_group');
    output = `=== Conditional Access Analysis ===\n\n`;
    
    const findings: string[] = [];
    roles.forEach(role => {
      const config = role.config as any;
      if (!config.conditions || config.conditions.length === 0) {
        findings.push(`[!] ${role.name}: No conditions configured\n    Recommended: Add aws:MultiFactorAuthPresent, aws:SourceIp, aws:RequestedRegion conditions`);
      }
    });
    groups.forEach(group => {
      const config = group.config as any;
      if (!config.mfaRequired) {
        findings.push(`[!] ${group.name}: MFA not required for group members`);
      }
    });
    
    if (findings.length > 0) {
      output += findings.join('\n\n');
    } else {
      output += "Conditional access is properly configured.";
    }
  }
  else if (lowerCmd === "aws iam find-escalation-paths") {
    output = `=== Privilege Escalation Path Analysis ===\n
Scanning for known IAM privilege escalation patterns...\n
[!] ESCALATION PATH 1: cicd-deployer -> DeveloperRole -> AdminRole
    Severity: CRITICAL
    Attack Chain:
    1. Attacker compromises cicd-deployer service account credentials
    2. Uses sts:AssumeRole to become DeveloperRole
    3. DeveloperRole has iam:PassRole + ec2:RunInstances
    4. Creates EC2 with AdminRole instance profile
    5. SSM into instance -> Full admin access
    MITRE ATT&CK: T1548.002 - Abuse Elevation Control Mechanism

[!] ESCALATION PATH 2: CrossAccountRole wildcard trust
    Severity: HIGH
    Attack Chain:
    1. Any AWS account can assume CrossAccountRole
    2. While ReadOnly, can enumerate sensitive resources
    3. Reconnaissance for follow-on attacks
    MITRE ATT&CK: T1078.004 - Valid Accounts: Cloud Accounts

[!] ESCALATION PATH 3: developer-mike direct policy attachment
    Severity: MEDIUM
    Risk: Bypasses group-based policy management
    Direct policies harder to audit and can grant unexpected permissions

=== Summary ===
3 privilege escalation paths identified
2 CRITICAL, 1 HIGH, 0 MEDIUM severity issues`;
  }
  else if (lowerCmd === "aws iam get-credential-report") {
    output = `=== IAM Credential Report ===\n
Generated: ${new Date().toISOString()}\n
User                    Password Last Used    Access Key 1 Age    MFA     Status
---------------------------------------------------------------------------------------
admin-sarah             2 hours ago          N/A                  Yes     COMPLIANT
developer-mike          1 day ago            45 days              Yes     COMPLIANT
contractor-alex         45 days ago          180 days             No      [!] STALE + NO MFA

Service Account         Last Activity        Key Age              Status
---------------------------------------------------------------------------------------
cicd-deployer           1 hour ago           180 days             [!] KEY ROTATION OVERDUE
backup-automation       90 days ago          365 days             [!] UNUSED + ANCIENT KEY
monitoring-agent        5 minutes ago        30 days              COMPLIANT

=== Findings ===
[CRITICAL] 1 user without MFA (contractor-alex)
[HIGH] 2 access keys older than 90 days
[HIGH] 1 unused credential (backup-automation)
[MEDIUM] 1 stale user account (contractor-alex - 45 days inactive)

CIS AWS Benchmark 1.12: Disable credentials unused for 90+ days`;
  }
  else if (lowerCmd === "aws iam fix-trust-policies") {
    const roles = resources.filter(r => r.type === 'iam_role' && r.isVulnerable);
    if (roles.length > 0) {
      for (const role of roles) {
        await storage.updateResource(role.id, { isVulnerable: false, status: 'secured' });
      }
      output = `[SUCCESS] Trust policies remediated for ${roles.length} role(s)\n\nChanges Applied:\n`;
      roles.forEach(role => {
        output += `  - ${role.name}:\n    + Added aws:MultiFactorAuthPresent condition\n    + Restricted principals to known entities\n    + Added aws:SourceIp condition for corporate IPs\n`;
      });
      success = true;
      const remaining = resources.filter(r => !roles.map(ro => ro.id).includes(r.id) && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n[MISSION COMPLETE] All identity vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = "No trust policy issues to fix.";
    }
  }
  else if (lowerCmd === "aws iam implement-permission-boundaries") {
    const boundaries = resources.filter(r => r.type === 'permission_boundary' && r.isVulnerable);
    const users = resources.filter(r => r.type === 'iam_user' && r.isVulnerable);
    const serviceAccounts = resources.filter(r => r.type === 'service_account' && r.isVulnerable);
    
    const toFix = [...boundaries, ...users, ...serviceAccounts];
    if (toFix.length > 0) {
      for (const resource of toFix) {
        await storage.updateResource(resource.id, { isVulnerable: false, status: 'secured' });
      }
      output = `[SUCCESS] Permission boundaries implemented\n\nChanges Applied:\n  - Permission boundary policy created: developer-boundary\n  - Maximum permissions: PowerUserAccess (prevents IAM privilege escalation)\n  - Applied to all developer roles and service accounts\n  - Blocks: iam:CreateUser, iam:CreateRole, iam:AttachUserPolicy, iam:PutRolePolicy`;
      success = true;
      const remaining = resources.filter(r => !toFix.map(t => t.id).includes(r.id) && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All identity vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = "Permission boundaries already implemented.";
    }
  }
  else if (lowerCmd === "aws iam enable-identity-monitoring") {
    const groups = resources.filter(r => r.type === 'iam_group' && r.isVulnerable);
    if (groups.length > 0) {
      for (const group of groups) {
        await storage.updateResource(group.id, { isVulnerable: false, status: 'monitored' });
      }
    }
    output = `[SUCCESS] Identity monitoring enabled\n
Configured Services:
  - CloudTrail: IAM data events enabled
  - GuardDuty: IAM finding types activated
    + UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
    + CredentialAccess:IAMUser/AnomalousBehavior
    + Persistence:IAMUser/ResourcePermissions
  - IAM Access Analyzer: Continuous analysis enabled
    + External access findings
    + Unused access findings
    + Policy validation
  - EventBridge: Real-time alerts configured
    + Role assumption from new IPs
    + Permission boundary modifications
    + Cross-account activity

Alert Destinations:
  - SIEM integration: Enabled
  - PagerDuty: Critical findings
  - Slack: All findings`;
    success = true;
    const remaining = resources.filter(r => r.isVulnerable);
    if (remaining.length === 0) {
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Identity security controls fully implemented!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    }
  }
  else if (lowerCmd === "aws iam generate-security-report") {
    const vulnerableCount = resources.filter(r => r.isVulnerable).length;
    const totalCount = resources.length;
    output = `=== Identity Security Assessment Report ===
Generated: ${new Date().toISOString()}

EXECUTIVE SUMMARY
-----------------
Total Identity Resources: ${totalCount}
Compliant: ${totalCount - vulnerableCount}
Non-Compliant: ${vulnerableCount}
Risk Score: ${vulnerableCount === 0 ? 'LOW' : vulnerableCount <= 3 ? 'MEDIUM' : 'HIGH'}

FINDINGS REMEDIATED
-------------------
1. Trust Policy Misconfigurations
   - AdminRole: Added MFA condition, restricted principals
   - CrossAccountRole: Removed wildcard trust, specified allowed accounts
   - DeveloperRole: Removed escalation path to admin

2. Privilege Escalation Paths Eliminated
   - cicd-deployer -> DeveloperRole -> AdminRole: BLOCKED
   - Service account permissions right-sized

3. Credential Lifecycle Issues
   - contractor-alex: Access revoked (stale account)
   - backup-automation: Key rotated and scoped down

4. Conditional Access Implemented
   - MFA required for all role assumptions
   - IP restrictions for sensitive operations
   - Session duration limits enforced

RECOMMENDATIONS
---------------
1. Implement regular access reviews (quarterly)
2. Enable AWS SSO for centralized identity management
3. Adopt infrastructure-as-code for IAM (Terraform/CloudFormation)
4. Implement just-in-time access for privileged operations

COMPLIANCE MAPPING
------------------
CIS AWS 1.5: MFA for root account - PASS
CIS AWS 1.12: Disable unused credentials - PASS
CIS AWS 1.16: Policies attached to groups/roles - PASS
MITRE ATT&CK T1078: Valid Accounts - MITIGATED
MITRE ATT&CK T1098: Account Manipulation - MITIGATED`;
    success = true;
  }
  // SIEM Threat Intel
  else if (lowerCmd.startsWith("aws siem lookup-ip ")) {
    const ipAddress = lowerCmd.replace("aws siem lookup-ip ", "").trim();
    output = `=== Threat Intelligence: ${ipAddress} ===\n\nReputation: MALICIOUS\nCategory: Data Exfiltration Infrastructure\nASN: AS50673 (Serverius Holding B.V.)\nCountry: Netherlands\nFirst Seen: 2024-09-15\nConfidence: 95%\n\nAssociated Campaigns:\n  - Operation DataHarvest (APT-41)\n  - Credential Theft Ring\n\n[!] CRITICAL: Known malicious infrastructure`;
  }
  else if (lowerCmd.startsWith("aws siem get-alert ")) {
    const alertId = lowerCmd.replace("aws siem get-alert ", "").trim();
    output = `=== Alert Details: ${alertId} ===\n\nTitle: Large Outbound Data Transfer\nSeverity: HIGH\nCategory: Data Exfiltration\nMITRE ATT&CK: T1048 - Exfiltration Over Alternative Protocol\n\nSource: analytics-server-01 (10.0.4.55)\nDestination: 185.220.101.42\nData Transferred: 47 GB\nDuration: 6 hours\n\nRecommended Actions:\n  1. Isolate affected server\n  2. Block destination IP\n  3. Analyze transferred data types`;
  }
  // ============= ACCESS ANALYZER COMMANDS =============
  else if (lowerCmd === "aws access-analyzer enable" || lowerCmd === "aws access-analyzer enable-monitoring") {
    output = `=== IAM Access Analyzer Enabled ===

[OK] Analyzer created: account-analyzer
[OK] Scanning IAM policies...
[OK] Scanning S3 bucket policies...
[OK] Scanning KMS key policies...

Initial findings will be available in 5-10 minutes.
Use 'aws access-analyzer list-findings' to view results.`;
    success = true;
  }
  else if (lowerCmd === "aws access-analyzer list-findings") {
    output = `=== Access Analyzer Findings ===

CRITICAL:
  [!] S3 Bucket 'prod-data' allows public access
  [!] IAM Role 'DevRole' trusts external account
  
HIGH:
  [!] KMS Key allows cross-account access
  [!] Lambda function has overly permissive role
  
MEDIUM:
  [!] S3 Bucket 'logs' allows cross-account read

Total: 5 findings | 2 Critical | 2 High | 1 Medium`;
    success = true;
  }
  else if (lowerCmd === "aws access-analyzer generate-report") {
    output = `=== Access Analyzer Report Generated ===

Report: access-analyzer-${new Date().toISOString().split('T')[0]}.pdf

Summary:
  Resources Analyzed: 147
  Findings: 5
  Remediated: 0

Exported to S3: s3://security-reports/access-analyzer/`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws access-analyzer remediate-")) {
    output = `=== Remediation Applied ===

[OK] Finding remediated
[OK] Policy updated to remove external access
[OK] Change logged to CloudTrail

Re-scan scheduled in 5 minutes.`;
    success = true;
  }
  // ============= AWS SERVICE COMMANDS =============
  else if (lowerCmd === "aws service list-active" || lowerCmd === "aws services") {
    output = `=== Active AWS Services ===

Compute:
  [OK] EC2 - 12 instances running
  [OK] Lambda - 45 functions deployed
  [OK] ECS - 3 clusters active

Storage:
  [OK] S3 - 28 buckets
  [OK] EBS - 50 volumes attached

Database:
  [OK] RDS - 4 instances
  [OK] DynamoDB - 8 tables

Security:
  [OK] IAM - 45 users, 23 roles
  [OK] KMS - 12 keys
  [!] GuardDuty - Disabled in 2 regions`;
    success = true;
  }
  // ============= CLOUDTRAIL ANALYZE COMMANDS =============
  else if (lowerCmd.startsWith("aws cloudtrail analyze-attack-timeline") || lowerCmd.startsWith("aws cloudtrail analyze-timeline ")) {
    output = `=== Attack Timeline Analysis ===

Phase 1: Initial Access (03:00-03:15)
  - ConsoleLogin from 198.51.100.45
  - MFA not used
  - Location: Netherlands (unusual)

Phase 2: Reconnaissance (03:15-03:30)
  - ListBuckets, ListUsers, DescribeInstances
  - Enumerated 28 buckets, 45 users

Phase 3: Privilege Escalation (03:30-03:45)
  - AttachUserPolicy: AdministratorAccess
  - CreateAccessKey for persistence

Phase 4: Data Access (03:45-04:15)
  - GetObject on sensitive buckets
  - 2.3 TB downloaded

MITRE ATT&CK: T1078 → T1087 → T1098 → T1530`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail analyze-source-ip")) {
    const parts = lowerCmd.split(" ");
    const target = parts[parts.length - 1];
    output = `=== Source IP Analysis: ${target} ===

Activity Summary:
  First Seen: 03:00:15 UTC
  Last Seen: 04:15:42 UTC
  Total Events: 247
  
Top Actions:
  GetObject: 156
  DescribeInstances: 45
  ListBuckets: 12
  AssumeRole: 8
  
Risk Indicators:
  [!] New IP - Never seen before
  [!] Tor exit node
  [!] Off-hours activity
  [!] High-volume data access

Verdict: HIGHLY SUSPICIOUS`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail find-anomalous-actions ") || lowerCmd.startsWith("aws cloudtrail find-persistence-indicators ")) {
    output = `=== Anomalous Activity Detected ===

Persistence Indicators:
  [!] CreateAccessKey - New key for backdoor access
  [!] CreateUser - Unauthorized user created
  [!] AttachUserPolicy - Admin policy attached
  [!] PutEventSelectors - Attempted logging bypass

Lateral Movement:
  [!] AssumeRole to 3 different roles
  [!] Cross-account access attempts

Credential Access:
  [!] GetSecretValue - Secrets Manager accessed
  [!] GetParameter - SSM parameters retrieved`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail get-console-login ") || lowerCmd.startsWith("aws cloudtrail get-session-activity ")) {
    output = `=== Console Activity Analysis ===

Login Details:
  User: finance-admin
  Time: 03:00:15 UTC
  IP: 198.51.100.45
  MFA: Not used
  
Session Activity:
  Duration: 1h 15m
  Actions: 247
  Data Accessed: 2.3 TB
  
Geographic Analysis:
  Expected: San Francisco, US
  Actual: Amsterdam, Netherlands
  
[!] ALERT: Location anomaly detected`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail get-events ") || lowerCmd.startsWith("aws cloudtrail get-instance-events ") || lowerCmd.startsWith("aws cloudtrail get-key-usage ")) {
    output = `=== CloudTrail Event Details ===

Events Retrieved: 47

Sample Events:
  [03:15:22] AssumeRole - AdminRole
  [03:15:45] DescribeInstances - All regions
  [03:16:02] ListBuckets - 28 found
  [03:16:30] GetObject - customer-data/exports/*
  [03:17:15] CreateAccessKey - backdoor-user

Filter: Last 24 hours
Source: All regions`;
    success = true;
  }
  else if (lowerCmd === "aws cloudtrail create-escalation-detections") {
    output = `=== Escalation Detection Rules Created ===

[OK] Rule: IAM Policy Escalation
     Trigger: AttachUserPolicy with Admin*
     
[OK] Rule: Role Assumption Chain
     Trigger: 3+ AssumeRole in 5 minutes
     
[OK] Rule: Access Key Creation
     Trigger: CreateAccessKey for any user
     
[OK] Rule: Trust Policy Modification
     Trigger: UpdateAssumeRolePolicy

4 detection rules deployed to CloudWatch.`;
    success = true;
  }
  else if (lowerCmd === "aws cloudtrail enable-comprehensive-logging" || lowerCmd === "aws cloudtrail enable-enhanced-logging") {
    const ctRes = resources.find(r => (r.type === 'cloudtrail' || r.name?.includes('trail') || r.name?.includes('log')) && r.isVulnerable);
    if (ctRes) {
      // Mark all vulnerable resources as fixed
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Comprehensive CloudTrail Logging Enabled ===

[OK] Multi-region logging: Enabled for all 25 regions
[OK] Management events: ReadWriteType = All
[OK] S3 data events: All buckets included
[OK] Lambda data events: All functions included  
[OK] Log file validation: SHA-256 hash enabled
[OK] Log encryption: KMS key configured
[OK] CloudTrail Insights: Anomaly detection enabled
[OK] Log bucket: Versioning and MFA delete enabled

Complete visibility into all API activity.
Ready for forensic investigation and compliance.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Comprehensive logging enabled!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `[SUCCESS] CloudTrail comprehensive logging already enabled.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws cloudtrail enable-organization-trail") {
    output = `=== Organization Trail Enabled ===

[OK] Trail created: org-security-trail
[OK] Applied to all accounts (47)
[OK] Centralized logging to security account
[OK] Immutable storage configured

Organization-wide visibility achieved.`;
    success = true;
  }
  // ============= EC2 NETWORK COMMANDS =============
  else if (lowerCmd === "aws ec2 analyze-traffic-patterns") {
    output = `=== Traffic Pattern Analysis ===

Normal Patterns:
  Web Tier → App Tier: 443/tcp (98%)
  App Tier → DB Tier: 3306/tcp (95%)
  All Tiers → NAT: 443/tcp (90%)

Anomalies Detected:
  [!] DB Tier → Internet: Direct egress (blocked)
  [!] Web Tier → SSH/22: From 0.0.0.0/0
  [!] Unknown → All: Port scan detected

Recommendation: Implement network segmentation`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 plan-security-group-architecture") {
    output = `=== Security Group Architecture Plan ===

Proposed Structure:
  1. web-tier-sg
     - Inbound: 443 from ALB only
     - Outbound: App tier on 8080
     
  2. app-tier-sg
     - Inbound: 8080 from web-tier-sg
     - Outbound: DB tier on 3306
     
  3. db-tier-sg
     - Inbound: 3306 from app-tier-sg
     - Outbound: None (deny all)
     
  4. bastion-sg
     - Inbound: 22 from corporate IP
     - Outbound: 22 to internal only

Plan ready for implementation.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 configure-web-tier-sg") || lowerCmd.startsWith("aws ec2 configure-app-tier-sg") || lowerCmd.startsWith("aws ec2 configure-data-tier-sg") || lowerCmd.startsWith("aws ec2 configure-admin-access")) {
    const tier = lowerCmd.includes("web") ? "Web" : lowerCmd.includes("app") ? "App" : lowerCmd.includes("data") ? "Data" : "Admin";
    output = `=== ${tier} Tier Security Group Configured ===

[OK] Removed overly permissive rules
[OK] Applied least privilege access
[OK] Logged changes to CloudTrail
[OK] Security group updated

${tier} tier now properly segmented.`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 verify-network-segmentation") {
    const vpcRes = resources.find(r => (r.type === 'vpc' || r.type === 'security_group' || r.type === 'securityGroups' || r.name?.includes('vpc') || r.name?.includes('sg')) && r.isVulnerable);
    if (vpcRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'verified' });
      }
      output = `=== Network Segmentation Verified ===

Test Results:
  [PASS] Web → App: Allowed on 8080
  [PASS] App → DB: Allowed on 3306
  [PASS] Web → DB: BLOCKED (as expected)
  [PASS] DB → Internet: BLOCKED (as expected)
  [PASS] Admin → All: Via bastion only
  [PASS] Egress filtering: Active
  [PASS] Lateral movement: Blocked

All segmentation rules working correctly.
Defense-in-depth architecture validated.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Network segmentation verified!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Network Segmentation Verified ===

Test Results:
  [PASS] Web → App: Allowed on 8080
  [PASS] App → DB: Allowed on 3306
  [PASS] Web → DB: BLOCKED (as expected)
  [PASS] DB → Internet: BLOCKED (as expected)
  [PASS] Admin → All: Via bastion only

All segmentation rules working correctly.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 analyze-flow-logs ") || lowerCmd.startsWith("aws ec2 analyze-flows ")) {
    output = `=== VPC Flow Log Analysis ===

Suspicious Flows:
  10.0.1.50 → 185.220.101.42:443 | 2.4 GB | ALERT
  10.0.2.100 → pool.minexmr.com:3333 | 156 MB | BLOCKED

Normal Flows:
  10.0.1.* → ALB:443 | 45 GB | OK
  App tier → DB:3306 | 12 GB | OK

Recommendations:
  - Block 185.220.101.42 at NACL
  - Investigate 10.0.1.50 for compromise`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 analyze-lateral-movement") {
    output = `=== Lateral Movement Analysis ===

Detected Movement:
  [!] web-server-03 → app-server-01 (SSH)
  [!] app-server-01 → db-server-01 (MySQL)
  [!] bastion → ALL internal (unusual)

Attack Path:
  Entry: web-server-03 (compromised)
  Pivot: app-server-01
  Target: db-server-01 (data access)

Recommendation: Isolate web-server-03 immediately`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-sg ") || lowerCmd === "aws ec2 ls-sg") {
    const sgName = lowerCmd.replace("aws ec2 describe-sg ", "").trim();
    output = `=== Security Group: ${sgName || "All"} ===

Inbound Rules:
  [!] 0.0.0.0/0 → 22 (SSH)    - OVERLY PERMISSIVE
  [!] 0.0.0.0/0 → 3389 (RDP)  - OVERLY PERMISSIVE
  [OK] 10.0.0.0/16 → 443      - Internal only

Outbound Rules:
  [OK] All → 443 (HTTPS)
  [!] All → 0.0.0.0/0         - UNRESTRICTED

Recommendation: Restrict SSH/RDP to bastion only`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-ssh ") || lowerCmd.startsWith("aws ec2 restrict-rdp ") || lowerCmd.startsWith("aws ec2 restrict-db ") || lowerCmd.startsWith("aws ec2 restrict-egress ")) {
    const target = lowerCmd.split(" ").pop();
    output = `=== Security Group Updated: ${target} ===

[OK] Removed 0.0.0.0/0 rules
[OK] Added bastion-only access
[OK] Restricted egress to required ports
[OK] Changes logged

Security posture improved.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-vpc ") || lowerCmd === "aws ec2 describe-vpc-architecture") {
    output = `=== VPC Architecture ===

VPC: vpc-production (10.0.0.0/16)

Subnets:
  public-1a:  10.0.1.0/24  (NAT, ALB)
  public-1b:  10.0.2.0/24  (NAT, ALB)
  private-1a: 10.0.10.0/24 (App tier)
  private-1b: 10.0.11.0/24 (App tier)
  data-1a:    10.0.20.0/24 (DB tier)
  data-1b:    10.0.21.0/24 (DB tier)

Gateways:
  igw-main: Internet Gateway
  nat-prod-01: NAT Gateway (public-1a)

Route Tables: 4 configured`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 enable-flow-logs ")) {
    output = `=== VPC Flow Logs Enabled ===

[OK] Flow logs created for VPC
[OK] Destination: CloudWatch Logs
[OK] Traffic type: ALL
[OK] Capture format: Default + custom fields

Flow logs now capturing all traffic.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-nat ") || lowerCmd.startsWith("aws ec2 describe-eips") || lowerCmd.startsWith("aws ec2 plan-nat-architecture ")) {
    output = `=== NAT Gateway Configuration ===

NAT Gateways:
  nat-prod-01: 10.0.1.0/24 (Active)
  nat-prod-02: 10.0.2.0/24 (Standby)

Elastic IPs:
  eip-nat-01: 52.1.2.3 (attached)
  eip-nat-02: 52.1.2.4 (attached)
  eip-unattached: 52.1.2.5 (unused - cost!)

High availability: Enabled`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 create-nat ") || lowerCmd.startsWith("aws ec2 update-routes-multi-nat ")) {
    output = `=== NAT Gateway Created ===

[OK] NAT Gateway provisioned
[OK] Elastic IP attached
[OK] Route tables updated
[OK] High availability configured

Multi-AZ NAT architecture complete.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 release-eip ")) {
    output = `=== Elastic IP Released ===

[OK] EIP released: 52.1.2.5
[OK] Cost savings: ~$3.60/month

Unused resources cleaned up.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-vpn ") || lowerCmd.startsWith("aws ec2 describe-cgw ") || lowerCmd.startsWith("aws ec2 describe-tgw ")) {
    output = `=== VPN/Transit Gateway Configuration ===

VPN Connection:
  Status: UP
  Tunnels: 2/2 active
  Encryption: AES-256
  
Customer Gateway:
  IP: 203.0.113.50
  BGP ASN: 65000
  
Transit Gateway:
  Attachments: 5 VPCs
  Routes: 12 propagated

Connectivity: Healthy`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 reset-vpn ") || lowerCmd.startsWith("aws ec2 fix-tgw-routes ")) {
    output = `=== VPN/TGW Configuration Fixed ===

[OK] Tunnels renegotiated
[OK] Routes corrected
[OK] BGP sessions re-established
[OK] Connectivity restored

Hybrid connectivity operational.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-nacl ") || lowerCmd.startsWith("aws ec2 fix-nacl ")) {
    output = `=== Network ACL Configuration ===

[OK] NACL rules reviewed
[OK] Deny rules added for malicious IPs
[OK] Ephemeral ports configured
[OK] Stateless rules optimized

Network layer security enhanced.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-peering ") || lowerCmd.startsWith("aws ec2 restrict-peering ")) {
    output = `=== VPC Peering Configuration ===

[OK] Peering connection reviewed
[OK] Route tables restricted
[OK] Only required CIDRs allowed
[OK] Cross-account access limited

Peering security improved.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 implement-network-segmentation ") || lowerCmd === "aws ec2 assess-network-security") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      // Mark all vulnerable resources as fixed for this lab
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Network Segmentation Implemented ===

[OK] Created public subnet (10.0.1.0/24) for web tier
[OK] Created private subnet (10.0.2.0/24) for app tier  
[OK] Created data subnet (10.0.3.0/24) for database tier
[OK] Configured NAT gateway for private subnet egress
[OK] Updated route tables with proper isolation
[OK] Moved web-01 to public subnet
[OK] Moved app-01 to private subnet
[OK] Moved db-01 to isolated data subnet
[OK] Disabled public accessibility for RDS

Defense-in-depth architecture complete.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Network segmentation implemented!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Network Segmentation Status ===

Network is already properly segmented.
  - Public subnet: Web tier
  - Private subnet: App tier
  - Data subnet: Database tier

All tiers properly isolated.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 create-traffic-mirror ")) {
    output = `=== Traffic Mirroring Configured ===

[OK] Mirror session created
[OK] Filter rules applied
[OK] Target configured
[OK] Packet capture ready

Network forensics enabled.`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 enable-ebs-encryption" || lowerCmd === "aws ec2 list-resource-placement") {
    output = `=== EBS Encryption / Resource Status ===

[OK] Default EBS encryption: Enabled
[OK] KMS key: aws/ebs (AWS managed)
[OK] All new volumes will be encrypted

Resource Placement:
  AZ-a: 6 instances, 12 volumes
  AZ-b: 6 instances, 12 volumes
  Multi-AZ: Properly distributed`;
    success = true;
  }
  // ============= GUARDDUTY COMMANDS =============
  else if (lowerCmd.startsWith("aws guardduty classify-finding ")) {
    output = `=== GuardDuty Finding Classified ===

[OK] Finding classified as: True Positive
[OK] Severity: HIGH
[OK] Investigation notes added
[OK] Workflow triggered

Finding archived after classification.`;
    success = true;
  }
  else if (lowerCmd === "aws guardduty configure-iam-findings") {
    output = `=== GuardDuty IAM Findings Configured ===

[OK] UnauthorizedAccess:IAMUser - Enabled
[OK] PrivilegeEscalation - Enabled  
[OK] Persistence - Enabled
[OK] CredentialAccess - Enabled

IAM-specific threat detection active.`;
    success = true;
  }
  else if (lowerCmd === "aws guardduty enable-organization") {
    output = `=== GuardDuty Organization Enabled ===

[OK] Delegated administrator set
[OK] Auto-enable for new accounts
[OK] 47 member accounts enrolled
[OK] Centralized findings dashboard

Organization-wide threat detection active.`;
    success = true;
  }
  else if (lowerCmd === "aws guardduty generate-sample-findings") {
    output = `=== Sample Findings Generated ===

Created 10 sample findings:
  - UnauthorizedAccess:IAMUser/ConsoleLogin
  - Recon:IAMUser/MaliciousIPCaller
  - Exfiltration:S3/MaliciousIPCaller
  - CryptoCurrency:EC2/BitcoinTool
  - Impact:EC2/PortSweep

Use these for testing detection workflows.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws guardduty get-finding ")) {
    output = `=== GuardDuty Finding Details ===

Finding: Console login from malicious IP
Severity: HIGH (8.0)
Type: UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B

Resource:
  User: admin-user
  IP: 198.51.100.45
  Location: Netherlands

Threat Intel:
  Known Tor exit node
  Previously used in attacks

Recommendation: Reset credentials immediately`;
    success = true;
  }
  // ============= IAM ADVANCED COMMANDS =============
  else if (lowerCmd === "aws iam list-privileged-users-mfa" || lowerCmd.startsWith("aws iam list-privileged")) {
    output = `=== Privileged Users MFA Status ===

User                 Privilege    MFA
----                 ---------    ---
root                 ROOT         [!] NONE
cloud-admin          Admin        [!] NONE
devops-lead          PowerUser    [OK] Enabled
security-admin       Admin        [!] NONE
emergency-access     Admin        [OK] Enabled

WARNING: 3 admin users without MFA!`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam create-permission-boundary") || lowerCmd.startsWith("aws iam create-permission-boundaries")) {
    output = `=== Permission Boundary Created ===

[OK] Boundary policy created
[OK] Maximum permissions defined
[OK] Prevents privilege escalation
[OK] Applied to developer roles

Guardrails now in place.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam apply-permission-boundaries") || lowerCmd.startsWith("aws iam enforce-boundary ")) {
    const iamRes = resources.find(r => (r.type === 'iam' || r.type === 'policies' || r.name?.includes('role') || r.name?.includes('developer')) && r.isVulnerable);
    if (iamRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Permission Boundaries Enforced ===

[OK] DeveloperBoundary created and attached
[OK] Maximum permissions capped for all dev roles
[OK] iam:CreatePolicy blocked for developers
[OK] iam:AttachUserPolicy restricted
[OK] Privilege escalation paths eliminated
[OK] Audit logging enabled

Developers can now create roles safely within guardrails.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Permission boundaries enforced!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Permission Boundaries Applied ===

[OK] Boundary attached to 15 roles
[OK] Developer permissions capped
[OK] Service roles protected
[OK] Audit logging enabled

All roles now operate within boundaries.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws iam enforce-mfa-policy") {
    output = `=== MFA Policy Enforced ===

[OK] SCP created: RequireMFA
[OK] Applied to all OUs
[OK] Deny actions without MFA
[OK] Grace period: 24 hours

All privileged actions now require MFA.`;
    success = true;
  }
  else if (lowerCmd === "aws iam get-root-account-summary") {
    output = `=== Root Account Summary ===

MFA Status: [!] NOT ENABLED
Access Keys: [!] 1 ACTIVE KEY FOUND
Last Login: 2024-01-10 (30 days ago)

CRITICAL ISSUES:
  1. Root account lacks MFA
  2. Access key should be deleted
  3. Root should only be used for billing

Immediate action required!`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam find-unused") || lowerCmd.startsWith("aws iam cleanup")) {
    output = `=== Unused IAM Resources ===

Unused Credentials (90+ days):
  - contractor-alex (180 days)
  - temp-deploy-key (120 days)
  - old-service-account (95 days)

Unused Roles:
  - LegacyAppRole (never used)
  - TestDeployRole (6 months)

Cleanup recommended.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam simulate-escalation") || lowerCmd.startsWith("aws iam analyze-escalation")) {
    output = `=== Privilege Escalation Analysis ===

Escalation Paths Found: 12

Critical Paths:
  [!] dev-user → iam:PassRole → AdminLambda → Admin
  [!] cicd-role → iam:CreatePolicy → Self-escalate
  [!] service-role → sts:AssumeRole → CrossAccount

Recommendations:
  1. Add permission boundaries
  2. Restrict iam:PassRole
  3. Remove iam:CreatePolicy from developers`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam generate-escalation-runbook") || lowerCmd.startsWith("aws iam generate-security-report")) {
    output = `=== Security Report Generated ===

Report: iam-security-${new Date().toISOString().split('T')[0]}.pdf

Contents:
  - Permission analysis
  - Escalation paths
  - Remediation steps
  - Compliance mapping

Exported to security reports bucket.`;
    success = true;
  }
  // ============= ORGANIZATIONS & SECURITY HUB =============
  else if (lowerCmd.startsWith("aws organizations ") || lowerCmd === "aws organizations implement-scps") {
    output = `=== Organizations Configuration ===

[OK] Service Control Policies applied
[OK] Guardrails enforced
[OK] Account isolation verified
[OK] Delegated administrators set

Organization security posture improved.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws securityhub ") || lowerCmd === "aws securityhub enable-organization" || lowerCmd === "aws securityhub assess-compliance") {
    output = `=== Security Hub Status ===

[OK] Security Hub enabled organization-wide
[OK] CIS AWS Foundations: 87% compliant
[OK] AWS Foundational Security: 92% compliant
[OK] PCI DSS: 78% compliant

Findings aggregated from all accounts.`;
    success = true;
  }
  else if (lowerCmd === "aws config enable-organization") {
    output = `=== AWS Config Organization Enabled ===

[OK] Config rules deployed to all accounts
[OK] Conformance packs applied
[OK] Aggregator configured
[OK] Remediation automation enabled

Continuous compliance monitoring active.`;
    success = true;
  }
  // ============= LOGGING & ASSESSMENT =============
  else if (lowerCmd === "aws assess-data-protection" || lowerCmd === "aws assess-logging-coverage") {
    output = `=== Security Assessment ===

Data Protection:
  [OK] S3: 95% encrypted
  [!] EBS: 80% encrypted
  [OK] RDS: 100% encrypted

Logging Coverage:
  [OK] CloudTrail: All regions
  [!] VPC Flow Logs: 60% coverage
  [OK] S3 Access Logs: 85%

Recommendations provided in report.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws logs configure-siem-forwarding") || lowerCmd.startsWith("aws logs configure")) {
    output = `=== Log Forwarding Configured ===

[OK] CloudTrail → SIEM
[OK] VPC Flow Logs → SIEM
[OK] GuardDuty Findings → SIEM
[OK] CloudWatch Logs → SIEM

All security logs now forwarded.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws network implement-central-security")) {
    output = `=== Central Network Security Implemented ===

[OK] Network Firewall deployed
[OK] VPC Flow Logs centralized
[OK] DNS Firewall enabled
[OK] Transit Gateway inspection

Centralized network controls active.`;
    success = true;
  }
  else if (lowerCmd === "aws security configure-soc-integration" || lowerCmd === "aws security generate-architecture-docs" || lowerCmd === "aws security verify-encryption-compliance") {
    output = `=== Security Configuration Complete ===

[OK] SOC integration configured
[OK] Architecture documented
[OK] Encryption verified
[OK] Compliance validated

Security posture: GOOD`;
    success = true;
  }
  // ============= CLOUDWATCH COMMANDS =============
  else if (lowerCmd.startsWith("aws cloudwatch get-nat-metrics ") || lowerCmd.startsWith("aws cloudwatch get-vpn-metrics ") || lowerCmd.startsWith("aws cloudwatch get-baseline ")) {
    output = `=== CloudWatch Metrics ===

Resource Metrics (Last 24h):
  CPU Utilization: 45% avg (normal)
  Network In: 2.3 GB
  Network Out: 1.8 GB
  Connections: 1,247
  
Baseline Comparison:
  [OK] Within normal parameters
  [!] Network out 15% above baseline

Alarm Status: No active alarms`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudwatch create-nat-alarm ")) {
    output = `=== CloudWatch Alarm Created ===

[OK] Alarm: NAT-HighUtilization
[OK] Threshold: 80%
[OK] Period: 5 minutes
[OK] Actions: SNS notification

Alarm now monitoring NAT gateway.`;
    success = true;
  }
  // ============= ECS/ELB COMMANDS =============
  else if (lowerCmd.startsWith("aws ecs describe-task ")) {
    output = `=== ECS Task Details ===

Task: ecs-task-1
Cluster: production
Status: RUNNING
CPU: 256
Memory: 512

Containers:
  app-container: RUNNING
  sidecar: RUNNING

Network: awsvpc mode
Security Group: ecs-tasks-sg`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws elbv2 describe-target-group ") || lowerCmd.startsWith("aws elbv2 describe-target-health ")) {
    output = `=== Target Group Status ===

Target Group: tg-api-containers
Protocol: HTTP
Port: 8080

Targets:
  10.0.10.15:8080 - healthy
  10.0.10.16:8080 - healthy
  10.0.11.15:8080 - healthy
  10.0.11.16:8080 - unhealthy (timeout)

Health Check: /api/health`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws elbv2 modify-target-group ")) {
    output = `=== Target Group Updated ===

[OK] Health check path updated
[OK] Health check port configured
[OK] Thresholds adjusted
[OK] Changes applied

Target group configuration optimized.`;
    success = true;
  }
  // ============= EVENTBRIDGE COMMANDS =============
  else if (lowerCmd.startsWith("aws events describe-rule ")) {
    const ruleName = lowerCmd.replace("aws events describe-rule ", "").trim();
    output = `=== EventBridge Rule: ${ruleName} ===

State: ENABLED
Schedule: None (event-based)
Event Pattern: IAM policy changes

Targets:
  - Lambda: notify-security
  - SNS: security-alerts

[!] WARNING: Rule appears malicious`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws events delete-rule ")) {
    output = `=== EventBridge Rule Deleted ===

[OK] Rule disabled
[OK] Targets removed
[OK] Rule deleted
[OK] Audit logged

Malicious persistence removed.`;
    success = true;
  }
  else if (lowerCmd === "aws events create-ir-triggers") {
    output = `=== IR Trigger Rules Created ===

[OK] GuardDuty findings → IR workflow
[OK] Security Hub findings → IR workflow
[OK] CloudWatch alarms → IR workflow

Automated incident response enabled.`;
    success = true;
  }
  // ============= WAF COMMANDS =============
  else if (lowerCmd.startsWith("aws waf add-ip-blocklist ")) {
    output = `=== WAF IP Blocklist Updated ===

[OK] IP added to blocklist
[OK] Rule priority: 1 (highest)
[OK] Action: BLOCK
[OK] Applied to web ACL

Malicious IP now blocked at edge.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws waf associate ") || lowerCmd.startsWith("aws waf check-association ")) {
    output = `=== WAF Association Status ===

Web ACL: production-waf
Resources:
  [OK] alb-web-frontend - Associated
  [OK] cloudfront-cdn - Associated

Rules Active: 12
Requests Blocked (24h): 1,247`;
    success = true;
  }
  // ============= SSM COMMANDS =============
  else if (lowerCmd.startsWith("aws ssm get-process-logs ")) {
    output = `=== SSM Process Logs ===

Instance: analytics-server-01

Recent Processes:
  [ALERT] xmrig - Crypto miner detected
  [ALERT] curl - Downloading from C2
  [OK] nginx - Web server
  [OK] node - Application

Suspicious activity detected.`;
    success = true;
  }
  // ============= STEP FUNCTIONS =============
  else if (lowerCmd.startsWith("aws stepfunctions ")) {
    output = `=== Step Functions Configuration ===

[OK] IR workflow created
[OK] Approval gates added
[OK] Notifications configured
[OK] Audit logging enabled

Automated workflow ready.`;
    success = true;
  }
  // ============= SNS/SQS COMMANDS =============
  else if (lowerCmd === "aws sns-sqs audit-policies") {
    output = `=== SNS/SQS Policy Audit ===

Topics/Queues Analyzed: 15

Issues Found:
  [!] alerts-topic: Public access
  [!] processing-queue: Cross-account
  [OK] audit-logs: Properly scoped

Remediation recommended.`;
    success = true;
  }
  // ============= SOAR COMMANDS =============
  else if (lowerCmd === "soar connect" || lowerCmd === "soar login") {
    output = `=== SOAR Platform Connected ===

[OK] Authenticating to CloudShield SOAR...
[OK] Loading playbook library...
[OK] Synchronizing case management...

Connected to SOAR Dashboard
  Active Playbooks: 12
  Pending Cases: 3
  Automation Rate: 78%

Available Commands:
  soar show-workflow <name>  - View playbook workflow
  soar create-playbook <name> - Create new playbook
  soar activate <name>       - Activate playbook`;
    success = true;
  }
  else if (lowerCmd.startsWith("soar show-workflow ")) {
    const playbook = lowerCmd.replace("soar show-workflow ", "").trim();
    output = `=== Playbook Workflow: ${playbook} ===

Steps:
  1. [TRIGGER] Alert received from SIEM
  2. [ENRICH] Lookup IP reputation
  3. [ENRICH] Check user risk score
  4. [DECIDE] If malicious -> quarantine
  5. [ACTION] Block source IP
  6. [ACTION] Reset user credentials
  7. [NOTIFY] Alert SOC analyst
  8. [CLOSE] Update ticket status

Automation Level: Semi-automated
Requires Approval: Steps 4, 6
Average Runtime: 3 minutes`;
    success = true;
  }
  else if (lowerCmd.startsWith("soar create-playbook ")) {
    const name = lowerCmd.replace("soar create-playbook ", "").trim();
    output = `=== Playbook Created: ${name} ===

[OK] Playbook template initialized
[OK] Default triggers configured
[OK] Action library linked

Playbook: ${name}
Status: DRAFT
Steps: 0

Use 'soar add-step ${name} <action>' to add steps.`;
    success = true;
  }
  else if (lowerCmd.startsWith("soar add-step ")) {
    const parts = lowerCmd.replace("soar add-step ", "").trim().split(" ");
    const playbook = parts[0];
    const step = parts.slice(1).join(" ") || "action";
    output = `=== Step Added to ${playbook} ===

[OK] Step added: ${step}
[OK] Workflow updated

Current steps in ${playbook}:
  1. ${step}

Use 'soar activate ${playbook}' when ready.`;
    success = true;
  }
  else if (lowerCmd.startsWith("soar activate ")) {
    const name = lowerCmd.replace("soar activate ", "").trim();
    output = `=== Playbook Activated: ${name} ===

[OK] Validation passed
[OK] Triggers armed
[OK] Monitoring active

Playbook ${name} is now LIVE.
It will automatically respond to matching alerts.`;
    success = true;
  }
  // ============= THREAT INTEL COMMANDS =============
  else if (lowerCmd === "threat-intel list-feeds" || lowerCmd === "threatintel list-feeds") {
    output = `=== Threat Intelligence Feeds ===

ACTIVE FEEDS:
  [OK] MISP Community Feed    - 45,231 IOCs
  [OK] AlienVault OTX         - 128,456 IOCs
  [OK] Abuse.ch URLhaus       - 12,890 URLs
  [OK] EmergingThreats        - 8,456 rules

AVAILABLE:
  [ ] VirusTotal Premium     - Requires API key
  [ ] Recorded Future        - Enterprise license
  [ ] ThreatConnect          - Not configured

Last Sync: ${new Date(Date.now() - 3600000).toISOString()}
Next Sync: ${new Date(Date.now() + 3600000).toISOString()}`;
    success = true;
  }
  else if (lowerCmd.startsWith("threat-intel configure ") || lowerCmd.startsWith("threatintel configure ")) {
    const feed = lowerCmd.replace("threat-intel configure ", "").replace("threatintel configure ", "").trim();
    output = `=== Configuring Feed: ${feed} ===

[OK] Feed endpoint validated
[OK] Authentication configured
[OK] Sync schedule set (hourly)
[OK] IOC types: IP, Domain, Hash, URL

Feed ${feed} is now configured and syncing.`;
    success = true;
  }
  else if (lowerCmd.startsWith("threat-intel status ") || lowerCmd.startsWith("threatintel status ")) {
    const feed = lowerCmd.replace("threat-intel status ", "").replace("threatintel status ", "").trim();
    output = `=== Feed Status: ${feed} ===

Status: HEALTHY
Last Sync: ${new Date(Date.now() - 3600000).toISOString()}
IOCs Loaded: 45,231
Match Rate: 0.3%
False Positive Rate: 2.1%`;
    success = true;
  }
  else if (lowerCmd.startsWith("threat-intel analyze ") || lowerCmd.startsWith("threatintel analyze ")) {
    const feed = lowerCmd.replace("threat-intel analyze ", "").replace("threatintel analyze ", "").trim();
    output = `=== Feed Analysis: ${feed} ===

IOC Distribution:
  IP Addresses:  45% (20,354)
  Domains:       30% (13,569)
  File Hashes:   20% (9,046)
  URLs:          5%  (2,262)

Threat Categories:
  Malware C2:    35%
  Phishing:      25%
  Botnets:       20%
  Ransomware:    15%
  Other:         5%

Quality Score: 87/100`;
    success = true;
  }
  else if (lowerCmd.startsWith("threat-intel create-alerts ") || lowerCmd.startsWith("threatintel create-alerts ")) {
    const feed = lowerCmd.replace("threat-intel create-alerts ", "").replace("threatintel create-alerts ", "").trim();
    output = `=== Alert Rules Created for ${feed} ===

[OK] IP match -> HIGH alert
[OK] Domain match -> MEDIUM alert
[OK] Hash match -> CRITICAL alert
[OK] URL match -> MEDIUM alert

Rules active and monitoring traffic.`;
    success = true;
  }
  else if (lowerCmd.startsWith("threat-intel enable-matching ") || lowerCmd.startsWith("threatintel enable-matching ")) {
    const feed = lowerCmd.replace("threat-intel enable-matching ", "").replace("threatintel enable-matching ", "").trim();
    output = `=== IOC Matching Enabled for ${feed} ===

[OK] Real-time matching active
[OK] Log sources connected
[OK] Alert pipeline configured

IOC matching is now live for ${feed}.`;
    success = true;
  }
  else if (lowerCmd.startsWith("threatintel lookup-ip ")) {
    const ip = lowerCmd.replace("threatintel lookup-ip ", "").trim();
    output = `=== Threat Intel Lookup: ${ip} ===

Reputation: MALICIOUS
Confidence: 95%
Category: Known C2 Infrastructure

Sources:
  [HIT] AlienVault OTX - APT-29 campaign
  [HIT] Abuse.ch - Malware distribution
  [HIT] EmergingThreats - Active C2

First Seen: 2024-06-15
Last Seen: ${new Date().toISOString().split('T')[0]}
Reports: 1,247

[!] HIGH RISK - Recommend blocking immediately`;
    success = true;
  }
  // ============= THREAT HUNTING COMMANDS =============
  else if (lowerCmd === "hunt create-hypothesis" || lowerCmd === "hunt hypothesis") {
    output = `=== Threat Hunt Hypothesis ===

Creating hypothesis based on threat intelligence...

Hypothesis: Adversary has compromised cloud credentials and is 
exfiltrating data via S3.

Indicators to Hunt:
  1. Unusual S3 API calls from new IPs
  2. Large data transfers outside business hours
  3. Access to sensitive buckets by non-standard users
  4. AssumeRole from unknown locations

MITRE ATT&CK Techniques:
  T1078.004 - Cloud Accounts
  T1530 - Data from Cloud Storage Object
  T1537 - Transfer Data to Cloud Account

Use 'hunt select-techniques cloud' to proceed.`;
    success = true;
  }
  else if (lowerCmd.startsWith("hunt select-techniques ")) {
    const category = lowerCmd.replace("hunt select-techniques ", "").trim();
    output = `=== Selected Techniques: ${category} ===

Cloud-specific techniques selected:

[X] T1078.004 - Cloud Accounts
    Hunt for: Unusual login locations, time anomalies
    
[X] T1530 - Data from Cloud Storage Object
    Hunt for: Bulk S3 GetObject from new principals
    
[X] T1525 - Implant Internal Image
    Hunt for: Modified AMIs, container images
    
[X] T1537 - Transfer Data to Cloud Account
    Hunt for: Cross-account data copies

Use 'hunt build-queries T1078.004 T1530 T1525' to create queries.`;
    success = true;
  }
  else if (lowerCmd.startsWith("hunt build-queries ")) {
    output = `=== Hunt Queries Built ===

Generated queries for selected techniques:

Query 1 (T1078.004):
  SELECT * FROM cloudtrail_logs 
  WHERE eventName = 'ConsoleLogin'
  AND sourceIPAddress NOT IN (known_ips)
  
Query 2 (T1530):
  SELECT * FROM cloudtrail_logs
  WHERE eventName = 'GetObject'
  GROUP BY userIdentity.arn
  HAVING count(*) > 1000

Query 3 (T1525):
  SELECT * FROM cloudtrail_logs
  WHERE eventName IN ('RegisterImage', 'PushImage')

Use 'hunt execute T1078.004' to run queries.`;
    success = true;
  }
  else if (lowerCmd.startsWith("hunt execute ")) {
    const technique = lowerCmd.replace("hunt execute ", "").trim();
    output = `=== Hunt Execution: ${technique} ===

Running hunt query...

Results Found: 23 events

Suspicious Findings:
  [!] 5 console logins from Tor exit nodes
  [!] 3 API calls from new geographic locations
  [!] 8 bulk S3 downloads after hours
  [!] 7 AssumeRole from unusual principals

Confidence: MEDIUM-HIGH (67%)

Use 'hunt analyze-results' to investigate.`;
    success = true;
  }
  else if (lowerCmd === "hunt analyze-results") {
    output = `=== Hunt Results Analysis ===

Aggregating findings across techniques...

Timeline:
  2024-01-15 03:00 - Unusual ConsoleLogin (T1078)
  2024-01-15 03:15 - Bulk S3 GetObject (T1530)
  2024-01-15 03:45 - Cross-region data copy (T1537)

Attack Chain Identified:
  Initial Access -> Data Collection -> Exfiltration

Affected Resources:
  - IAM User: compromised-admin
  - S3 Buckets: customer-data, financial-reports
  - Estimated Data: 2.3 TB

Risk: CRITICAL

Use 'hunt investigate-findings' for deep dive.`;
    success = true;
  }
  else if (lowerCmd === "hunt investigate-findings") {
    output = `=== Findings Investigation ===

Deep dive on suspicious items...

Finding 1: Compromised Credentials
  Evidence: Login from known Tor exit node
  User: compromised-admin
  Verdict: TRUE POSITIVE
  
Finding 2: Data Exfiltration
  Evidence: 2.3 TB transferred to external account
  Timeframe: 03:00-05:00 UTC
  Verdict: TRUE POSITIVE
  
Finding 3: Persistence Attempt
  Evidence: New IAM user created with admin rights
  User: backdoor-user
  Verdict: TRUE POSITIVE

Escalating to Incident Response.`;
    success = true;
  }
  else if (lowerCmd === "hunt document-findings") {
    output = `=== Hunt Documentation ===

Recording findings...

Hunt ID: HNT-${Date.now().toString(36).toUpperCase()}
Date: ${new Date().toISOString()}
Analyst: Current User

Findings Documented:
  - 3 True Positives
  - 0 False Positives
  - Attack chain confirmed

Evidence preserved in case file.
Handoff to IR team complete.`;
    success = true;
  }
  else if (lowerCmd === "hunt create-detections") {
    output = `=== Detection Rules Created ===

Converting hunt findings to detections...

[OK] Rule: Unusual ConsoleLogin Location
     Technique: T1078.004
     Severity: HIGH
     
[OK] Rule: Bulk S3 Data Access
     Technique: T1530
     Severity: CRITICAL
     
[OK] Rule: Cross-Account Data Transfer
     Technique: T1537
     Severity: CRITICAL

3 new detection rules deployed.
Future attacks using these techniques will be caught automatically.`;
    success = true;
  }
  else if (lowerCmd === "hunt generate-report") {
    output = `=== Threat Hunt Report Generated ===

Report ID: THR-${Date.now().toString(36).toUpperCase()}

Executive Summary:
  Hunt Duration: 2 hours
  Techniques Hunted: 3
  Findings: 3 confirmed compromises
  
Key Discoveries:
  1. Active data exfiltration detected
  2. Compromised admin credentials identified
  3. Persistence mechanism discovered
  
Remediation Status:
  - Credentials rotated
  - Backdoor user removed
  - Data transfer blocked
  
Recommendations:
  1. Implement stronger MFA
  2. Enable CloudTrail data events
  3. Deploy SIEM correlation rules

Report exported to: /reports/threat-hunt-${new Date().toISOString().split('T')[0]}.pdf`;
    success = true;
  }
  else if (lowerCmd === "hunt search-iocs") {
    output = `=== IOC Search Results ===

Searching for known indicators...

Matches Found:
  [HIT] IP 198.51.100.45 - Known C2 infrastructure
  [HIT] IP 185.220.101.42 - Tor exit node
  [HIT] Domain: evil-exfil.com - Data staging
  
No Matches:
  [ ] File hashes - No malware detected
  [ ] Email addresses - No phishing indicators

2 high-confidence IOC matches found.
Recommend immediate investigation.`;
    success = true;
  }
  // ============= INCIDENT RESPONSE (IR) COMMANDS =============
  else if (lowerCmd.startsWith("aws ir ") || lowerCmd === "aws ir contain-ransomware ransomware-active" || lowerCmd === "aws ir create-war-room" || lowerCmd === "aws ir eradicate-persistence" || lowerCmd === "aws ir execute-containment" || lowerCmd === "aws ir generate-incident-report" || lowerCmd === "aws ir generate-runbooks" || lowerCmd === "aws ir implement-improvements" || lowerCmd.startsWith("aws ir revoke-all-credentials")) {
    output = `=== Incident Response Executed ===

[OK] War room established
[OK] Containment measures deployed
[OK] Credentials revoked
[OK] Persistence mechanisms removed
[OK] Forensic evidence preserved
[OK] Incident report generated

IR playbook execution complete.
All affected systems isolated and secured.`;
    success = true;
  }
  // ============= RANSOMWARE COMMANDS =============
  else if (lowerCmd.startsWith("aws ransomware ") || lowerCmd === "aws ransomware isolate-all-encrypted") {
    output = `=== Ransomware Containment ===

[OK] Encrypted systems identified
[OK] Network isolation applied
[OK] Backup status verified
[OK] Recovery plan initiated
[OK] Law enforcement notified

All encrypted systems quarantined.
Clean backups available for restore.`;
    success = true;
  }
  // ============= STS COMMANDS =============
  else if (lowerCmd === "aws sts revoke-all-sessions" || lowerCmd.startsWith("aws sts revoke")) {
    output = `=== STS Sessions Revoked ===

[OK] All active sessions invalidated
[OK] Temporary credentials expired
[OK] Role assumptions terminated
[OK] Federation tokens revoked

All STS sessions have been terminated.
Users must re-authenticate.`;
    success = true;
  }
  // ============= GLACIER COMMANDS =============
  else if (lowerCmd.startsWith("aws glacier ")) {
    output = `=== Glacier Vault Updated ===

[OK] Vault access policy modified
[OK] Unauthorized access removed
[OK] Vault lock applied
[OK] Audit logging enabled

Data archive security enhanced.`;
    success = true;
  }
  // ============= EFS COMMANDS =============
  else if (lowerCmd.startsWith("aws efs ")) {
    output = `=== EFS Configuration Updated ===

[OK] Mount target security verified
[OK] Access points configured
[OK] Encryption enforced
[OK] Unauthorized mounts removed

EFS file system secured.`;
    success = true;
  }
  // ============= BACKUP COMMANDS =============
  else if (lowerCmd.startsWith("aws backup ")) {
    output = `=== AWS Backup Restored ===

[OK] Immutable backup identified
[OK] Restore job initiated
[OK] Point-in-time recovery: Available
[OK] Clean data restored

Backup restore completed successfully.`;
    success = true;
  }
  // ============= RDS COMMANDS =============
  else if (lowerCmd.startsWith("aws rds enable-encryption ")) {
    output = `=== RDS Encryption Enabled ===

[OK] Snapshot created
[OK] Encrypted copy initiated
[OK] New instance launched
[OK] DNS endpoint updated

Database encryption migration complete.`;
    success = true;
  }
  // ============= DATASYNC COMMANDS =============
  else if (lowerCmd.startsWith("aws datasync stop-job ") || lowerCmd.startsWith("aws datasync stop-task ")) {
    output = `=== DataSync Task Stopped ===

[OK] Sync task terminated
[OK] Data transfer halted
[OK] Exfiltration blocked
[OK] Audit trail captured

Unauthorized data movement stopped.`;
    success = true;
  }
  // ============= LAMBDA DELETE COMMANDS =============
  else if (lowerCmd.startsWith("aws lambda delete-function ") || lowerCmd.startsWith("aws lambda delete-layer ") || lowerCmd.startsWith("aws lambda create-containment")) {
    output = `=== Lambda Function Removed ===

[OK] Malicious function identified
[OK] Invocations terminated
[OK] Function deleted
[OK] IAM role detached
[OK] CloudWatch logs preserved

Persistence mechanism eliminated.`;
    success = true;
  }
  // ============= KMS ADVANCED COMMANDS =============
  else if (lowerCmd.startsWith("aws kms cancel-deletion ")) {
    output = `=== KMS Key Deletion Cancelled ===

[OK] Key: kms-prod-encryption
[OK] Status: Enabled
[OK] Deletion cancelled
[OK] Key available for use

Critical encryption key preserved.`;
    success = true;
  }
  else if (lowerCmd === "aws kms create-classification-keys" || lowerCmd === "aws kms enable-key-rotation-all") {
    output = `=== KMS Keys Configured ===

[OK] Classification keys created
[OK] Key rotation enabled
[OK] Key policies hardened
[OK] Alias mappings updated

Encryption key management enhanced.`;
    success = true;
  }
  // ============= SSM ADVANCED COMMANDS =============
  else if (lowerCmd.startsWith("aws ssm terminate-session ") || lowerCmd === "aws ssm terminate ssm-session-xyz") {
    output = `=== SSM Session Terminated ===

[OK] Covert session identified
[OK] Session terminated
[OK] Access revoked
[OK] Audit logged

Unauthorized SSM session eliminated.`;
    success = true;
  }
  else if (lowerCmd === "aws ssm list-sessions") {
    output = `=== Active SSM Sessions ===

Session ID           Target          User
-----------          ------          ----
ssm-session-001     i-0abc123       admin
ssm-session-xyz     i-0def456       UNKNOWN [!]
ssm-session-003     i-0ghi789       devops

[!] WARNING: Suspicious session detected`;
    success = true;
  }
  // ============= ORGANIZATIONS ADVANCED COMMANDS =============
  else if (lowerCmd.startsWith("aws organizations apply-scp ") || lowerCmd.startsWith("aws organizations create-escalation-scp") || lowerCmd === "aws organizations create-security-account" || lowerCmd.startsWith("aws organizations enable-scps ") || lowerCmd === "aws organizations configure-scps" || lowerCmd === "aws organizations implement-scps") {
    output = `=== Organization SCPs Applied ===

[OK] Service Control Policies created
[OK] Guardrails enforced across OUs
[OK] External trust denied by default
[OK] Privileged actions restricted
[OK] Audit trail enabled

Organization-wide security controls active.`;
    success = true;
  }
  // ============= IAM ADVANCED COMMANDS =============
  else if (lowerCmd.startsWith("aws iam add-federation-conditions") || lowerCmd.startsWith("aws iam break-role-chain ")) {
    output = `=== IAM Federation Fixed ===

[OK] Federation conditions added
[OK] Role chain broken
[OK] Trust policies hardened
[OK] Session duration limited

Privilege escalation paths eliminated.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam cleanup-inactive-users") || lowerCmd.startsWith("aws iam cleanup-service-roles")) {
    const iamRes = resources.find(r => (r.type === 'iam_user' || r.type === 'iam' || r.type === 'users' || r.name?.includes('inactive') || r.name?.includes('employee') || r.name?.includes('service')) && r.isVulnerable);
    if (iamRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'cleaned' });
      }
      output = `=== IAM Cleanup Complete ===

[OK] Inactive users disabled: former-employee, old-service-acct
[OK] Stale access keys deleted: 3 keys older than 90 days
[OK] Unused roles removed: LegacyAppRole, TestDeployRole
[OK] Orphaned policies deleted: 8 unattached policies
[OK] Service accounts audited and cleaned

Identity hygiene restored. Attack surface reduced.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] IAM cleanup complete!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== IAM Cleanup Complete ===

[OK] Inactive users disabled: 5
[OK] Stale roles removed: 3
[OK] Unused policies deleted: 8
[OK] Access keys rotated: 12

Identity hygiene improved.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam delete-role ") || lowerCmd.startsWith("aws iam delete-access-key ")) {
    const target = lowerCmd.split(" ").pop();
    output = `=== IAM Resource Deleted: ${target} ===

[OK] Resource identified as malicious
[OK] Permissions revoked
[OK] Resource deleted
[OK] Audit trail preserved

Backdoor access eliminated.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam disable-user ")) {
    const user = lowerCmd.replace("aws iam disable-user ", "").trim();
    const iamRes = resources.find(r => (r.type === 'iam_user' || r.type === 'iam' || r.name === user || r.name?.includes(user)) && r.isVulnerable);
    if (iamRes) {
      await storage.updateResource(iamRes.id, { isVulnerable: false, status: 'disabled' });
      output = `=== User Disabled: ${user} ===

[OK] Console access revoked
[OK] API access revoked
[OK] All access keys deactivated
[OK] MFA deregistered
[OK] All active sessions terminated
[OK] User marked for deletion review

User account locked and secured.`;
      success = true;
      const remaining = resources.filter(r => r.id !== iamRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] User disabled and secured!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== User Disabled: ${user} ===

[OK] Console access revoked
[OK] API access revoked
[OK] MFA deregistered
[OK] Sessions terminated

User account locked.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws iam enable-root-mfa") {
    const rootRes = resources.find(r => (r.type === 'root' || r.type === 'iam_root' || r.name?.includes('root')) && r.isVulnerable);
    if (rootRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Root Account MFA Enabled ===

[OK] Hardware MFA device registered
[OK] Virtual MFA as backup
[OK] Access keys deleted
[OK] Password rotated to 32+ characters
[OK] Contact info verified

Root account now protected with MFA.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Root account secured!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Root Account Secured ===

[OK] MFA enabled (virtual device)
[OK] Access keys deleted
[OK] Password rotated
[OK] Contact info verified

Root account now protected.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam fix-role-trust ") || lowerCmd === "aws iam fix-trust-policies") {
    output = `=== Trust Policies Fixed ===

[OK] External principals removed
[OK] Condition keys added
[OK] MFA required for assume
[OK] Session duration limited

Trust relationships hardened.`;
    success = true;
  }
  else if (lowerCmd === "aws iam implement-least-privilege" || lowerCmd.startsWith("aws iam implement-least-privilege ")) {
    const iamRes = resources.find(r => (r.type === 'iam_role' || r.type === 'iam' || r.name?.includes('role') || r.name?.includes('service')) && r.isVulnerable);
    if (iamRes) {
      // Mark all vulnerable IAM resources as fixed
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Least Privilege Implemented ===

[OK] Analyzed actual API usage from CloudTrail
[OK] Removed AdministratorAccess from app-service-role
[OK] Created scoped policy: S3GetObject, DynamoDBPutItem only
[OK] Applied resource-level restrictions
[OK] Added conditions for VPC and source IP
[OK] Lambda execution role scoped to required services

All roles now follow least privilege principle.
Blast radius significantly reduced.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Least privilege implemented!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `[SUCCESS] All roles already follow least privilege.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws iam remove-persistence") {
    const iamRes = resources.find(r => (r.type === 'iam' || r.type === 'iam_user' || r.type === 'iam_role' || r.name?.includes('backdoor') || r.name?.includes('persistence')) && r.isVulnerable);
    if (iamRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'secured' });
      }
      output = `=== Persistence Mechanisms Removed ===

[OK] Backdoor access keys revoked
[OK] Unauthorized trust policies removed
[OK] Shadow admin accounts disabled
[OK] Malicious role assumptions blocked
[OK] All sessions terminated
[OK] Forensic evidence preserved

All attacker persistence indicators eliminated.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Persistence removed!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Persistence Removed ===

[OK] Backdoor keys revoked
[OK] Unauthorized trust removed
[OK] Persistence mechanisms eliminated
[OK] Access audit complete

All persistence indicators cleared.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam rotate-access-key ") || lowerCmd.startsWith("aws iam rotate-service-credentials ") || lowerCmd.startsWith("aws iam rotate-saml-certificate ")) {
    output = `=== Credentials Rotated ===

[OK] Old credentials invalidated
[OK] New credentials generated
[OK] Services updated
[OK] Validation complete

Credential rotation successful.`;
    success = true;
  }
  else if (lowerCmd === "aws iam terminate-all-federated-sessions") {
    output = `=== Federated Sessions Terminated ===

[OK] All SAML sessions revoked
[OK] All OIDC sessions revoked
[OK] Federation cache cleared
[OK] Re-authentication required

All federated access terminated.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam update-trust-policy ") || lowerCmd.startsWith("aws iam fix-policy ") || lowerCmd.startsWith("aws iam revert-policy ")) {
    output = `=== IAM Policy Updated ===

[OK] Policy analyzed
[OK] Overly permissive rules removed
[OK] New policy version active
[OK] Changes logged

Policy now follows security best practices.`;
    success = true;
  }
  else if (lowerCmd === "aws iam generate-hygiene-report" || lowerCmd === "aws iam generate-zero-trust-report") {
    output = `=== IAM Report Generated ===

Report: iam-hygiene-${new Date().toISOString().split('T')[0]}.pdf

Summary:
  Users analyzed: 45
  Roles analyzed: 23
  Issues found: 12
  Remediated: 8

Exported to security reports.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam restrict-user ")) {
    const userName = lowerCmd.replace("aws iam restrict-user ", "").trim();
    const iamUser = resources.find(r => r.type === "iam_user" && r.name === userName);
    
    if (iamUser) {
      await storage.updateResource(iamUser.id, { isVulnerable: false, status: 'least-privilege' });
      output = `=== IAM User Restricted ===

[OK] User '${userName}' analyzed
[OK] AdministratorAccess policy removed
[OK] Least privilege policy applied
[OK] Permissions now scoped to Lambda deployment only
[OK] Changes logged to CloudTrail

User now follows least privilege principle.`;
      success = true;
      const remaining = resources.filter(r => r.id !== iamUser.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== IAM Security Enhanced ===

[OK] User restrictions applied
[OK] Session durations reduced  
[OK] Identity monitoring enabled
[OK] Permission boundaries enforced

IAM security posture improved.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws iam reduce-session-duration" || lowerCmd === "aws iam enable-identity-monitoring" || lowerCmd === "aws iam implement-permission-boundaries") {
    output = `=== IAM Security Enhanced ===

[OK] Session durations reduced
[OK] Identity monitoring enabled
[OK] Permission boundaries enforced

IAM security posture improved.`;
    success = true;
  }
  // ============= EC2 ADDITIONAL COMMANDS =============
  else if (lowerCmd.startsWith("aws ec2 block-exfil-destination ") || lowerCmd.startsWith("aws ec2 block-outbound ")) {
    output = `=== Egress Blocked ===

[OK] Malicious destination blocked
[OK] NACL rules updated
[OK] Security group modified
[OK] Traffic stopped

Data exfiltration prevented.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 deregister-ami ")) {
    output = `=== Malicious AMI Removed ===

[OK] AMI deregistered
[OK] Snapshots flagged for review
[OK] Launch permissions revoked
[OK] Audit logged

Compromised image eliminated.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 isolate-vpc ") || lowerCmd.startsWith("aws ec2 remove-tgw-attachment ")) {
    output = `=== VPC Isolated ===

[OK] Transit gateway detached
[OK] Peering connections removed
[OK] Internet access blocked
[OK] VPN tunnels terminated

Compromised VPC quarantined.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 restore-route-table ") || lowerCmd.startsWith("aws ec2 terminate-mining-instances ") || lowerCmd.startsWith("aws ec2 terminate-tunnel ")) {
    output = `=== EC2 Security Action Complete ===

[OK] Route tables restored
[OK] Malicious instances terminated
[OK] Covert tunnels closed
[OK] Network integrity verified

Infrastructure secured.`;
    success = true;
  }
  // ============= CLOUDTRAIL ADDITIONAL COMMANDS =============
  else if (lowerCmd === "aws cloudtrail enable-data-events" || lowerCmd.startsWith("aws cloudtrail enable challenge-trail") || lowerCmd.startsWith("aws cloudtrail analyze-saml-anomalies")) {
    output = `=== CloudTrail Configuration Updated ===

[OK] Data events enabled
[OK] SAML anomalies analyzed
[OK] Trail configured
[OK] Logging verified

Full visibility achieved.`;
    success = true;
  }
  // ============= SIEM ADVANCED COMMANDS =============
  else if (lowerCmd.startsWith("siem create-behavioral-rule ") || lowerCmd.startsWith("siem enable-ueba ")) {
    output = `=== UEBA/Behavioral Analysis Enabled ===

[OK] Behavioral baseline established
[OK] Anomaly detection active
[OK] User risk scores calculated
[OK] Insider threat monitoring enabled

Behavioral analytics now active.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem correlate-logs ")) {
    output = `=== Log Correlation Complete ===

Correlated Events: 47

Attack Chain Detected:
  1. Unusual login (CloudTrail)
  2. Policy enumeration (CloudTrail)
  3. Outbound data (VPC Flow)
  4. Process spawn (CloudWatch)

Confidence: 94%
Verdict: TRUE POSITIVE`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem create-investigation-dashboards") || lowerCmd === "siem generate-triage-report") {
    output = `=== Investigation Dashboard Created ===

[OK] Timeline view configured
[OK] Entity analysis panels added
[OK] IOC correlation enabled
[OK] Export functionality ready

Dashboard available for investigation.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem validate-alert ")) {
    output = `=== Alert Validated ===

Alert: api-anomaly-02
Validation: TRUE POSITIVE

Evidence:
  - Unusual API patterns confirmed
  - New source IP verified
  - Off-hours activity detected

Escalating to incident response.`;
    success = true;
  }
  // ============= HUNT FRAMEWORK COMMANDS =============
  else if (lowerCmd === "hunt-framework initialize" || lowerCmd === "hunt-platform" || lowerCmd === "hunt_platform" || lowerCmd === "hunt-workspace" || lowerCmd === "hunt_workspace") {
    output = `=== Threat Hunt Framework Initialized ===

[OK] Hunt workspace created
[OK] Data sources connected
[OK] Query templates loaded
[OK] IOC feeds synced
[OK] MITRE ATT&CK mapping ready

Hunt platform operational.
Ready for hypothesis-driven hunting.`;
    success = true;
  }
  else if (lowerCmd.startsWith("hunt-framework schedule ")) {
    output = `=== Hunt Scheduled ===

[OK] Hunt job scheduled
[OK] Frequency: Daily at 02:00 UTC
[OK] Data retention: 90 days
[OK] Alert on findings: Enabled

Automated hunting active.`;
    success = true;
  }
  // ============= CORRELATE COMMANDS =============
  else if (lowerCmd === "correlate" || lowerCmd.startsWith("correlate-") || lowerCmd === "correlated-activity" || lowerCmd === "correlated-events" || lowerCmd === "correlated-timeline") {
    output = `=== Event Correlation Complete ===

Timeline Built: 47 events correlated

Attack Phases Identified:
  Phase 1: Initial Access (5 events)
  Phase 2: Execution (8 events)
  Phase 3: Persistence (6 events)
  Phase 4: Exfiltration (12 events)

Confidence Score: 89%
MITRE ATT&CK techniques: 7 mapped`;
    success = true;
  }
  // ============= LOGS COMMANDS =============
  else if (lowerCmd === "logs" || lowerCmd === "logs-bucket" || lowerCmd === "network-logs" || lowerCmd === "network-metrics" || lowerCmd === "hunt-logs") {
    output = `=== Log Analysis ===

Sources Available:
  [OK] CloudTrail: 1.2M events/day
  [OK] VPC Flow Logs: 45M records/day
  [OK] CloudWatch Logs: 500 streams
  [OK] S3 Access Logs: 2.3M requests/day

Query interface ready.
Use specific commands to filter.`;
    success = true;
  }
  else if (lowerCmd.startsWith("logs set-retention ")) {
    const logRes = resources.find(r => (r.type === 'logs' || r.type === 'log_source' || r.type === 'siem') && r.isVulnerable);
    if (logRes) {
      await storage.updateResource(logRes.id, { isVulnerable: false, status: 'secured' });
      const remaining = resources.filter(r => r.id !== logRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    }
    output = `=== Log Retention Updated ===

[OK] Hot storage: 90 days
[OK] Cold storage: 365 days
[OK] Archive: 7 years
[OK] Compliance: Met

Log lifecycle policy applied.`;
    success = true;
  }
  // ============= ASSESS COMMANDS =============
  else if (lowerCmd === "aws assess-data-protection" || lowerCmd === "aws assess-logging-coverage") {
    output = `=== Security Assessment Complete ===

Data Protection: 92%
  [OK] Encryption at rest: 95%
  [OK] Encryption in transit: 100%
  [!] Public access: 2 resources exposed

Logging Coverage: 87%
  [OK] CloudTrail: All regions
  [!] VPC Flow Logs: 85% coverage
  [OK] S3 Access Logs: 90%

Recommendations in detailed report.`;
    success = true;
  }
  // ============= DESCRIBE COMMANDS (GENERIC) =============
  else if (lowerCmd.startsWith("aws describe-instance-role ")) {
    output = `=== Instance Role Analysis ===

Instance: analytics-server-01
Role: AnalyticsRole

Permissions:
  [!] s3:* - Overly permissive
  [!] ec2:* - Overly permissive
  [OK] cloudwatch:PutMetricData

Risk: HIGH - Needs least privilege`;
    success = true;
  }
  // ============= DASHBOARD COMMANDS =============
  else if (lowerCmd.startsWith("dashboard add-widget ") || lowerCmd.startsWith("dashboard create-widget ")) {
    const widgetName = lowerCmd.replace("dashboard add-widget ", "").replace("dashboard create-widget ", "").trim();
    const dashRes = resources.find(r => r.type === 'dashboard' && r.isVulnerable);
    if (dashRes) {
      await storage.updateResource(dashRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Widget Added: ${widgetName} ===

[OK] Widget created successfully
[OK] Data source connected
[OK] Visualization configured
[OK] Added to dashboard

Widget is now live and updating in real-time.`;
      success = true;
      const remaining = resources.filter(r => r.id !== dashRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Widget "${widgetName}" added to dashboard.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("dashboard open ") || lowerCmd.startsWith("dashboard list-widgets")) {
    output = `=== SOC Dashboard ===

Active Widgets:
  [1] Alert Queue - Real-time alerts
  [2] Threat Map - Geographic view
  
Add widgets with 'dashboard add-widget <name>'`;
    success = true;
  }
  // ============= SIEM CORRELATION COMMANDS =============
  else if (lowerCmd.startsWith("siem create-correlation ") || lowerCmd.startsWith("siem add-chain-event ") || lowerCmd.startsWith("siem set-window ")) {
    const corrRes = resources.find(r => (r.type === 'correlation_engine' || r.type === 'siem' || r.type === 'siem_rules') && r.isVulnerable);
    if (corrRes) {
      await storage.updateResource(corrRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Correlation Rule Updated ===

[OK] Correlation chain configured
[OK] Events linked
[OK] Time window set
[OK] Detection active

Correlated detection now monitoring.`;
      success = true;
      const remaining = resources.filter(r => r.id !== corrRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Correlation rule updated.`;
      success = true;
    }
  }
  // ============= THREAT INTEL COMMANDS =============
  else if (lowerCmd.startsWith("threat-intel configure ") || lowerCmd.startsWith("threat-intel enable-matching ")) {
    const tiRes = resources.find(r => (r.type === 'threat_intel' || r.type === 'threat_feed') && r.isVulnerable);
    if (tiRes) {
      await storage.updateResource(tiRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Threat Intelligence Configured ===

[OK] Feed connected
[OK] IOC matching enabled
[OK] Alerts configured
[OK] Integration active

Threat intel now protecting your environment.`;
      success = true;
      const remaining = resources.filter(r => r.id !== tiRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Threat intelligence configured.`;
      success = true;
    }
  }
  // ============= SOAR COMMANDS WITH RESOURCE UPDATES =============
  else if (lowerCmd.startsWith("soar create-playbook ") || lowerCmd.startsWith("soar activate ")) {
    const soarRes = resources.find(r => (r.type === 'soar' || r.type === 'playbook') && r.isVulnerable);
    if (soarRes) {
      await storage.updateResource(soarRes.id, { isVulnerable: false, status: 'secured' });
      const action = lowerCmd.includes("create") ? "created" : "activated";
      output = `=== SOAR Playbook ${action.charAt(0).toUpperCase() + action.slice(1)} ===

[OK] Playbook ${action}
[OK] Triggers configured
[OK] Automation active

SOAR automation now responding to alerts.`;
      success = true;
      const remaining = resources.filter(r => r.id !== soarRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] SOAR playbook operation complete.`;
      success = true;
    }
  }
  // ============= DETECTION COMMANDS =============
  else if (lowerCmd.startsWith("detection create-pipeline ") || lowerCmd.startsWith("detection verify-pipeline")) {
    const detRes = resources.find(r => (r.type === 'detection_pipeline' || r.type === 'detection' || r.type === 'detection_rule') && r.isVulnerable);
    if (detRes) {
      await storage.updateResource(detRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Detection Pipeline Configured ===

[OK] Pipeline created
[OK] Rules deployed
[OK] Monitoring active

Detection-as-code pipeline operational.`;
      success = true;
      const remaining = resources.filter(r => r.id !== detRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Detection pipeline configured.`;
      success = true;
    }
  }
  // ============= PURPLE TEAM COMMANDS =============
  else if (lowerCmd.startsWith("purple-team deploy ") || lowerCmd.startsWith("purple-team generate-report")) {
    const ptRes = resources.find(r => (r.type === 'adversary_sim' || r.type === 'purple_team') && r.isVulnerable);
    if (ptRes) {
      await storage.updateResource(ptRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Purple Team Exercise Complete ===

[OK] Adversary simulation deployed
[OK] Detection gaps identified
[OK] Report generated

Purple team engagement documented.`;
      success = true;
      const remaining = resources.filter(r => r.id !== ptRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Purple team operation complete.`;
      success = true;
    }
  }
  // ============= SIEM MULTI-TENANT COMMANDS =============
  else if (lowerCmd.startsWith("siem configure-isolation ") || lowerCmd.startsWith("siem onboard-tenant ")) {
    const mtRes = resources.find(r => (r.type === 'siem_cluster' || r.type === 'siem') && r.isVulnerable);
    if (mtRes) {
      await storage.updateResource(mtRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Multi-Tenant SIEM Configured ===

[OK] Tenant isolation enabled
[OK] Index separation configured
[OK] RBAC applied

Multi-tenant security enforced.`;
      success = true;
      const remaining = resources.filter(r => r.id !== mtRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Multi-tenant configuration applied.`;
      success = true;
    }
  }
  // ============= HUNT FRAMEWORK WITH RESOURCE UPDATES =============
  else if (lowerCmd === "hunt-framework initialize" || lowerCmd.startsWith("hunt-framework schedule ")) {
    const huntRes = resources.find(r => (r.type === 'hunt_platform' || r.type === 'hunt_workspace') && r.isVulnerable);
    if (huntRes) {
      await storage.updateResource(huntRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Threat Hunt Framework Configured ===

[OK] Hunt workspace initialized
[OK] Schedule configured
[OK] Automation active

Proactive threat hunting enabled.`;
      success = true;
      const remaining = resources.filter(r => r.id !== huntRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Hunt framework configured.`;
      success = true;
    }
  }
  // ============= SIEM TUNING COMMANDS =============
  else if (lowerCmd.startsWith("siem create-tuning-proposal ") || lowerCmd.startsWith("siem deploy-tuning ")) {
    const tuneRes = resources.find(r => (r.type === 'siem_rules' || r.type === 'siem_alert' || r.type === 'siem_alerts') && r.isVulnerable);
    if (tuneRes) {
      await storage.updateResource(tuneRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Alert Tuning Applied ===

[OK] Tuning proposal created
[OK] Rule updated
[OK] False positive rate reduced

Alert quality improved.`;
      success = true;
      const remaining = resources.filter(r => r.id !== tuneRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Alert tuning deployed.`;
      success = true;
    }
  }
  // ============= IR PLAYBOOK COMMANDS =============
  else if (lowerCmd.startsWith("ir execute-playbook ") || lowerCmd.startsWith("ir generate-incident-report ") || lowerCmd.startsWith("ir contain-exfiltration ") || lowerCmd.startsWith("ir generate-executive-report ") || lowerCmd.startsWith("ir generate-comprehensive-report")) {
    const irRes = resources.find(r => (r.type === 'incident' || r.type === 'ransomware_incident' || r.type === 'data_exfiltration' || r.type === 'attack') && r.isVulnerable);
    if (irRes) {
      await storage.updateResource(irRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Incident Response Complete ===

[OK] Playbook executed
[OK] Containment achieved
[OK] Report generated

Incident successfully managed.`;
      success = true;
      const remaining = resources.filter(r => r.id !== irRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Incident response action complete.`;
      success = true;
    }
  }
  // ============= SECURITY INVESTIGATION COMMANDS =============
  else if (lowerCmd.startsWith("security generate-investigation-summary ") || lowerCmd.startsWith("security generate-finding-report ") || lowerCmd.startsWith("security map-to-attack ") || lowerCmd.startsWith("security generate-incident-report ") || lowerCmd.startsWith("security recommend-containment ") || lowerCmd.startsWith("security remediate-critical") || lowerCmd.startsWith("security generate-assessment-report")) {
    const secRes = resources.find(r => r.isVulnerable);
    if (secRes) {
      await storage.updateResource(secRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Security Action Complete ===

[OK] Investigation completed
[OK] Findings documented
[OK] Recommendations generated

Security posture improved.`;
      success = true;
      const remaining = resources.filter(r => r.id !== secRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Security action complete.`;
      success = true;
    }
  }
  // ============= CROSS-CLOUD COMMANDS =============
  else if (lowerCmd.startsWith("cross-cloud revoke-federation") || lowerCmd.startsWith("azure ransomware ") || lowerCmd.startsWith("gcp ransomware ") || lowerCmd.startsWith("notify-law-enforcement")) {
    const cloudRes = resources.find(r => (r.type === 'azure_ransomware' || r.type === 'gcp_ransomware' || r.type === 'federation') && r.isVulnerable);
    if (cloudRes) {
      await storage.updateResource(cloudRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Cross-Cloud Action Complete ===

[OK] Multi-cloud containment executed
[OK] Federation revoked
[OK] Systems isolated

Cross-cloud response successful.`;
      success = true;
      const remaining = resources.filter(r => r.id !== cloudRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Cross-cloud action complete.`;
      success = true;
    }
  }
  // ============= SIEM DETECTION CREATION =============
  else if (lowerCmd === "siem create-detection-rules" || lowerCmd.startsWith("siem create-detection-rules")) {
    const detRes = resources.find(r => (r.type === 'siem' || r.type === 'siem_rules' || r.type === 'detection_rule') && r.isVulnerable);
    if (detRes) {
      await storage.updateResource(detRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Detection Rules Created ===

[OK] Rules deployed to SIEM
[OK] Alerts configured
[OK] Monitoring active

Detection coverage improved.`;
      success = true;
      const remaining = resources.filter(r => r.id !== detRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Detection rules created.`;
      success = true;
    }
  }
  // ============= HUNT CREATE DETECTIONS =============
  else if (lowerCmd === "hunt create-detections" || lowerCmd === "hunt generate-report") {
    const huntRes = resources.find(r => (r.type === 'hunt_workspace' || r.type === 'hunt_platform' || r.type === 'detection') && r.isVulnerable);
    if (huntRes) {
      await storage.updateResource(huntRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Hunt Findings Processed ===

[OK] Detections created from findings
[OK] Report generated
[OK] Knowledge captured

Hunt cycle complete.`;
      success = true;
      const remaining = resources.filter(r => r.id !== huntRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Hunt operation complete.`;
      success = true;
    }
  }
  // ============= AWS LOGS CONFIGURE =============
  else if (lowerCmd === "aws logs configure-siem-forwarding" || lowerCmd.startsWith("aws logs configure")) {
    const logRes = resources.find(r => (r.type === 'cloudtrail' || r.type === 'cloudwatch' || r.type === 'logs') && r.isVulnerable);
    if (logRes) {
      await storage.updateResource(logRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== SIEM Log Forwarding Configured ===

[OK] CloudTrail forwarding enabled
[OK] VPC Flow Logs connected
[OK] CloudWatch integration active

All logs now streaming to SIEM.`;
      success = true;
      const remaining = resources.filter(r => r.id !== logRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Log forwarding configured.`;
      success = true;
    }
  }
  // ============= SIEM INVESTIGATION DASHBOARDS =============
  else if (lowerCmd === "siem create-investigation-dashboards") {
    const dashRes = resources.find(r => (r.type === 'siem' || r.type === 'dashboard') && r.isVulnerable);
    if (dashRes) {
      await storage.updateResource(dashRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Investigation Dashboards Created ===

[OK] Timeline view configured
[OK] Entity analysis enabled
[OK] IOC correlation active

Investigation toolkit ready.`;
      success = true;
      const remaining = resources.filter(r => r.id !== dashRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Investigation dashboards created.`;
      success = true;
    }
  }
  // ============= SIEM VALIDATE AND TRIAGE =============
  else if (lowerCmd.startsWith("siem validate-alert ") || lowerCmd === "siem generate-triage-report") {
    const alertRes = resources.find(r => (r.type === 'siem_alert' || r.type === 'siem_alerts' || r.type === 'alert') && r.isVulnerable);
    if (alertRes) {
      await storage.updateResource(alertRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Alert Validation Complete ===

[OK] Alert validated
[OK] Classification updated
[OK] Triage report generated

Alert handling documented.`;
      success = true;
      const remaining = resources.filter(r => r.id !== alertRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Alert validation complete.`;
      success = true;
    }
  }
  // ============= EC2 MULTI-TIER SECURITY COMMANDS =============
  else if (lowerCmd === "aws ec2 analyze-traffic-patterns" || lowerCmd.startsWith("aws ec2 analyze-traffic")) {
    output = `=== Traffic Pattern Analysis ===

[SCAN] Analyzing VPC Flow Logs...

Traffic Patterns Identified:
  Web Tier (port 443): 45K requests/hour from ALB
  App Tier (port 8080): 12K requests/hour from web tier
  Data Tier (port 5432): 3K queries/hour from app tier
  
Anomalies Detected:
  [!] Direct internet traffic to app tier (bypassing web)
  [!] SSH traffic from unknown IPs to all tiers
  [!] Database port exposed to web tier

Recommended: Implement tier isolation.`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 plan-security-group-architecture" || lowerCmd.startsWith("aws ec2 plan-security-group")) {
    output = `=== Security Group Architecture Plan ===

Proposed Multi-Tier Design:
  
  [INTERNET] --> [ALB-SG] --> [WEB-SG] --> [APP-SG] --> [DB-SG]
                    |            |            |            |
                   443         8080         8080         5432
                 (public)    (ALB only)  (web only)   (app only)

Security Group Rules:
  alb-sg:     Ingress 443 from 0.0.0.0/0
  web-sg:     Ingress 8080 from alb-sg only
  app-sg:     Ingress 8080 from web-sg only
  db-sg:      Ingress 5432 from app-sg only
  admin-sg:   Ingress 22 from bastion-sg only

Plan ready for implementation.`;
    success = true;
  }
  else if (lowerCmd === "aws ec2 configure-web-tier-sg" || lowerCmd.startsWith("aws ec2 configure-web-tier")) {
    const sgRes = resources.find(r => (r.type === 'security_group' || r.type === 'securityGroup' || r.name?.includes('web')) && r.isVulnerable);
    if (sgRes) {
      await storage.updateResource(sgRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Web Tier Security Group Configured ===

[OK] Removed 0.0.0.0/0 ingress rules
[OK] Added ingress from ALB security group only
[OK] Restricted to port 8080
[OK] Egress limited to app tier

Web tier now accepts traffic only from load balancer.`;
      success = true;
      const remaining = resources.filter(r => r.id !== sgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Web tier security group configured.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ec2 configure-app-tier-sg" || lowerCmd.startsWith("aws ec2 configure-app-tier")) {
    const sgRes = resources.find(r => (r.type === 'security_group' || r.type === 'securityGroup' || r.name?.includes('app')) && r.isVulnerable);
    if (sgRes) {
      await storage.updateResource(sgRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== App Tier Security Group Configured ===

[OK] Ingress restricted to web tier only
[OK] Port 8080 for application traffic
[OK] Egress limited to database tier
[OK] No direct internet access

App tier isolated from direct internet exposure.`;
      success = true;
      const remaining = resources.filter(r => r.id !== sgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] App tier security group configured.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ec2 configure-data-tier-sg" || lowerCmd.startsWith("aws ec2 configure-data-tier")) {
    const sgRes = resources.find(r => (r.type === 'security_group' || r.type === 'securityGroup' || r.name?.includes('db') || r.name?.includes('data')) && r.isVulnerable);
    if (sgRes) {
      await storage.updateResource(sgRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Data Tier Security Group Configured ===

[OK] Ingress restricted to app tier only
[OK] Port 5432 for PostgreSQL
[OK] No SSH access from internet
[OK] Egress blocked (no internet)

Database tier fully isolated from external access.`;
      success = true;
      const remaining = resources.filter(r => r.id !== sgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Data tier security group configured.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ec2 configure-admin-access" || lowerCmd.startsWith("aws ec2 configure-admin")) {
    const sgRes = resources.find(r => (r.type === 'security_group' || r.type === 'bastion' || r.name?.includes('admin') || r.name?.includes('bastion')) && r.isVulnerable);
    if (sgRes) {
      await storage.updateResource(sgRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Admin Access Configured ===

[OK] SSH removed from all tier security groups
[OK] Session Manager enabled for all instances
[OK] Bastion host removed (using SSM)
[OK] Admin access now audited via CloudTrail

Zero-trust admin access implemented.`;
      success = true;
      const remaining = resources.filter(r => r.id !== sgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Admin access configured securely.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ec2 verify-network-segmentation" || lowerCmd.startsWith("aws ec2 verify-network")) {
    output = `=== Network Segmentation Verification ===

Testing tier isolation...

[PASS] Web tier cannot reach database directly
[PASS] App tier cannot reach internet
[PASS] Database tier has no egress
[PASS] SSH blocked from internet to all tiers
[PASS] Only ALB can reach web tier

All segmentation rules verified.
Defense-in-depth architecture confirmed.`;
    success = true;
  }
  // ============= IAM SECURITY COMMANDS =============
  else if (lowerCmd.startsWith("aws iam list-privileged-users") || lowerCmd === "aws iam list-privileged-users-mfa") {
    output = `=== Privileged Users MFA Status ===

User                    Role              MFA Status
---------------------------------------------------
cloud-admin            Administrator      [!] DISABLED
devops-lead            PowerUser          [!] DISABLED
security-admin         SecurityAudit      [OK] ENABLED
data-engineer          DataAccess         [!] DISABLED
finance-admin          BillingAccess      [OK] ENABLED

3 privileged users without MFA protection!
Recommend: Enable MFA for all admin accounts.`;
    success = true;
  }
  else if (lowerCmd === "aws iam get-root-account-summary" || lowerCmd.startsWith("aws iam get-root-account")) {
    output = `=== Root Account Security Summary ===

[!] CRITICAL FINDINGS:

MFA Status:          NOT ENABLED
Access Keys:         1 ACTIVE KEY FOUND (created 847 days ago)
Last Console Login:  3 days ago
Last API Activity:   12 hours ago

Root account has:
  - No MFA protection
  - Active programmatic access keys
  - Recent activity (should be dormant)

RISK: CRITICAL
Immediate action required!`;
    success = true;
  }
  else if (lowerCmd === "aws iam enforce-mfa-policy" || lowerCmd.startsWith("aws iam enforce-mfa")) {
    const iamRes = resources.find(r => (r.type === 'iam' || r.type === 'root' || r.type === 'users' || r.name?.includes('admin') || r.name?.includes('root')) && r.isVulnerable);
    if (iamRes) {
      await storage.updateResource(iamRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== MFA Policy Enforced ===

[OK] SCP deployed: DenyActionsWithoutMFA
[OK] Root MFA: Hardware token registered
[OK] Root access keys: Deleted
[OK] Admin users: MFA required for console
[OK] API access: MFA required for sensitive operations

All privileged access now requires MFA.
Credential theft attacks neutralized.`;
      success = true;
      const remaining = resources.filter(r => r.id !== iamRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] MFA policy enforced organization-wide.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam analyze-escalation") || lowerCmd === "aws iam analyze-escalation-risk") {
    output = `=== Privilege Escalation Risk Analysis ===

12 Escalation Paths Identified:

HIGH RISK:
  [1] developer-role can iam:CreatePolicy + iam:AttachUserPolicy
  [2] cicd-role can iam:PassRole to admin roles
  [3] lambda-role can sts:AssumeRole without conditions

MEDIUM RISK:
  [4-8] Various role chaining vulnerabilities

LOW RISK:
  [9-12] Limited scope escalation paths

Recommendation: Implement permission boundaries.`;
    success = true;
  }
  else if (lowerCmd === "aws iam create-permission-boundaries" || lowerCmd.startsWith("aws iam create-permission-bound")) {
    output = `=== Permission Boundaries Created ===

[OK] DeveloperBoundary: Blocks iam:*, sts:AssumeRole to admin
[OK] CICDBoundary: Limits PassRole to approved roles only
[OK] LambdaBoundary: Restricts to specific services

Boundaries ready for attachment.`;
    success = true;
  }
  else if (lowerCmd === "aws iam apply-permission-boundaries" || lowerCmd.startsWith("aws iam apply-permission-bound")) {
    const iamRes = resources.find(r => (r.type === 'iam' || r.type === 'policies' || r.type === 'escalation-paths') && r.isVulnerable);
    if (iamRes) {
      await storage.updateResource(iamRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Permission Boundaries Applied ===

[OK] DeveloperBoundary attached to developer-role
[OK] CICDBoundary attached to cicd-role
[OK] LambdaBoundary attached to lambda-role

All roles now capped by permission boundaries.
Privilege escalation paths blocked.`;
      success = true;
      const remaining = resources.filter(r => r.id !== iamRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Permission boundaries applied.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws cloudtrail create-escalation-detections") || lowerCmd === "aws cloudtrail create-escalation-detections") {
    output = `=== Escalation Detection Rules Created ===

[OK] Rule: IAM Policy Creation by non-admin
[OK] Rule: Role assumption to privileged roles
[OK] Rule: Permission boundary removal attempts
[OK] Rule: SCP modification attempts

Alerts configured to SOC queue.
Escalation attempts will be detected in real-time.`;
    success = true;
  }
  else if (lowerCmd === "aws organizations create-escalation-scp" || lowerCmd.startsWith("aws organizations create-escalation")) {
    const orgRes = resources.find(r => (r.type === 'iam' || r.type === 'policies' || r.type === 'escalation-paths' || r.type === 'scp') && r.isVulnerable);
    if (orgRes) {
      await storage.updateResource(orgRes.id, { isVulnerable: false, status: 'protected' });
      output = `=== Escalation Prevention SCPs Created ===

[OK] SCP: DenyPermissionBoundaryRemoval
[OK] SCP: DenyCreateAdminPolicies
[OK] SCP: RequireMFAForIAMChanges
[OK] SCP: DenyRootAccountUsage

SCPs attached to all OUs.
Organization-level guardrails active.`;
      success = true;
      const remaining = resources.filter(r => r.id !== orgRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Escalation prevention implemented!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `=== Escalation Prevention SCPs Created ===

[OK] SCP: DenyPermissionBoundaryRemoval
[OK] SCP: DenyCreateAdminPolicies
[OK] SCP: RequireMFAForIAMChanges

SCPs attached to all OUs.
Organization-level guardrails active.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam simulate-escalation") || lowerCmd === "aws iam simulate-escalation-attack") {
    output = `=== Escalation Attack Simulation ===

Testing blocked paths...

[BLOCKED] developer-role: CreatePolicy -> Permission boundary denied
[BLOCKED] cicd-role: PassRole to admin -> SCP denied
[BLOCKED] lambda-role: AssumeRole to admin -> Condition failed

[ALERT] 3 escalation attempt alerts generated
[ALERT] SOC notified within 2 seconds

All escalation paths confirmed blocked!`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws iam generate-escalation-runbook") || lowerCmd === "aws iam generate-escalation-runbook") {
    const iamRes = resources.find(r => (r.type === 'iam' || r.type === 'policies' || r.type === 'escalation-paths' || r.name?.includes('role') || r.name?.includes('escalation')) && r.isVulnerable);
    if (iamRes) {
      for (const res of resources.filter(r => r.isVulnerable)) {
        await storage.updateResource(res.id, { isVulnerable: false, status: 'documented' });
      }
      output = `=== Escalation Response Runbook Generated ===

Runbook: privilege-escalation-response.md

Sections:
  1. Alert Triage Criteria
  2. Investigation Steps
  3. Containment Procedures
  4. Evidence Collection
  5. Remediation Actions
  6. Post-Incident Review

Runbook saved and linked to detection rules.
SOC team trained on response procedures.`;
      success = true;
      labCompleted = true;
      output += "\n\n[MISSION COMPLETE] Escalation controls documented!";
      await storage.updateProgress(userId, labId, true);
      broadcastLeaderboardUpdate();
    } else {
      output = `=== Escalation Response Runbook Generated ===

Runbook: privilege-escalation-response.md

Runbook saved and linked to detection rules.`;
      success = true;
    }
  }
  // ============= AWS IR COMMANDS =============
  else if (lowerCmd === "aws ir execute-containment" || lowerCmd.startsWith("aws ir execute-contain")) {
    const irRes = resources.find(r => r.isVulnerable);
    if (irRes) {
      await storage.updateResource(irRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Containment Executed ===

[OK] Compromised credentials revoked
[OK] Affected instances isolated
[OK] Network access blocked
[OK] Session tokens invalidated

Threat contained. Proceeding to eradication.`;
      success = true;
      const remaining = resources.filter(r => r.id !== irRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Containment actions executed.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ir eradicate-persistence" || lowerCmd.startsWith("aws ir eradicate")) {
    const irRes = resources.find(r => r.isVulnerable);
    if (irRes) {
      await storage.updateResource(irRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Persistence Eradicated ===

[OK] Unauthorized IAM users deleted
[OK] Backdoor Lambda functions removed
[OK] Malicious EventBridge rules deleted
[OK] Rogue SSH keys removed

All persistence mechanisms eliminated.`;
      success = true;
      const remaining = resources.filter(r => r.id !== irRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Persistence mechanisms eradicated.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ir implement-improvements" || lowerCmd.startsWith("aws ir implement-improve")) {
    const irRes = resources.find(r => r.isVulnerable);
    if (irRes) {
      await storage.updateResource(irRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Security Improvements Implemented ===

[OK] MFA enforced for all privileged access
[OK] Permission boundaries applied
[OK] Enhanced monitoring deployed
[OK] Incident response playbooks updated

Lessons learned incorporated.`;
      success = true;
      const remaining = resources.filter(r => r.id !== irRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Security improvements implemented.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws ir generate-incident-report" || lowerCmd.startsWith("aws ir generate-incident")) {
    const irRes = resources.find(r => r.isVulnerable);
    if (irRes) {
      await storage.updateResource(irRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Incident Report Generated ===

Report: incident-report-${new Date().toISOString().split('T')[0]}.pdf

Executive Summary:
  - Incident Type: Unauthorized Access
  - Duration: 4 hours
  - Impact: Contained before data exfiltration
  - Root Cause: Compromised credentials
  
Recommendations included.
Report ready for stakeholder review.`;
      success = true;
      const remaining = resources.filter(r => r.id !== irRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Incident report generated.`;
      success = true;
    }
  }
  // ============= ACCESS ANALYZER COMMANDS =============
  else if (lowerCmd === "aws access-analyzer remediate-public" || lowerCmd.startsWith("aws access-analyzer remediate-public")) {
    const aaRes = resources.find(r => (r.type === 'access_analyzer' || r.type === 's3' || r.type === 'public') && r.isVulnerable);
    if (aaRes) {
      await storage.updateResource(aaRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Public Access Remediated ===

[OK] S3 public ACLs removed
[OK] Block Public Access enabled
[OK] Lambda function policies restricted
[OK] SNS topic policies updated

No more publicly accessible resources.`;
      success = true;
      const remaining = resources.filter(r => r.id !== aaRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Public access remediated.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws access-analyzer remediate-cross-account" || lowerCmd.startsWith("aws access-analyzer remediate-cross")) {
    const aaRes = resources.find(r => (r.type === 'access_analyzer' || r.type === 'cross_account') && r.isVulnerable);
    if (aaRes) {
      await storage.updateResource(aaRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Cross-Account Access Remediated ===

[OK] Unknown account access removed
[OK] Trusted accounts verified
[OK] Conditions added to trust policies
[OK] External ID requirements enforced

Cross-account access now properly controlled.`;
      success = true;
      const remaining = resources.filter(r => r.id !== aaRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Cross-account access remediated.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws access-analyzer enable-monitoring" || lowerCmd.startsWith("aws access-analyzer enable-monitor")) {
    const aaRes = resources.find(r => (r.type === 'access_analyzer' || r.type === 'monitoring') && r.isVulnerable);
    if (aaRes) {
      await storage.updateResource(aaRes.id, { isVulnerable: false, status: 'secured' });
      output = `=== Access Analyzer Monitoring Enabled ===

[OK] Continuous monitoring active
[OK] New finding alerts configured
[OK] Weekly reports scheduled
[OK] Integration with Security Hub

Access permissions continuously monitored.`;
      success = true;
      const remaining = resources.filter(r => r.id !== aaRes.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Access Analyzer monitoring enabled.`;
      success = true;
    }
  }
  // ============= SIEM ADDITIONAL COMMANDS =============
  else if (lowerCmd === "siem analyze-attack-coverage" || lowerCmd.startsWith("siem analyze-attack")) {
    output = `=== MITRE ATT&CK Coverage Analysis ===

Current Detection Coverage:

Initial Access:      ████████░░ 80%
Execution:           ██████░░░░ 60%
Persistence:         ████████░░ 80%
Privilege Esc:       ██████░░░░ 60%
Defense Evasion:     ████░░░░░░ 40%
Credential Access:   ████████░░ 80%
Discovery:           ██████░░░░ 60%
Lateral Movement:    ████░░░░░░ 40%
Collection:          ████████░░ 80%
Exfiltration:        ████████░░ 80%
Impact:              ██████░░░░ 60%

Gaps identified in Defense Evasion and Lateral Movement.`;
    success = true;
  }
  else if (lowerCmd === "siem tune-detection-rules" || lowerCmd.startsWith("siem tune-detection")) {
    output = `=== Detection Rules Tuned ===

[OK] False positive patterns identified
[OK] Baseline thresholds adjusted
[OK] Known-good patterns whitelisted
[OK] Alert severity recalibrated

Alert quality improved by 40%.
False positive rate reduced from 35% to 8%.`;
    success = true;
  }
  else if (lowerCmd === "siem design-tenant-schema" || lowerCmd.startsWith("siem design-tenant")) {
    output = `=== Tenant Schema Designed ===

Multi-Tenant Architecture:

Index Pattern: logs-{tenant_id}-{date}
  
Isolation Level: Index-per-tenant
  - Separate indices per customer
  - RBAC enforced at index level
  - No cross-tenant queries possible

Schema includes:
  - Tenant metadata fields
  - Normalized log format
  - Tenant-specific enrichment

Schema ready for implementation.`;
    success = true;
  }
  else if (lowerCmd === "siem configure-rbac tenant-roles" || lowerCmd.startsWith("siem configure-rbac")) {
    output = `=== Tenant RBAC Configured ===

[OK] Role: tenant_a_analyst (read logs-tenant_a-*)
[OK] Role: tenant_b_analyst (read logs-tenant_b-*)
[OK] Role: mssp_admin (read all, no PII)

Access controls verified.
Cross-tenant access blocked.`;
    success = true;
  }
  else if (lowerCmd === "siem create-tenant-dashboards" || lowerCmd.startsWith("siem create-tenant-dash")) {
    output = `=== Tenant Dashboards Created ===

[OK] Dashboard: tenant_a_security_overview
[OK] Dashboard: tenant_b_security_overview
[OK] Widget: Alert trends (per tenant)
[OK] Widget: Top threats (per tenant)

Each tenant sees only their data.`;
    success = true;
  }
  else if (lowerCmd === "siem configure-rate-limits" || lowerCmd.startsWith("siem configure-rate")) {
    output = `=== Rate Limits Configured ===

[OK] Ingestion rate: 10GB/day per tenant
[OK] Query rate: 100 queries/minute per user
[OK] Dashboard refresh: 30 second minimum
[OK] Burst allowance: 2x for 5 minutes

Noisy neighbor prevention active.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem test-isolation ")) {
    output = `=== Tenant Isolation Test ===

[PASS] Tenant A cannot query Tenant B indices
[PASS] Tenant B cannot see Tenant A alerts
[PASS] Cross-tenant API calls blocked
[PASS] Dashboard filtering enforced

Data isolation verified.`;
    success = true;
  }
  // ============= SOC INVESTIGATION COMMANDS =============
  else if (lowerCmd === "aws iam get-credential-report" || lowerCmd.startsWith("aws iam get-credential")) {
    output = `=== IAM Credential Report ===

User              Created       Last Used     MFA    Access Keys   Status
--------------------------------------------------------------------------------
admin             2023-01-15    2h ago        No     1 active      VULNERABLE
deploy-svc        2023-06-20    5m ago        N/A    1 active      OK
sarah.chen        2024-02-10    3h ago        Yes    0 keys        OK
compromised-key   2024-12-28    NOW           No     1 active      COMPROMISED

[!] ALERT: 'compromised-key' showing activity from unknown IP.
[!] ALERT: 'admin' user has no MFA enabled.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem correlate-logs ") || lowerCmd === "siem correlate-logs") {
    output = `=== Log Correlation Analysis ===

Correlating CloudTrail, VPC Flow Logs, and GuardDuty...

Timeline of Related Events:
  03:42:15  CloudTrail  AssumeRole from 198.51.100.45
  03:42:18  VPC Flow    Inbound SSH from 198.51.100.45
  03:42:45  CloudTrail  ListBuckets API call
  03:43:01  CloudTrail  GetObject on sensitive-data bucket
  03:44:12  GuardDuty   UnauthorizedAccess alert triggered

[!] Attack chain identified: Credential theft → Lateral movement → Data access
[!] Source IP 198.51.100.45 appears in multiple log sources`;
    success = true;
  }
  else if (lowerCmd === "aws s3 get-bucket-policy" || lowerCmd.startsWith("aws s3 get-bucket-policy")) {
    output = `=== Bucket Policy Analysis ===

Bucket: production-bucket
Policy Type: PUBLIC ACCESS

{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PublicRead",
    "Effect": "Allow",
    "Principal": "*",
    "Action": ["s3:GetObject"],
    "Resource": "arn:aws:s3:::production-bucket/*"
  }]
}

[!] CRITICAL: Principal "*" allows ANY user to read objects!
[!] This policy was modified 5 minutes ago.`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem analyze-pattern ")) {
    const pattern = lowerCmd.replace("siem analyze-pattern ", "");
    output = `=== Pattern Analysis: ${pattern} ===

Analyzing behavioral patterns...

Detection Findings:
  Occurrences: 127 events in last 24 hours
  Peak Time: 03:00 - 04:00 UTC
  Source IPs: 3 unique (1 flagged as malicious)
  Affected Users: 2 accounts

Anomalies Detected:
  [!] 50+ attempts in 5-minute window (threshold: 10)
  [!] Geographic anomaly: Login from unusual country
  [!] Time anomaly: Activity outside normal business hours

Recommended: Create detection rule for this pattern.`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail lookup-events --s3") || lowerCmd === "aws cloudtrail lookup-events --s3") {
    output = `=== S3-Related CloudTrail Events ===

Recent S3 API Activity:
  03:42:00  PutBucketPolicy      production-bucket  user/admin
  03:42:01  PutBucketAcl         production-bucket  user/admin (CHANGED TO PUBLIC)
  03:43:00  GetObject            production-bucket  Anonymous
  03:43:05  GetObject            production-bucket  Anonymous
  03:44:00  ListBucket           production-bucket  Anonymous

[!] Bucket policy changed to allow public access 5 minutes ago
[!] Anonymous access detected immediately after policy change`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail lookup-events --ec2") || lowerCmd === "aws cloudtrail lookup-events --ec2") {
    output = `=== EC2-Related CloudTrail Events ===

Recent EC2 API Activity:
  03:30:00  RunInstances         p3.2xlarge × 10    ap-south-1
  03:30:05  ModifySecurityGroup  sg-gpu-mining      0.0.0.0/0:22
  03:31:00  CreateKeyPair        mining-key         user/compromised
  03:32:00  AssociateAddress     eip-xxx            i-suspicious

[!] 10 GPU instances launched in unusual region (ap-south-1)
[!] Security group opened SSH to entire internet
[!] Activity from compromised user credentials`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail lookup-events --username") || lowerCmd === "aws cloudtrail lookup-events --username admin") {
    output = `=== User Activity: admin ===

Failed Login Attempts (last hour):
  03:40:00  ConsoleLogin  FAILED  203.0.113.100
  03:40:02  ConsoleLogin  FAILED  203.0.113.100
  03:40:05  ConsoleLogin  FAILED  203.0.113.100
  ... 47 more attempts ...
  03:44:58  ConsoleLogin  FAILED  203.0.113.100

[!] Brute force attack detected
[!] All attempts from single IP: 203.0.113.100
[!] Recommend: Block IP and enable MFA`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail lookup-events --sg") || lowerCmd === "aws cloudtrail lookup-events --sg") {
    output = `=== Security Group CloudTrail Events ===

Recent Security Group Changes:
  03:35:00  AuthorizeSecurityGroupIngress  prod-sg  22/TCP  0.0.0.0/0
  03:35:05  AuthorizeSecurityGroupIngress  prod-sg  3389/TCP  0.0.0.0/0
  03:36:00  ModifySecurityGroupRules       dev-sg   (restrictive)

[!] SSH (port 22) opened to internet on production security group
[!] RDP (port 3389) also opened - possible lateral movement prep
[!] Changes made by user: admin (possibly compromised)`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws cloudtrail lookup-events --iam") || lowerCmd === "aws cloudtrail lookup-events --iam") {
    output = `=== IAM CloudTrail Events ===

Recent IAM Changes:
  03:45:00  CreateRole           LambdaExecutionRole  AdministratorAccess
  03:45:02  AttachRolePolicy     LambdaExecutionRole  S3FullAccess
  03:45:05  CreateAccessKey      deploy-svc           NEW KEY CREATED
  03:46:00  PutUserPolicy        admin                INLINE POLICY ADDED

[!] New role created with overly permissive access
[!] New access key created (potential persistence mechanism)
[!] Inline policy bypasses managed policy controls`;
    success = true;
  }
  else if (lowerCmd === "aws iam analyze-policies" || lowerCmd.startsWith("aws iam analyze-policies")) {
    output = `=== IAM Policy Analysis ===

Overly Permissive Policies Found:
  
  LambdaExecutionRole:
    - s3:* on *  [CRITICAL]
    - iam:PassRole on *  [HIGH]
    
  admin-inline-policy:
    - *:* on *  [CRITICAL - God mode]
    
  deploy-svc:
    - ec2:* on *  [MEDIUM]

Recommendations:
  1. Remove inline policies, use managed policies
  2. Apply least privilege principle
  3. Add resource constraints to * actions`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 describe-sg ") || lowerCmd === "aws ec2 describe-sg") {
    const sgName = lowerCmd.replace("aws ec2 describe-sg ", "") || "prod-sg";
    output = `=== Security Group: ${sgName} ===

Group ID: sg-0abc123def456
VPC: vpc-production
Description: Production web servers

Inbound Rules:
  [!] 22/TCP    0.0.0.0/0       SSH from anywhere     VULNERABLE
  [!] 3389/TCP  0.0.0.0/0       RDP from anywhere     VULNERABLE
  [OK] 443/TCP  0.0.0.0/0       HTTPS (expected)
  [OK] 80/TCP   10.0.0.0/16     HTTP from VPC only

Outbound Rules:
  [OK] All traffic  0.0.0.0/0   Default egress

[!] CRITICAL: SSH and RDP open to internet - must be restricted`;
    success = true;
  }
  else if (lowerCmd === "aws guardduty list-findings" || lowerCmd.startsWith("aws guardduty list-findings")) {
    output = `=== GuardDuty Findings ===

Active Findings (last 24h):

[CRITICAL] UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration
  Severity: 8.5
  Resource: i-0abc123def456
  Description: EC2 instance credentials used from external IP
  First Seen: 2 hours ago
  
[HIGH] Recon:IAMUser/MaliciousIPCaller
  Severity: 7.0
  Resource: user/compromised
  Description: API calls from known malicious IP
  First Seen: 3 hours ago

[HIGH] CryptoCurrency:EC2/BitcoinTool.B
  Severity: 7.0
  Resource: i-suspicious-gpu
  Description: EC2 instance mining cryptocurrency
  First Seen: 1 hour ago

Total: 3 active findings requiring attention`;
    success = true;
  }
  else if (lowerCmd === "aws iam list-users" || lowerCmd.startsWith("aws iam list-users")) {
    output = `=== IAM Users ===

User                Created         Last Activity   MFA     Status
------------------------------------------------------------------------
admin               2023-01-15      2 hours ago     No      ACTIVE
deploy-svc          2023-06-20      5 min ago       N/A     ACTIVE
sarah.chen          2024-02-10      3 hours ago     Yes     ACTIVE
compromised-key     2024-12-28      NOW             No      ACTIVE [!]
backup-admin        2024-01-05      30 days ago     No      INACTIVE

[!] WARNING: 'compromised-key' showing unusual activity
[!] WARNING: 3 users without MFA enabled`;
    success = true;
  }
  else if (lowerCmd === "aws iam list-roles" || lowerCmd.startsWith("aws iam list-roles")) {
    output = `=== IAM Roles ===

Role                        Trust Policy              Permissions
------------------------------------------------------------------------
LambdaExecutionRole         lambda.amazonaws.com      S3FullAccess [!]
EC2InstanceRole             ec2.amazonaws.com         SSMFullAccess [OK]
CrossAccountRole            External: 123456789012   AdministratorAccess [!]
OrganizationRole            organizations.aws.com     ReadOnly [OK]

[!] LambdaExecutionRole has overly permissive S3 access
[!] CrossAccountRole trusts external account with admin access`;
    success = true;
  }
  else if (lowerCmd.startsWith("aws ec2 revoke-launch-permissions") || lowerCmd === "aws ec2 revoke-launch-permissions") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Launch Permissions Revoked ===

[OK] AMI launch permissions removed for external accounts
[OK] Instance launch blocked in non-approved regions
[OK] Service quota reduced for GPU instances
[OK] SCP applied to prevent unauthorized launches

Compute abuse prevented.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Launch permissions revoked.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws cloudwatch acknowledge-alarm") || lowerCmd === "aws cloudwatch acknowledge-alarm") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Alarm Acknowledged ===

[OK] Alarm state changed to ACKNOWLEDGED
[OK] SOC ticket created: INC-${Math.floor(Math.random() * 10000)}
[OK] On-call notified
[OK] Remediation tracking enabled

Alarm being actively investigated.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Alarm acknowledged.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws budgets set-alert") || lowerCmd === "aws budgets set-alert") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Budget Alert Configured ===

[OK] Alert threshold: 80% of monthly budget
[OK] Email notification configured
[OK] SNS topic for automation
[OK] Slack integration enabled

Cost anomalies will trigger immediate alerts.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Budget alert configured.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 scale-down") || lowerCmd === "aws ec2 scale-down") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Auto Scaling Updated ===

[OK] Desired capacity reduced
[OK] GPU instances terminated
[OK] Spot requests cancelled
[OK] Reserved capacity returned

Compute costs brought under control.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Instances scaled down.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws s3 enable-block-public-access ") || lowerCmd === "aws s3 enable-block-public-access") {
    const anyVulnerable = resources.find(r => (r.type === 's3' || r.type === 'bucket') && r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Block Public Access Enabled ===

[OK] BlockPublicAcls: true
[OK] IgnorePublicAcls: true
[OK] BlockPublicPolicy: true
[OK] RestrictPublicBuckets: true

Bucket can no longer be made public.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Block public access enabled.`;
      success = true;
    }
  }
  // ============= ADDITIONAL SOC INVESTIGATION COMMANDS =============
  else if (lowerCmd === "aws ec2 ls-sg" || lowerCmd.startsWith("aws ec2 ls-sg")) {
    output = `=== Security Groups ===

Group ID            Name              VPC               Inbound Rules    Status
--------------------------------------------------------------------------------
sg-0abc123def       prod-sg           vpc-production    5 rules          [!] OPEN
sg-0def456ghi       dev-sg            vpc-development   3 rules          OK
sg-0ghi789jkl       bastion-sg        vpc-production    2 rules          OK
sg-0jkl012mno       db-sg             vpc-production    1 rule           OK

[!] WARNING: prod-sg has overly permissive inbound rules
    Use 'aws ec2 describe-sg prod-sg' for details`;
    success = true;
  }
  else if (lowerCmd.startsWith("siem show-alerts") || lowerCmd === "siem show-alerts") {
    output = `=== SIEM Active Alerts ===

ID        Severity   Type                           Status      Age
------------------------------------------------------------------------
ALT-001   CRITICAL   Unauthorized API Key Usage     PENDING     5m
ALT-002   HIGH       S3 Bucket Policy Modified      PENDING     12m
ALT-003   HIGH       Unusual EC2 Instance Launch    PENDING     8m
ALT-004   MEDIUM     Failed Login Attempts Spike    PENDING     15m
ALT-005   MEDIUM     Security Group Rule Added      PENDING     3m
ALT-006   LOW        New IAM Role Created           PENDING     22m

Total: 6 pending alerts requiring attention`;
    success = true;
  }
  // ============= ADDITIONAL SOC REMEDIATION COMMANDS =============
  else if (lowerCmd.startsWith("aws iam enforce-mfa-policy") || lowerCmd === "aws iam enforce-mfa-policy") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== MFA Policy Enforced ===

[OK] IAM policy updated to require MFA for all users
[OK] Grace period: 24 hours for compliance
[OK] Non-compliant users will be locked
[OK] CloudTrail logging enabled for policy changes

All users must now enable MFA.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] MFA policy enforced.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-ssh ") || lowerCmd === "aws ec2 restrict-ssh") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== SSH Access Restricted ===

[OK] SSH port 22 removed from 0.0.0.0/0
[OK] SSH allowed only from bastion subnet (10.0.1.0/24)
[OK] Security group updated
[OK] Change logged to CloudTrail

Instance SSH access now follows security best practices.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] SSH access restricted.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam apply-permission-boundaries") || lowerCmd === "aws iam apply-permission-boundaries") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Permission Boundaries Applied ===

[OK] DeveloperBoundary attached to all developer roles
[OK] AdminBoundary attached to admin roles
[OK] Maximum permissions now capped
[OK] Privilege escalation paths blocked

Roles can no longer exceed boundary permissions.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Permission boundaries applied.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("security remediate-critical") || lowerCmd === "security remediate-critical") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Critical Vulnerabilities Remediated ===

[OK] Public S3 buckets locked down
[OK] Overly permissive security groups restricted
[OK] Unattached EBS volumes encrypted
[OK] Root account MFA verified
[OK] Default VPCs reviewed

Critical security gaps addressed.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Critical vulnerabilities remediated.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("security generate-assessment-report") || lowerCmd === "security generate-assessment-report") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Security Assessment Report Generated ===

Report: SEC-ASSESS-${new Date().toISOString().split('T')[0]}.pdf

Executive Summary:
  Overall Score: 78/100 (improved from 45/100)
  Critical Issues: 0 remaining
  High Issues: 2 remaining (non-blocking)
  Compliance: CIS AWS Benchmark 82%

Key Improvements:
  - Public access eliminated
  - MFA enforcement enabled
  - Logging enhanced
  - Network segmentation improved

Next Steps documented in report.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Security assessment report generated.`;
      success = true;
    }
  }
  // ============= SOC REMEDIATION COMMANDS =============
  else if (lowerCmd.startsWith("aws iam revoke-credentials ") || lowerCmd === "aws iam revoke-credentials") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Credentials Revoked ===

[OK] Access key deactivated immediately
[OK] Session tokens invalidated
[OK] Console access disabled
[OK] CloudTrail marker added for audit

Compromised credentials neutralized.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Credentials revoked.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 terminate ") || lowerCmd === "aws ec2 terminate") {
    const anyVulnerable = resources.find(r => (r.type === 'ec2' || r.type === 'instance') && r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Instance Terminated ===

[OK] Instance terminated immediately
[OK] EBS volumes scheduled for deletion
[OK] Elastic IP released
[OK] Security group detached

Suspicious compute resources eliminated.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Instance terminated.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam lock-account ") || lowerCmd === "aws iam lock-account") {
    const anyVulnerable = resources.find(r => (r.type === 'iam' || r.type === 'user') && r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Account Locked ===

[OK] Console password disabled
[OK] All access keys deactivated
[OK] Active sessions terminated
[OK] Account marked for security review

User account secured pending investigation.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Account locked.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws waf add-ip-blocklist ") || lowerCmd === "aws waf add-ip-blocklist") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== IP Added to Blocklist ===

[OK] IP added to WAF block rule
[OK] All regions updated
[OK] CloudFront distributions updated
[OK] Rate limiting applied

Malicious IP blocked at network edge.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] IP blocklist updated.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("siem create-rule ") || lowerCmd === "siem create-rule") {
    const ruleName = lowerCmd.replace("siem create-rule ", "") || "detection-rule";
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Detection Rule Created: ${ruleName} ===

[OK] Rule logic validated
[OK] Threshold configured (10 events/5 min)
[OK] Alert severity: HIGH
[OK] Notification routing configured

Future attacks of this pattern will be detected.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Detection rule created: ${ruleName}`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws ec2 restrict-sg ") || lowerCmd === "aws ec2 restrict-sg") {
    const anyVulnerable = resources.find(r => (r.type === 'security_group' || r.type === 'securityGroup' || r.type === 'sg') && r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Security Group Restricted ===

[OK] Removed 0.0.0.0/0 ingress rules
[OK] SSH restricted to bastion CIDR only
[OK] RDP access removed
[OK] Unnecessary ports closed

Security group now follows least privilege.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Security group restricted.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("aws iam review-role ") || lowerCmd === "aws iam review-role") {
    const roleName = lowerCmd.replace("aws iam review-role ", "") || "role";
    output = `=== Role Review: ${roleName} ===

Current Permissions:
  - s3:* on arn:aws:s3:::*  [OVERLY PERMISSIVE]
  - iam:PassRole on *  [DANGEROUS]
  - logs:* on *  [OK]

Trust Policy:
  - Principal: lambda.amazonaws.com [OK]
  - Condition: None [MISSING]

Recommendations:
  1. Restrict S3 access to specific buckets
  2. Add resource conditions to PassRole
  3. Add external ID for cross-account trust`;
    success = true;
  }
  else if (lowerCmd === "aws cloudtrail enable-data-events" || lowerCmd.startsWith("aws cloudtrail enable-data-events")) {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== S3 Data Events Enabled ===

[OK] Read events logging enabled
[OK] Write events logging enabled
[OK] All buckets included
[OK] Log delivery verified

S3 access now fully audited.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] CloudTrail data events enabled.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws guardduty enable-enhanced" || lowerCmd.startsWith("aws guardduty enable-enhanced")) {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== GuardDuty Enhanced Mode Enabled ===

[OK] EKS runtime monitoring active
[OK] Lambda network monitoring active
[OK] Malware protection enabled
[OK] Finding confidence threshold lowered

Enhanced threat detection now active.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] GuardDuty enhanced mode enabled.`;
      success = true;
    }
  }
  else if (lowerCmd.startsWith("security generate-incident-report") || lowerCmd === "security generate-incident-report") {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Incident Report Generated ===

Report: IR-${new Date().toISOString().split('T')[0]}-001.pdf

Summary:
  Type: Unauthorized Access / Credential Compromise
  Severity: CRITICAL
  Duration: Contained within 15 minutes
  Impact: Limited - early detection prevented data exfil
  Root Cause: Compromised API credentials
  
Actions Taken:
  - Credentials revoked
  - Source IP blocked
  - Detection rules created
  
Lessons Learned documented.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Incident report generated.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws config enable-sg-monitoring" || lowerCmd.startsWith("aws config enable-sg-monitoring")) {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Security Group Monitoring Enabled ===

[OK] AWS Config rule: restricted-ssh deployed
[OK] AWS Config rule: restricted-rdp deployed
[OK] SNS notifications configured
[OK] Auto-remediation Lambda deployed

Security group changes will be automatically detected and remediated.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] Security group monitoring enabled.`;
      success = true;
    }
  }
  else if (lowerCmd === "aws cloudtrail create-iam-alerts" || lowerCmd.startsWith("aws cloudtrail create-iam-alerts")) {
    const anyVulnerable = resources.find(r => r.isVulnerable);
    if (anyVulnerable) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== IAM Change Alerts Created ===

[OK] EventBridge rule: IAM role creation
[OK] EventBridge rule: Policy attachment
[OK] EventBridge rule: Access key creation
[OK] SNS topic configured
[OK] SOC queue integration complete

IAM changes will trigger immediate alerts.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      output = `[SUCCESS] IAM change alerts created.`;
      success = true;
    }
  }
  // ============= GENERIC RESOURCE UPDATE HANDLER =============
  else if (lowerCmd.startsWith("aws ") || lowerCmd.startsWith("siem ") || lowerCmd.startsWith("soar ") || lowerCmd.startsWith("hunt ") || lowerCmd.startsWith("ir ") || lowerCmd.startsWith("security ") || lowerCmd.startsWith("threat-intel ") || lowerCmd.startsWith("detection ") || lowerCmd.startsWith("purple-team ") || lowerCmd.startsWith("dashboard ") || lowerCmd.startsWith("logs ")) {
    // Generic handler for any remaining commands - check if it might be a fix/remediation command
    const anyVulnerable = resources.find(r => r.isVulnerable);
    const actionKeywords = ["fix", "remediate", "secure", "enable", "configure", "create", "deploy", "apply", "enforce", "implement", "execute", "generate-report", "activate", "revoke", "lock", "terminate", "restrict", "block", "acknowledge", "add-ip-blocklist", "scale-down", "set-alert", "review-role", "create-iam-alerts", "enable-sg-monitoring", "restrict-sg"];
    if (anyVulnerable && actionKeywords.some(keyword => lowerCmd.includes(keyword))) {
      await storage.updateResource(anyVulnerable.id, { isVulnerable: false, status: 'secured' });
      output = `=== Command Executed Successfully ===

[OK] ${command}

Action completed. Security posture improved.`;
      success = true;
      const remaining = resources.filter(r => r.id !== anyVulnerable.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All objectives achieved!";
        await storage.updateProgress(userId, labId, true);
        broadcastLeaderboardUpdate();
      }
    } else {
      // It's a read/analysis command
      output = `=== ${command} ===

Command executed. Review the output above for findings.
Use appropriate remediation commands to fix issues.`;
      success = true;
    }
  }
  // Unknown command
  else {
    output = `Command not found: ${command}. Type 'help' for available commands.`;
  }

  return { output, success, labCompleted };
};

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {
  // Auth Setup
  await setupAuth(app);
  registerAuthRoutes(app);

  // Labs
  app.get(api.labs.list.path, isAuthenticated, async (req, res) => {
    const labs = await storage.getLabs();
    res.json(labs);
  });

  app.get(api.labs.get.path, isAuthenticated, async (req, res) => {
    const lab = await storage.getLab(Number(req.params.id));
    if (!lab) return res.status(404).json({ message: "Lab not found" });
    
    const resources = await storage.getResources(lab.id);
    res.json({ ...lab, resources });
  });

  app.post(api.labs.reset.path, isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    await storage.resetLabResources(Number(req.params.id), userId);
    res.json({ message: "Lab reset successfully" });
  });

  // Resources
  app.get(api.resources.list.path, isAuthenticated, async (req, res) => {
    const resources = await storage.getResources(Number(req.params.labId));
    res.json(resources);
  });

  // Terminal
  app.post(api.terminal.execute.path, isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const { command, labId } = req.body;
    
    const result = await processCommand(command, labId, userId);
    await storage.logCommand(userId, labId, command, result.output, result.success);
    
    // Detect which step was completed based on matching command to step hints
    let completedStep: number | undefined;
    const lab = await storage.getLab(labId);
    if (lab && lab.steps && Array.isArray(lab.steps)) {
      const lowerCmd = command.toLowerCase().trim();
      const steps = lab.steps as any[];
      
      // Find the best matching step (most specific match wins)
      let bestMatch: { step: number; score: number } | null = null;
      
      for (const step of steps) {
        if (step.hint) {
          // Extract command from hint like "Type 'scan' to..." or "Type 'aws s3 ls'..."
          const hintMatch = step.hint.match(/[Tt]ype\s+['"]([^'"]+)['"]/);
          if (hintMatch) {
            let expectedCmd = hintMatch[1].toLowerCase().trim();
            // Remove placeholder parts like <bucket>, <instance>, etc.
            expectedCmd = expectedCmd.replace(/<[^>]+>/g, '').trim();
            const expectedParts = expectedCmd.split(' ').filter((p: string) => p.length > 0);
            const cmdParts = lowerCmd.split(' ').filter((p: string) => p.length > 0);
            
            if (expectedParts.length > 0) {
              // Check for exact match first
              if (lowerCmd === expectedCmd) {
                bestMatch = { step: step.number, score: 1000 };
                break; // Exact match, stop searching
              }
              
              // Check if command starts with expected command
              if (lowerCmd.startsWith(expectedCmd + ' ') || lowerCmd === expectedCmd) {
                const score = expectedParts.length * 10;
                if (!bestMatch || score > bestMatch.score) {
                  bestMatch = { step: step.number, score };
                }
                continue;
              }
              
              // Check if all expected parts match the beginning of the command
              const allPartsMatch = expectedParts.every((part: string, i: number) => cmdParts[i] === part);
              if (allPartsMatch && cmdParts.length >= expectedParts.length) {
                const score = expectedParts.length;
                if (!bestMatch || score > bestMatch.score) {
                  bestMatch = { step: step.number, score };
                }
              }
            }
          }
        }
      }
      
      if (bestMatch) {
        completedStep = bestMatch.step;
      }
    }
    
    res.json({ ...result, completedStep });
  });

  // Progress
  app.get(api.progress.get.path, isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const progress = await storage.getUserProgress(userId);
    res.json(progress);
  });

  app.delete("/api/progress/:labId", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const labId = parseInt(req.params.labId);
      if (isNaN(labId)) {
        return res.status(400).json({ message: "Invalid lab ID" });
      }
      await storage.resetLabProgress(userId, labId);
      res.json({ success: true, message: "Lab progress reset successfully" });
    } catch (error) {
      console.error("Error resetting lab progress:", error);
      res.status(500).json({ message: "Failed to reset lab progress" });
    }
  });

  // Badges
  app.get("/api/badges", isAuthenticated, async (req, res) => {
    const badges = await storage.getBadges();
    res.json(badges);
  });

  app.get("/api/user/badges", isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const userBadges = await storage.getUserBadges(userId);
    res.json(userBadges);
  });

  app.get("/api/user/level", isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const progress = await storage.getUserProgress(userId);
    const completedCount = progress.filter(p => p.completed).length;
    const levelInfo = calculateLevel(completedCount);
    res.json({ ...levelInfo, completedLabs: completedCount });
  });

  app.post("/api/badges/check", isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const progress = await storage.getUserProgress(userId);
    const completedLabs = progress.filter(p => p.completed);
    const allBadges = await storage.getBadges();
    const userBadges = await storage.getUserBadges(userId);
    const earnedBadgeIds = new Set(userBadges.map(ub => ub.badgeId));
    
    const newBadges: any[] = [];
    
    for (const badge of allBadges) {
      if (earnedBadgeIds.has(badge.id)) continue;
      
      try {
        const req = JSON.parse(badge.requirement);
        let earned = false;
        
        if (req.type === "total_labs") {
          earned = completedLabs.length >= req.count;
        } else if (req.type === "category_complete") {
          const categoryLabs = await storage.getLabs();
          const categoryLabIds = categoryLabs.filter(l => l.category === req.category).map(l => l.id);
          const completedInCategory = completedLabs.filter(p => categoryLabIds.includes(p.labId)).length;
          earned = completedInCategory >= categoryLabIds.length && categoryLabIds.length > 0;
        } else if (req.type === "difficulty_count") {
          const difficultyLabs = await storage.getLabs();
          const diffLabIds = difficultyLabs.filter(l => l.difficulty === req.difficulty).map(l => l.id);
          const completedDiff = completedLabs.filter(p => diffLabIds.includes(p.labId)).length;
          earned = completedDiff >= req.count;
        } else if (req.type === "warlord") {
          const userPostCount = await storage.getUserPostCount(userId);
          earned = completedLabs.length >= req.labs && userPostCount >= req.posts;
        }
        
        if (earned) {
          await storage.awardBadge(userId, badge.id);
          newBadges.push(badge);
        }
      } catch (e) {
        console.error(`Error parsing badge requirement for ${badge.name}:`, e);
      }
    }
    
    res.json({ newBadges });
  });

  // Leaderboard API
  app.get("/api/leaderboard", async (req, res) => {
    try {
      const leaderboard = await storage.getLeaderboard();
      res.json(leaderboard);
    } catch (error) {
      console.error("Error fetching leaderboard:", error);
      res.status(500).json({ message: "Failed to fetch leaderboard" });
    }
  });

  // Update user display name
  app.patch("/api/user/display-name", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { displayName } = req.body;
      
      if (typeof displayName !== "string" || displayName.length > 50) {
        return res.status(400).json({ message: "Display name must be a string under 50 characters" });
      }
      
      const sanitizedName = displayName.trim();
      await storage.updateUserDisplayName(userId, sanitizedName);
      
      res.json({ message: "Display name updated", displayName: sanitizedName });
    } catch (error) {
      console.error("Error updating display name:", error);
      res.status(500).json({ message: "Failed to update display name" });
    }
  });

  // Equip or unequip a badge
  app.patch("/api/user/equipped-badge", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { badgeId } = req.body;
      
      // badgeId can be null to unequip
      if (badgeId !== null && typeof badgeId !== "number") {
        return res.status(400).json({ message: "Badge ID must be a number or null" });
      }
      
      // If equipping, verify the user has earned this badge
      if (badgeId !== null) {
        const hasBadge = await storage.hasBadge(userId, badgeId);
        if (!hasBadge) {
          return res.status(403).json({ message: "You haven't earned this badge yet" });
        }
      }
      
      await storage.updateEquippedBadge(userId, badgeId);
      
      res.json({ message: badgeId ? "Badge equipped" : "Badge unequipped", equippedBadgeId: badgeId });
    } catch (error) {
      console.error("Error updating equipped badge:", error);
      res.status(500).json({ message: "Failed to update equipped badge" });
    }
  });

  // Get current user profile
  app.get("/api/user/profile", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      
      res.json({
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        displayName: user.displayName,
        profileImageUrl: user.profileImageUrl,
        equippedBadgeId: user.equippedBadgeId
      });
    } catch (error) {
      console.error("Error fetching user profile:", error);
      res.status(500).json({ message: "Failed to fetch user profile" });
    }
  });

  // Category Metadata
  app.get("/api/categories", async (req, res) => {
    try {
      const { CATEGORY_METADATA } = await import("./category-metadata");
      res.json(CATEGORY_METADATA);
    } catch (error) {
      console.error("Error fetching category metadata:", error);
      res.status(500).json({ message: "Failed to fetch category metadata" });
    }
  });

  // Certificates
  app.get("/api/user/certificates", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const certs = await storage.getUserCertificates(userId);
      res.json(certs);
    } catch (error) {
      console.error("Error fetching certificates:", error);
      res.status(500).json({ message: "Failed to fetch certificates" });
    }
  });

  app.get("/api/user/certificates/:category", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const category = req.params.category;
      const cert = await storage.getCertificate(userId, category);
      res.json(cert || null);
    } catch (error) {
      console.error("Error fetching certificate:", error);
      res.status(500).json({ message: "Failed to fetch certificate" });
    }
  });

  app.get("/api/user/category-progress/:category", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const category = req.params.category;
      const progress = await storage.getCategoryCompletion(userId, category);
      res.json(progress);
    } catch (error) {
      console.error("Error fetching category progress:", error);
      res.status(500).json({ message: "Failed to fetch category progress" });
    }
  });

  app.post("/api/user/certificates/check", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { category } = req.body;
      
      if (!category) {
        return res.status(400).json({ message: "Category is required" });
      }

      const existingCert = await storage.getCertificate(userId, category);
      if (existingCert) {
        return res.json({ earned: true, certificate: existingCert, isNew: false });
      }

      const progress = await storage.getCategoryCompletion(userId, category);
      if (progress.completed === progress.total && progress.total > 0) {
        const newCert = await storage.createCertificate(userId, category, progress.completed, 0);
        return res.json({ earned: true, certificate: newCert, isNew: true });
      }

      res.json({ earned: false, progress });
    } catch (error) {
      console.error("Error checking certificate:", error);
      res.status(500).json({ message: "Failed to check certificate" });
    }
  });

  // GitHub README Sync API
  app.post("/api/github/sync-readme", isAuthenticated, async (req, res) => {
    try {
      const octokit = await getUncachableGitHubClient();
      const owner = "Amir-Fadelelsaid";
      const repo = "CyberSecurityLab";
      const path = "README.md";
      
      const readmeContent = fs.readFileSync("README.md", "utf-8");
      
      const { data: currentFile } = await octokit.repos.getContent({
        owner,
        repo,
        path
      }) as { data: { sha: string } };
      
      await octokit.repos.createOrUpdateFileContents({
        owner,
        repo,
        path,
        message: "Update README with latest features and leaderboard",
        content: Buffer.from(readmeContent).toString("base64"),
        sha: currentFile.sha
      });
      
      res.json({ success: true, message: "README synced to GitHub" });
    } catch (error: any) {
      console.error("GitHub sync error:", error);
      res.status(500).json({ message: "Failed to sync README", error: error.message });
    }
  });

  // === COMMUNITY DISCUSSION ENDPOINTS ===
  const { checkProfanity, CODE_OF_CONDUCT } = await import("./profanity-filter");

  app.get("/api/discussions", async (req, res) => {
    try {
      const posts = await storage.getDiscussionPosts();
      res.json(posts);
    } catch (error) {
      console.error("Error fetching discussions:", error);
      res.status(500).json({ message: "Failed to fetch discussions" });
    }
  });

  app.get("/api/discussions/code-of-conduct", (req, res) => {
    res.json({ content: CODE_OF_CONDUCT });
  });

  app.post("/api/discussions", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { content, category, parentId } = req.body;

      if (!content || typeof content !== "string") {
        return res.status(400).json({ message: "Content is required" });
      }

      const profanityCheck = checkProfanity(content);
      if (!profanityCheck.isClean) {
        return res.status(400).json({ 
          message: profanityCheck.reason,
          violation: profanityCheck.violation
        });
      }

      const post = await storage.createDiscussionPost({
        userId,
        content: content.trim(),
        category: category || "general",
        parentId: parentId || null
      });

      const user = await storage.getUser(userId);
      res.json({ ...post, user, replies: [] });
    } catch (error) {
      console.error("Error creating discussion post:", error);
      res.status(500).json({ message: "Failed to create post" });
    }
  });

  app.delete("/api/discussions/:id", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const postId = parseInt(req.params.id);

      if (isNaN(postId)) {
        return res.status(400).json({ message: "Invalid post ID" });
      }

      const deleted = await storage.deleteDiscussionPost(postId, userId);
      if (!deleted) {
        return res.status(403).json({ message: "Cannot delete this post" });
      }

      res.json({ success: true });
    } catch (error) {
      console.error("Error deleting discussion post:", error);
      res.status(500).json({ message: "Failed to delete post" });
    }
  });

  // WebSocket for live leaderboard updates
  leaderboardClients = new Set<WebSocket>();
  const wss = new WebSocketServer({ server: httpServer, path: "/ws/leaderboard" });
  
  wss.on("connection", (ws) => {
    leaderboardClients!.add(ws);
    
    storage.getLeaderboard().then(leaderboard => {
      ws.send(JSON.stringify({ type: 'leaderboard_update', data: leaderboard }));
    }).catch(err => {
      console.error("Failed to send initial leaderboard:", err);
    });
    
    ws.on("close", () => {
      leaderboardClients?.delete(ws);
    });
    
    ws.on("error", () => {
      leaderboardClients?.delete(ws);
    });
  });
  
  wss.on("close", () => {
    leaderboardClients?.clear();
    leaderboardClients = null;
  });

  // Seed Data
  await seedDatabase();

  return httpServer;
}

async function seedDatabase() {
  const existingLabs = await storage.getLabs();
  
  // Get valid lab titles from definitions
  const validTitles = new Set(allLabs.map(l => l.title));
  
  // Remove old/orphaned labs not in current definitions
  for (const lab of existingLabs) {
    if (!validTitles.has(lab.title)) {
      await storage.deleteLab(lab.id);
      console.log(`Removed old lab: ${lab.title}`);
    }
  }
  
  // Refresh lab list after cleanup
  const currentLabs = await storage.getLabs();
  const existingByTitle = new Map(currentLabs.map(l => [l.title, l]));
  
  for (const labDef of allLabs) {
    const existingLab = existingByTitle.get(labDef.title);
    
    // Update existing labs with latest content (steps, briefing, scenario, etc.)
    if (existingLab) {
      // Always update to ensure latest briefing, scenario, intel content syncs
      await storage.updateLab(existingLab.id, { 
        description: labDef.description,
        estimatedTime: labDef.estimatedTime,
        steps: labDef.steps,
        briefing: labDef.briefing || null,
        scenario: labDef.scenario || null,
        successMessage: labDef.successMessage || null
      });
    }
    
    if (!existingByTitle.has(labDef.title)) {
      // Create lab
      const lab = await storage.createLab({
        title: labDef.title,
        description: labDef.description,
        briefing: labDef.briefing || null,
        scenario: labDef.scenario || null,
        successMessage: labDef.successMessage || null,
        difficulty: labDef.difficulty,
        category: labDef.category,
        estimatedTime: labDef.estimatedTime,
        initialState: labDef.initialState,
        steps: labDef.steps
      });
      
      // Create resources for the lab
      for (const resDef of labDef.resources) {
        await storage.createResource({
          labId: lab.id,
          type: resDef.type,
          name: resDef.name,
          config: resDef.config,
          isVulnerable: resDef.isVulnerable,
          status: resDef.status
        });
      }
      
      console.log(`Created lab: ${labDef.title}`);
    }
  }
  
  const finalCount = (await storage.getLabs()).length;
  console.log(`Labs synced. Total: ${finalCount} labs (expected: 97)`);
  
  // Seed and sync badges
  const existingBadges = await storage.getBadges();
  const existingBadgeMap = new Map(existingBadges.map(b => [b.name, b]));
  
  for (const badgeDef of allBadgeDefinitions) {
    const existing = existingBadgeMap.get(badgeDef.name);
    if (!existing) {
      await storage.createBadge({
        name: badgeDef.name,
        description: badgeDef.description,
        icon: badgeDef.icon,
        category: badgeDef.category,
        requirement: badgeDef.requirement,
        level: badgeDef.level || null
      });
      console.log(`Created badge: ${badgeDef.name}`);
    } else if (existing.description !== badgeDef.description || existing.requirement !== badgeDef.requirement) {
      // Update existing badge if description or requirement changed
      await db.update(badges)
        .set({ 
          description: badgeDef.description, 
          requirement: badgeDef.requirement 
        })
        .where(eq(badges.id, existing.id));
      console.log(`Updated badge: ${badgeDef.name}`);
    }
  }
  
  const badgeCount = (await storage.getBadges()).length;
  console.log(`Badges synced. Total: ${badgeCount} badges`);
}
