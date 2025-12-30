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
  else if (lowerCmd.startsWith("aws ec2 restrict-ssh ")) {
    const instanceId = lowerCmd.replace("aws ec2 restrict-ssh ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Security group updated for ${instanceId}\n  - SSH restricted to 10.0.0.0/8 (internal only)\n  - Removed 0.0.0.0/0 from ingress`;
      success = true;
      const remaining = resources.filter(r => r.id !== sg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else if (sg) {
      output = `Info: Security group for ${instanceId} is already secure.`;
    } else {
      output = `Error: Instance ${instanceId} not found.`;
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
    const root = resources.find(r => r.type === 'iam_root');
    if (root && root.isVulnerable) {
      await storage.updateResource(root.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Root account secured\n  - MFA enabled\n  - Access keys deleted\n  - Strong password policy enforced`;
      success = true;
      const remaining = resources.filter(r => r.id !== root.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else {
      output = "Root account is already secured.";
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
      output = "No CloudTrail configured for this lab.";
    }
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
      
      for (const step of steps) {
        if (step.hint) {
          // Extract command from hint like "Type 'scan' to..." or "Type 'aws s3 ls'..."
          const hintMatch = step.hint.match(/[Tt]ype\s+['"]([^'"]+)['"]/);
          if (hintMatch) {
            let expectedCmd = hintMatch[1].toLowerCase().trim();
            // Remove placeholder parts like <bucket>, <instance>, etc.
            expectedCmd = expectedCmd.replace(/<[^>]+>/g, '').trim();
            // Remove specific resource names from expected cmd for flexible matching
            const expectedParts = expectedCmd.split(' ').filter((p: string) => p.length > 0);
            const cmdParts = lowerCmd.split(' ').filter((p: string) => p.length > 0);
            
            // Check if command starts with the base command pattern
            if (expectedParts.length > 0) {
              const baseMatch = expectedParts.slice(0, -1).every((part: string, i: number) => cmdParts[i] === part) ||
                               expectedParts.every((part: string, i: number) => cmdParts[i] === part) ||
                               lowerCmd.startsWith(expectedCmd) ||
                               lowerCmd === expectedCmd;
              if (baseMatch) {
                completedStep = step.number;
                break;
              }
            }
          }
        }
      }
      
      // If no specific step matched but command was successful, auto-advance to next logical step
      if (!completedStep && (result.success || result.output.includes("==="))) {
        // Find first incomplete step (we'll let frontend track this)
        completedStep = steps.length > 0 ? steps[0].number : undefined;
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
        profileImageUrl: user.profileImageUrl
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
