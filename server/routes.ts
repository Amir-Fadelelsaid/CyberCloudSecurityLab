import type { Express } from "express";
import type { Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated, registerAuthRoutes } from "./replit_integrations/auth";
import { api } from "@shared/routes";
import { allLabs } from "./lab-definitions";

// Generic command handler for fixing resources
const handleFixCommand = async (
  resourceType: string,
  resourceName: string,
  resources: any[],
  labId: number,
  userId: string
) => {
  const resource = resources.find(r => r.type === resourceType && r.name === resourceName);
  
  if (!resource) {
    return { output: `Error: Resource ${resourceName} not found.`, success: false, labCompleted: false };
  }
  
  if (!resource.isVulnerable) {
    return { output: `Info: ${resourceName} is already secure.`, success: false, labCompleted: false };
  }
  
  await storage.updateResource(resource.id, { isVulnerable: false, status: 'secured' });
  
  const remaining = resources.filter(r => r.id !== resource.id && r.isVulnerable);
  let labCompleted = false;
  let output = `[SUCCESS] ${resourceName} has been secured.\n`;
  
  if (remaining.length === 0) {
    labCompleted = true;
    output += "\n[MISSION COMPLETE] All vulnerabilities remediated!";
    await storage.updateProgress(userId, labId, true);
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
      output = `[SUCCESS] Instance ${instanceName} isolated\n  - Network interfaces detached\n  - Security group changed to isolation-sg (no inbound/outbound)\n  - Instance preserved for forensics`;
      success = true;
      const remaining = resources.filter(r => r.id !== instance.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] Threat contained!";
        await storage.updateProgress(userId, labId, true);
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
    
    res.json(result);
  });

  // Progress
  app.get(api.progress.get.path, isAuthenticated, async (req, res) => {
    const userId = (req.user as any).claims.sub;
    const progress = await storage.getUserProgress(userId);
    res.json(progress);
  });

  // Seed Data
  await seedDatabase();

  return httpServer;
}

async function seedDatabase() {
  const existingLabs = await storage.getLabs();
  
  // Check which labs need to be added or updated
  const existingByTitle = new Map(existingLabs.map(l => [l.title, l]));
  
  for (const labDef of allLabs) {
    const existingLab = existingByTitle.get(labDef.title);
    
    // Update existing labs with estimatedTime if missing
    if (existingLab && !existingLab.estimatedTime) {
      await storage.updateLab(existingLab.id, { 
        estimatedTime: labDef.estimatedTime,
        steps: labDef.steps 
      });
    }
    
    if (!existingByTitle.has(labDef.title)) {
      // Create lab
      const lab = await storage.createLab({
        title: labDef.title,
        description: labDef.description,
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
  
  if (existingLabs.length === 0) {
    console.log("Database seeded with 30 labs");
  } else {
    console.log(`Labs synced. Total: ${(await storage.getLabs()).length}`);
  }
}
