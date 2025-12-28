import type { Express } from "express";
import type { Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated, registerAuthRoutes } from "./replit_integrations/auth";
import { api } from "@shared/routes";
import { z } from "zod";

// Simulated command processor
const processCommand = async (command: string, labId: number, userId: string) => {
  const resources = await storage.getResources(labId, userId);
  const lowerCmd = command.toLowerCase().trim();
  
  let output = "";
  let success = false;
  let labCompleted = false;

  // Simple parser for MVP
  if (lowerCmd === "help") {
    output = `Available commands:
  aws s3 ls                  List S3 buckets
  aws s3 fix <bucket>        Apply secure bucket policy
  aws ec2 ls                 List EC2 instances
  aws ec2 restrict-ssh <id>  Restrict SSH access
  aws cloudtrail lookup-events    View recent API activity
  aws iam list-compromised   Show compromised credentials
  aws iam revoke-keys <user> Revoke user's access keys
  report incident            Generate incident report
  scan                       Run security scan`;
  } else if (lowerCmd === "aws cloudtrail lookup-events") {
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    if (cloudtrailRes) {
      const events = (cloudtrailRes.config as any).events || [];
      output = "=== CloudTrail Event History ===\n\n" + events.map((e: any) => 
        `[${e.timestamp}] ${e.eventName}\n  User: ${e.userIdentity}\n  Source IP: ${e.sourceIP}${e.targetRole ? '\n  Target Role: ' + e.targetRole : ''}${e.bucket ? '\n  Bucket: ' + e.bucket : ''}`
      ).join('\n\n');
      output += "\n\n[!] ALERT: Multiple events from suspicious IP 185.220.101.42 (Tor exit node)";
    } else {
      output = "No CloudTrail events found for this lab.";
    }
  } else if (lowerCmd === "aws iam list-compromised") {
    const iamUser = resources.find(r => r.type === 'iam_user' && r.status === 'compromised');
    if (iamUser) {
      const config = iamUser.config as any;
      output = `=== Compromised Credentials Analysis ===\n\n[CRITICAL] User: ${iamUser.name}\n  Status: COMPROMISED\n  Access Key Age: ${config.accessKeyAge}\n  Last Rotation: ${config.lastRotation}\n  Permissions: ${config.permissions.join(', ')}\n\n[!] Recommendation: Immediately revoke access keys for ${iamUser.name}`;
    } else {
      output = "No compromised credentials detected.";
    }
  } else if (lowerCmd.startsWith("aws iam revoke-keys ")) {
    const userName = lowerCmd.replace("aws iam revoke-keys ", "").trim();
    const iamUser = resources.find(r => r.type === 'iam_user' && r.name === userName);
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    
    if (iamUser && iamUser.isVulnerable) {
      await storage.updateResource(iamUser.id, { isVulnerable: false, status: 'secured' });
      // Also mark CloudTrail as investigated/secured
      if (cloudtrailRes && cloudtrailRes.isVulnerable) {
        await storage.updateResource(cloudtrailRes.id, { isVulnerable: false, status: 'investigated' });
      }
      output = `[SUCCESS] Access keys revoked for user: ${userName}\n\n  - All active access keys deactivated\n  - Session tokens invalidated\n  - User flagged for credential rotation\n  - CloudTrail events marked as investigated\n\n[!] Next: Document the incident and implement detection rules.`;
      success = true;
      
      // Check if all vulnerable resources are fixed for lab completion
      const remaining = resources.filter(r => r.id !== iamUser.id && r.id !== (cloudtrailRes?.id || 0) && r.isVulnerable);
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
  } else if (lowerCmd === "report incident") {
    const cloudtrailRes = resources.find(r => r.type === 'cloudtrail');
    if (cloudtrailRes) {
      output = `=== INCIDENT REPORT ===
Generated: ${new Date().toISOString()}

SUMMARY:
Credential compromise detected for IAM user 'dev-jenkins-sa'.
Attacker used compromised credentials to escalate privileges and access sensitive data.

TIMELINE:
08:23:15 - CreateAccessKey: Attacker created new access key
08:24:02 - AssumeRole: Escalated to AdminRole
08:25:30 - ListBuckets: Enumerated S3 buckets
08:26:45 - GetObject: Accessed customer-pii-data bucket

INDICATORS OF COMPROMISE (IOCs):
- Source IP: 185.220.101.42 (Known Tor exit node)
- MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation)

REMEDIATION:
1. Revoke compromised credentials [${resources.find(r => r.type === 'iam_user')?.isVulnerable ? 'PENDING' : 'COMPLETE'}]
2. Rotate all affected secrets [PENDING]
3. Review CloudTrail for data exfiltration [PENDING]
4. Implement MFA requirement [RECOMMENDED]`;
      success = true;
    } else {
      output = "No incident data available for this lab.";
    }
  } else if (lowerCmd.startsWith("aws ec2 restrict-ssh ")) {
    const instanceId = lowerCmd.replace("aws ec2 restrict-ssh ", "").trim();
    const sg = resources.find(r => r.type === 'security_group');
    
    if (sg && sg.isVulnerable) {
      await storage.updateResource(sg.id, { isVulnerable: false, status: 'secured' });
      output = `[SUCCESS] Security group updated for ${instanceId}\n\n  - SSH access restricted to 10.0.0.0/8 (internal network only)\n  - Removed 0.0.0.0/0 from ingress rules\n  - CIS Control 12.1 compliance achieved`;
      success = true;
      
      const remaining = resources.filter(r => r.id !== sg.id && r.isVulnerable);
      if (remaining.length === 0) {
        labCompleted = true;
        output += "\n\n[MISSION COMPLETE] All security vulnerabilities remediated!";
        await storage.updateProgress(userId, labId, true);
      }
    } else if (sg) {
      output = `Info: Security group for ${instanceId} is already properly configured.`;
    } else {
      output = `Error: Instance ${instanceId} not found.`;
    }
  } else if (lowerCmd === "aws s3 ls") {
    const buckets = resources.filter(r => r.type === 's3');
    output = buckets.map(b => `${b.name} [${b.isVulnerable ? 'PUBLIC' : 'PRIVATE'}]`).join('\n');
  } else if (lowerCmd.startsWith("aws s3 fix ")) {
    const bucketName = lowerCmd.replace("aws s3 fix ", "");
    const bucket = resources.find(r => r.type === 's3' && r.name === bucketName);
    
    if (bucket) {
      if (bucket.isVulnerable) {
        await storage.updateResource(bucket.id, { isVulnerable: false, status: 'secured' });
        output = `Success: Bucket policy updated for ${bucketName}. Public access blocked.`;
        success = true;
        
        // Check if all vulnerable resources are fixed
        const remaining = resources.filter(r => r.id !== bucket.id && r.isVulnerable);
        if (remaining.length === 0) {
          labCompleted = true;
          output += "\n\n🎉 CONGRATULATIONS! Lab Completed. All resources secured.";
          await storage.updateProgress(userId, labId, true);
        }
      } else {
        output = `Info: Bucket ${bucketName} is already secure.`;
      }
    } else {
      output = `Error: Bucket ${bucketName} not found.`;
    }
  } else if (lowerCmd === "scan") {
    const vulnerabilities = resources.filter(r => r.isVulnerable);
    if (vulnerabilities.length > 0) {
      output = "SECURITY ALERT: Vulnerabilities detected!\n" + vulnerabilities.map(v => `- ${v.type.toUpperCase()}: ${v.name} is misconfigured`).join('\n');
    } else {
      output = "Scan complete. No vulnerabilities found. System secure.";
    }
  } else {
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
  const labs = await storage.getLabs();
  
  // Check if CloudTrail lab exists, add if missing
  const hasCloudTrailLab = labs.some(lab => lab.category === 'SOC Operations');
  if (labs.length > 0 && !hasCloudTrailLab) {
    // Add CloudTrail lab to existing database
    const lab3 = await storage.createLab({
      title: "CloudTrail Log Analysis - Credential Compromise",
      description: "Your SOC team detected unusual API activity. An attacker may have compromised IAM credentials. Analyze CloudTrail logs to identify the threat actor's actions and respond to the incident.",
      difficulty: "Advanced",
      category: "SOC Operations",
      initialState: {
        logs: ["cloudtrail-events"],
        compromisedUser: "dev-jenkins-sa"
      },
      steps: [
        { number: 1, title: "Understand the Alert", description: "GuardDuty flagged suspicious API activity from an IAM user. Your mission is to investigate the CloudTrail logs and identify what the attacker did.", hint: "MITRE ATT&CK T1078: Adversaries may use valid accounts to maintain access." },
        { number: 2, title: "Query CloudTrail Logs", description: "Start by examining recent API calls to understand the scope of the compromise.", hint: "Type 'aws cloudtrail lookup-events' to see recent API activity." },
        { number: 3, title: "Identify Suspicious Activity", description: "Look for unusual patterns: API calls from new IP addresses, privilege escalation attempts, or data exfiltration.", hint: "Focus on iam:CreateAccessKey, sts:AssumeRole, and s3:GetObject calls from unfamiliar IPs." },
        { number: 4, title: "Determine Compromised Credentials", description: "Identify which IAM user or role was compromised based on the unusual activity patterns.", hint: "Type 'aws iam list-compromised' to see which credentials show suspicious behavior." },
        { number: 5, title: "Revoke Compromised Credentials", description: "Immediately revoke the compromised access keys to stop the attacker.", hint: "Type 'aws iam revoke-keys dev-jenkins-sa' to deactivate the compromised credentials." },
        { number: 6, title: "Document the Incident", description: "Create an incident report summarizing the attack timeline, affected resources, and remediation steps.", hint: "Type 'report incident' to generate an incident summary for your SOC team." },
        { number: 7, title: "Implement Detection Rules", description: "Create detection rules to catch similar attacks in the future.", hint: "Type 'scan' to verify all threats are contained and detection rules are in place." }
      ]
    });

    await storage.createResource({
      labId: lab3.id,
      type: "cloudtrail",
      name: "suspicious-api-activity",
      config: { 
        events: [
          { eventName: "CreateAccessKey", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:23:15Z" },
          { eventName: "AssumeRole", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", targetRole: "AdminRole", timestamp: "2025-01-15T08:24:02Z" },
          { eventName: "ListBuckets", userIdentity: "AdminRole", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:25:30Z" },
          { eventName: "GetObject", userIdentity: "AdminRole", sourceIP: "185.220.101.42", bucket: "customer-pii-data", timestamp: "2025-01-15T08:26:45Z" }
        ]
      },
      isVulnerable: true,
      status: "active"
    });

    await storage.createResource({
      labId: lab3.id,
      type: "iam_user",
      name: "dev-jenkins-sa",
      config: { 
        accessKeyAge: "180 days",
        lastRotation: "2024-07-15",
        permissions: ["s3:*", "iam:CreateAccessKey", "sts:AssumeRole"]
      },
      isVulnerable: true,
      status: "compromised"
    });
    
    console.log("Added CloudTrail SOC lab to existing database");
  }
  
  if (labs.length === 0) {
    const lab1 = await storage.createLab({
      title: "Public S3 Bucket Exposure",
      description: "A sensitive corporate S3 bucket has been accidentally left open to the public. Your mission is to identify the bucket and apply a restrictive bucket policy to secure it.",
      difficulty: "Beginner",
      category: "Storage Security",
      initialState: {
        buckets: ["corp-payroll-data", "public-assets"],
      },
      steps: [
        {
          number: 1,
          title: "Scan for Vulnerabilities",
          description: "First, let's identify what's vulnerable in our infrastructure.",
          hint: "Type 'scan' in the terminal to see all vulnerable resources."
        },
        {
          number: 2,
          title: "List S3 Buckets",
          description: "Now let's examine our S3 buckets to understand what we're working with.",
          hint: "Type 'aws s3 ls' to list all available S3 buckets and their security status."
        },
        {
          number: 3,
          title: "Identify the Vulnerable Bucket",
          description: "Look at the bucket list. One of them is marked as PUBLIC, which means it's exposed to the internet.",
          hint: "The vulnerable bucket name is 'corp-payroll-data'. Notice it shows [PUBLIC] status."
        },
        {
          number: 4,
          title: "Fix the Vulnerable Bucket",
          description: "Apply a secure bucket policy to restrict public access and protect the payroll data.",
          hint: "Type 'aws s3 fix corp-payroll-data' to apply the security fix."
        },
        {
          number: 5,
          title: "Verify the Fix",
          description: "Run a final security scan to confirm all vulnerabilities have been remediated.",
          hint: "Type 'scan' again to verify that the bucket is now secure and marked as [PRIVATE]."
        }
      ]
    });

    await storage.createResource({
      labId: lab1.id,
      type: "s3",
      name: "corp-payroll-data",
      config: { access: "public-read" },
      isVulnerable: true,
      status: "active"
    });

    await storage.createResource({
      labId: lab1.id,
      type: "s3",
      name: "public-website-assets",
      config: { access: "public-read" },
      isVulnerable: false,
      status: "active"
    });

    const lab2 = await storage.createLab({
      title: "Insecure Security Group",
      description: "An EC2 instance hosting an internal database allows SSH access from 0.0.0.0/0. You need to restrict the security group rules.",
      difficulty: "Intermediate",
      category: "Network Security",
      initialState: {
        instances: ["db-prod-01"],
      },
      steps: [
        {
          number: 1,
          title: "Understand the Threat",
          description: "An EC2 instance with a database is exposed to SSH attacks from anywhere on the internet (0.0.0.0/0).",
          hint: "SSH (port 22) should only be accessible from trusted IP addresses, never from the entire internet."
        },
        {
          number: 2,
          title: "Run a Security Scan",
          description: "Scan the infrastructure to identify the misconfigured security group.",
          hint: "Type 'scan' to see all vulnerabilities in the environment."
        },
        {
          number: 3,
          title: "Analyze the Vulnerability Details",
          description: "The output will show that 'security_group' is misconfigured with overly permissive SSH rules.",
          hint: "Overly permissive rules mean that anyone on the internet can attempt to connect via SSH."
        },
        {
          number: 4,
          title: "Restrict SSH Access",
          description: "Update the security group to only allow SSH from specific IPs or internal networks.",
          hint: "Type 'aws ec2 restrict-ssh db-prod-01' to apply stricter security rules."
        },
        {
          number: 5,
          title: "Verify Network Security",
          description: "Confirm that the SSH rule now restricts access to only trusted sources.",
          hint: "Type 'scan' to verify that the security group vulnerability has been fixed."
        },
        {
          number: 6,
          title: "Monitor for Compliance",
          description: "Regular security scanning ensures your infrastructure maintains compliance and protection.",
          hint: "Keep running security scans to catch any future misconfigurations."
        }
      ]
    });

    await storage.createResource({
      labId: lab2.id,
      type: "security_group",
      name: "sg-db-prod-01",
      config: { 
        ingress: [{ port: 22, source: "0.0.0.0/0", protocol: "tcp" }]
      },
      isVulnerable: true,
      status: "active"
    });

    // Lab 3: CloudTrail Log Analysis (Advanced SOC Lab)
    const lab3 = await storage.createLab({
      title: "CloudTrail Log Analysis - Credential Compromise",
      description: "Your SOC team detected unusual API activity. An attacker may have compromised IAM credentials. Analyze CloudTrail logs to identify the threat actor's actions and respond to the incident.",
      difficulty: "Advanced",
      category: "SOC Operations",
      initialState: {
        logs: ["cloudtrail-events"],
        compromisedUser: "dev-jenkins-sa"
      },
      steps: [
        {
          number: 1,
          title: "Understand the Alert",
          description: "GuardDuty flagged suspicious API activity from an IAM user. Your mission is to investigate the CloudTrail logs and identify what the attacker did.",
          hint: "MITRE ATT&CK T1078: Adversaries may use valid accounts to maintain access."
        },
        {
          number: 2,
          title: "Query CloudTrail Logs",
          description: "Start by examining recent API calls to understand the scope of the compromise.",
          hint: "Type 'aws cloudtrail lookup-events' to see recent API activity."
        },
        {
          number: 3,
          title: "Identify Suspicious Activity",
          description: "Look for unusual patterns: API calls from new IP addresses, privilege escalation attempts, or data exfiltration.",
          hint: "Focus on iam:CreateAccessKey, sts:AssumeRole, and s3:GetObject calls from unfamiliar IPs."
        },
        {
          number: 4,
          title: "Determine Compromised Credentials",
          description: "Identify which IAM user or role was compromised based on the unusual activity patterns.",
          hint: "Type 'aws iam list-compromised' to see which credentials show suspicious behavior."
        },
        {
          number: 5,
          title: "Revoke Compromised Credentials",
          description: "Immediately revoke the compromised access keys to stop the attacker.",
          hint: "Type 'aws iam revoke-keys dev-jenkins-sa' to deactivate the compromised credentials."
        },
        {
          number: 6,
          title: "Document the Incident",
          description: "Create an incident report summarizing the attack timeline, affected resources, and remediation steps.",
          hint: "Type 'report incident' to generate an incident summary for your SOC team."
        },
        {
          number: 7,
          title: "Implement Detection Rules",
          description: "Create detection rules to catch similar attacks in the future.",
          hint: "Type 'scan' to verify all threats are contained and detection rules are in place."
        }
      ]
    });

    await storage.createResource({
      labId: lab3.id,
      type: "cloudtrail",
      name: "suspicious-api-activity",
      config: { 
        events: [
          { eventName: "CreateAccessKey", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:23:15Z" },
          { eventName: "AssumeRole", userIdentity: "dev-jenkins-sa", sourceIP: "185.220.101.42", targetRole: "AdminRole", timestamp: "2025-01-15T08:24:02Z" },
          { eventName: "ListBuckets", userIdentity: "AdminRole", sourceIP: "185.220.101.42", timestamp: "2025-01-15T08:25:30Z" },
          { eventName: "GetObject", userIdentity: "AdminRole", sourceIP: "185.220.101.42", bucket: "customer-pii-data", timestamp: "2025-01-15T08:26:45Z" }
        ]
      },
      isVulnerable: true,
      status: "active"
    });

    await storage.createResource({
      labId: lab3.id,
      type: "iam_user",
      name: "dev-jenkins-sa",
      config: { 
        accessKeyAge: "180 days",
        lastRotation: "2024-07-15",
        permissions: ["s3:*", "iam:CreateAccessKey", "sts:AssumeRole"]
      },
      isVulnerable: true,
      status: "compromised"
    });
  }
}
