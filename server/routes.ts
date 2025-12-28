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
    output = "Available commands:\n  aws s3 ls                List buckets\n  aws s3 fix <bucket>      Apply secure policy\n  aws ec2 ls               List instances\n  scan                     Run security scan";
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
  }
}
