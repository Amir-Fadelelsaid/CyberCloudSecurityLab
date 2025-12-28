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
      }
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
      isVulnerable: false, // This one is supposed to be public
      status: "active"
    });

    const lab2 = await storage.createLab({
      title: "Insecure Security Group",
      description: "An EC2 instance hosting an internal database allows SSH access from 0.0.0.0/0. You need to restrict the security group rules.",
      difficulty: "Intermediate",
      category: "Network Security",
      initialState: {
        instances: ["db-prod-01"],
      }
    });
    
    // Additional seeding for lab 2 can happen here if needed
  }
}
