import { getUncachableGitHubClient } from "../server/github";
import * as fs from "fs";

async function syncReadmeToGithub() {
  try {
    console.log("Syncing README to GitHub...");
    
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
      message: "Update README with live leaderboard feature and latest stats",
      content: Buffer.from(readmeContent).toString("base64"),
      sha: currentFile.sha
    });
    
    console.log("README successfully synced to GitHub!");
  } catch (error: any) {
    console.error("Failed to sync README:", error.message);
    process.exit(1);
  }
}

syncReadmeToGithub();
