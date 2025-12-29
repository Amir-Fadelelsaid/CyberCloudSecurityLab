import { Link } from "wouter";
import { motion } from "framer-motion";
import { ArrowLeft, Shield, Terminal, Database, Users, CheckCircle2, Target, Briefcase, Award, ExternalLink, Github, Network, Eye, Activity, Cloud } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function HiringManager() {
  return (
    <div className="min-h-screen bg-background text-foreground py-12 px-6">
      <div className="max-w-5xl mx-auto">
        <Link href="/">
          <button className="flex items-center gap-2 text-muted-foreground hover:text-primary mb-8 transition-colors" data-testid="link-back-home">
            <ArrowLeft className="w-4 h-4" />
            Back to Platform
          </button>
        </Link>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-8"
        >
          <div className="text-center space-y-4">
            <Badge variant="outline" className="text-primary border-primary">
              For Hiring Managers
            </Badge>
            <h1 className="text-4xl font-display font-bold text-white">
              CloudShieldLab Platform Overview
            </h1>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              CloudShieldLab showcases practical cloud security skills through 81 hands-on labs across 7 categories that mirror real-world scenarios. 
              Here's what a candidate practicing on this platform has demonstrated.
            </p>
            <div className="flex justify-center gap-4 pt-4">
              <a href="https://cloudshieldlab.com/" target="_blank" rel="noopener noreferrer">
                <Button className="gap-2" data-testid="link-live-demo">
                  <ExternalLink className="w-4 h-4" />
                  Live Demo
                </Button>
              </a>
              <a href="https://github.com/Amir-Fadelelsaid/CyberSecurityLab" target="_blank" rel="noopener noreferrer">
                <Button variant="outline" className="gap-2" data-testid="link-github">
                  <Github className="w-4 h-4" />
                  View Source Code
                </Button>
              </a>
            </div>
          </div>

          <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-primary/30">
            <CardContent className="py-6">
              <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
                <div>
                  <p className="text-3xl font-bold text-primary">81</p>
                  <p className="text-sm text-muted-foreground">Labs</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">7</p>
                  <p className="text-sm text-muted-foreground">Categories</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">19</p>
                  <p className="text-sm text-muted-foreground">Badges</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">6</p>
                  <p className="text-sm text-muted-foreground">Skill Levels</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">4</p>
                  <p className="text-sm text-muted-foreground">Difficulty Tiers</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid md:grid-cols-4 lg:grid-cols-7 gap-3">
            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Database className="w-4 h-4 text-teal-400" />
                  Storage
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">11</p>
                <p className="text-xs text-muted-foreground">S3, encryption</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Network className="w-4 h-4 text-blue-400" />
                  Network
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">11</p>
                <p className="text-xs text-muted-foreground">VPC, SGs, WAF</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Eye className="w-4 h-4 text-violet-400" />
                  SOC Ops
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">11</p>
                <p className="text-xs text-muted-foreground">CloudTrail, alerts</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Activity className="w-4 h-4 text-orange-400" />
                  SOC Engineer
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">SIEM, SOAR</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Cloud className="w-4 h-4 text-cyan-400" />
                  Cloud Analyst
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">CSPM, compliance</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Users className="w-4 h-4 text-yellow-400" />
                  IAM Security
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">Roles, policies, MFA</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-2 text-sm">
                  <Shield className="w-4 h-4 text-rose-400" />
                  Cloud SecEng
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">Security Hub, IaC</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <Card className="bg-card/50 border-primary/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  SOC Professional Skills
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">Skills demonstrated:</p>
                <ul className="space-y-2 text-sm">
                  {[
                    "CloudTrail log analysis",
                    "Incident response procedures",
                    "Threat detection and IOC identification",
                    "Security framework application (MITRE ATT&CK)",
                    "Credential compromise investigation"
                  ].map((skill, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                      <span className="text-muted-foreground">{skill}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Database className="w-5 h-5 text-teal-400" />
                  Cloud Security Engineer
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">Skills demonstrated:</p>
                <ul className="space-y-2 text-sm">
                  {[
                    "AWS S3 bucket policy configuration",
                    "Security group rule management",
                    "IAM access key lifecycle management",
                    "Least privilege principle application",
                    "AWS CLI proficiency"
                  ].map((skill, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                      <span className="text-muted-foreground">{skill}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Users className="w-5 h-5 text-violet-400" />
                  Detection Engineer
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">Skills demonstrated:</p>
                <ul className="space-y-2 text-sm">
                  {[
                    "SIEM configuration and tuning",
                    "Detection rule development",
                    "SOAR playbook automation",
                    "Threat intelligence integration",
                    "Purple team exercise coordination"
                  ].map((skill, i) => (
                    <li key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                      <span className="text-muted-foreground">{skill}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-card/50 border-primary/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-primary" />
                Tools & Frameworks Practiced
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { name: "AWS CLI", desc: "Cloud management" },
                  { name: "CloudTrail", desc: "Audit logging" },
                  { name: "GuardDuty", desc: "Threat detection" },
                  { name: "IAM", desc: "Access control" },
                  { name: "S3 Policies", desc: "Data protection" },
                  { name: "Security Groups", desc: "Network security" },
                  { name: "MITRE ATT&CK", desc: "Threat framework" },
                  { name: "CIS Controls", desc: "Security standards" },
                  { name: "SIEM/SOAR", desc: "Security operations" },
                  { name: "Detection Rules", desc: "Threat hunting" },
                  { name: "Container Security", desc: "K8s/EKS" },
                  { name: "Compliance", desc: "SOC2, PCI, HIPAA" },
                ].map((tool, i) => (
                  <div key={i} className="bg-background/50 rounded-lg p-3 border border-border">
                    <p className="font-bold text-white text-sm">{tool.name}</p>
                    <p className="text-xs text-muted-foreground">{tool.desc}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="bg-card/50 border-primary/20">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="w-5 h-5 text-primary" />
                Sample Lab Scenarios
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                {
                  title: "Public S3 Bucket Exposure",
                  difficulty: "Beginner",
                  skills: ["Data classification", "Bucket policy configuration", "Public access remediation"],
                  framework: "CIS Control 3.3 - Configure Data Access Control Lists"
                },
                {
                  title: "SIEM Alert Correlation",
                  difficulty: "Intermediate", 
                  skills: ["Log analysis", "Alert triage", "Threat hunting", "Detection tuning"],
                  framework: "MITRE ATT&CK - Multiple Techniques"
                },
                {
                  title: "Multi-Cloud Security Assessment",
                  difficulty: "Advanced",
                  skills: ["Cross-cloud posture management", "Unified compliance", "Attack surface reduction"],
                  framework: "CIS Cloud Benchmarks"
                }
              ].map((lab, i) => (
                <div key={i} className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-start justify-between gap-4 mb-2">
                    <div>
                      <h4 className="font-bold text-white">{lab.title}</h4>
                      <p className="text-xs text-muted-foreground">{lab.framework}</p>
                    </div>
                    <Badge variant="outline" className={`${
                      lab.difficulty === 'Beginner' ? 'text-primary border-primary' :
                      lab.difficulty === 'Intermediate' ? 'text-yellow-500 border-yellow-500' :
                      'text-destructive border-destructive'
                    }`}>
                      {lab.difficulty}
                    </Badge>
                  </div>
                  <div className="flex flex-wrap gap-2 mt-3">
                    {lab.skills.map((skill, j) => (
                      <Badge key={j} variant="secondary" className="text-xs">
                        {skill}
                      </Badge>
                    ))}
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="bg-gradient-to-r from-primary/10 to-cyan-500/10 border-primary/30">
            <CardContent className="py-8 text-center">
              <Briefcase className="w-12 h-12 text-primary mx-auto mb-4" />
              <h3 className="text-xl font-bold text-white mb-2">Candidate Value Proposition</h3>
              <p className="text-muted-foreground max-w-2xl mx-auto mb-6">
                A candidate who has completed these labs demonstrates practical, hands-on experience with 
                cloud security concepts that directly translate to production environments. They understand 
                not just the "what" but the "why" behind security controls.
              </p>
              <div className="flex justify-center gap-4 flex-wrap">
                <Badge className="bg-primary/20 text-primary border-primary/30 py-2 px-4">
                  <Award className="w-4 h-4 mr-2" />
                  Hands-on Experience
                </Badge>
                <Badge className="bg-cyan-500/20 text-cyan-400 border-cyan-500/30 py-2 px-4">
                  <Shield className="w-4 h-4 mr-2" />
                  Security Mindset
                </Badge>
                <Badge className="bg-violet-500/20 text-violet-400 border-violet-500/30 py-2 px-4">
                  <Terminal className="w-4 h-4 mr-2" />
                  CLI Proficiency
                </Badge>
              </div>
            </CardContent>
          </Card>

          <div className="text-center space-y-4">
            <p className="text-muted-foreground text-sm">
              Built by Amir Fadelelsaid - SOC Professional & Cloud Security Engineer
            </p>
            <div className="flex justify-center gap-4">
              <a href="https://cloudshieldlab.com/" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm">
                cloudshieldlab.com
              </a>
              <span className="text-muted-foreground">|</span>
              <a href="https://github.com/Amir-Fadelelsaid/CyberSecurityLab" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm">
                GitHub Repository
              </a>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
