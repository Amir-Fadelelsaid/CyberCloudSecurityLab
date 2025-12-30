import { Link } from "wouter";
import { motion } from "framer-motion";
import { ArrowLeft, Shield, Terminal, Database, Users, CheckCircle2, Target, Briefcase, Award, ExternalLink, Github, Network, Eye, Activity, Cloud, AlertTriangle, FileText, Code, Monitor, Globe, Workflow } from "lucide-react";
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
              For Hiring Managers & Recruiters
            </Badge>
            <h1 className="text-4xl font-display font-bold text-white">
              CloudShieldLab Platform Overview
            </h1>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              CloudShieldLab is a production-grade cloud security training platform with 97 hands-on labs, 
              an enterprise SOC simulation environment, and certificate-based skill validation. 
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
              <div className="grid grid-cols-2 md:grid-cols-6 gap-4 text-center">
                <div>
                  <p className="text-3xl font-bold text-primary">97</p>
                  <p className="text-sm text-muted-foreground">Labs</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">7</p>
                  <p className="text-sm text-muted-foreground">Categories</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">24</p>
                  <p className="text-sm text-muted-foreground">Badges</p>
                </div>
                <div>
                  <p className="text-3xl font-bold text-primary">7</p>
                  <p className="text-sm text-muted-foreground">Certificates</p>
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
            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Database className="w-4 h-4 text-teal-400" />
                  Storage Security
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">S3, encryption</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Network className="w-4 h-4 text-blue-400" />
                  Network Security
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">17</p>
                <p className="text-xs text-muted-foreground">VPC, SGs, WAF</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Eye className="w-4 h-4 text-violet-400" />
                  SOC Operations
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">12</p>
                <p className="text-xs text-muted-foreground">CloudTrail, alerts</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Activity className="w-4 h-4 text-orange-400" />
                  SOC Engineer
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">13</p>
                <p className="text-xs text-muted-foreground">SIEM, SOAR</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Cloud className="w-4 h-4 text-cyan-400" />
                  Cloud Security Analyst
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">14</p>
                <p className="text-xs text-muted-foreground">CSPM, compliance</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Users className="w-4 h-4 text-yellow-400" />
                  IAM Security
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">16</p>
                <p className="text-xs text-muted-foreground">Roles, policies, MFA</p>
              </CardContent>
            </Card>

            <Card className="bg-card/50 border-primary/20 text-center">
              <CardHeader className="pb-2 flex flex-col items-center">
                <CardTitle className="flex items-center justify-center gap-2 text-sm">
                  <Shield className="w-4 h-4 text-rose-400" />
                  Cloud Security Engineer
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center">
                <p className="text-2xl font-bold text-white">13</p>
                <p className="text-xs text-muted-foreground">Security Hub, IaC</p>
              </CardContent>
            </Card>
          </div>

          <Card className="bg-gradient-to-r from-violet-500/10 to-cyan-500/10 border-violet-500/30">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-violet-400" />
                Enterprise SOC Simulation Platform
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Full-featured Security Operations Center dashboard simulating real-world SIEM/SOAR environments:
              </p>
              <div className="grid md:grid-cols-3 gap-4">
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="w-4 h-4 text-red-400" />
                    <span className="font-bold text-white text-sm">SIEM Alerts</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Real-time security alerts with severity levels, enrichment data, and investigation panels</p>
                </div>
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <FileText className="w-4 h-4 text-blue-400" />
                    <span className="font-bold text-white text-sm">Multi-Source Logs</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Windows Events, Linux Syslog, Cloud Telemetry, Network Flows with normalized fields</p>
                </div>
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <Code className="w-4 h-4 text-teal-400" />
                    <span className="font-bold text-white text-sm">Detection Rules</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Custom detection rules with MITRE ATT&CK mapping and threshold logic</p>
                </div>
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <Workflow className="w-4 h-4 text-orange-400" />
                    <span className="font-bold text-white text-sm">Case Management</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Full workflow: open, investigating, pending, closed with alert linking and notes</p>
                </div>
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <Globe className="w-4 h-4 text-cyan-400" />
                    <span className="font-bold text-white text-sm">Enrichment Layer</span>
                  </div>
                  <p className="text-xs text-muted-foreground">GeoIP, user context, asset criticality, IP reputation scoring</p>
                </div>
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <Monitor className="w-4 h-4 text-violet-400" />
                    <span className="font-bold text-white text-sm">Endpoint Telemetry</span>
                  </div>
                  <p className="text-xs text-muted-foreground">Process trees, command lines, file hashes, MITRE technique tags</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="grid md:grid-cols-3 gap-6">
            <Card className="bg-card/50 border-primary/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  SOC Analyst Skills
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">Skills demonstrated:</p>
                <ul className="space-y-2 text-sm">
                  {[
                    "SIEM alert triage and investigation",
                    "Multi-source log correlation",
                    "Incident response procedures",
                    "Threat detection and IOC identification",
                    "Case management workflow"
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
                    "Detection rule development with thresholds",
                    "MITRE ATT&CK framework mapping",
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
                  { name: "SIEM/Splunk", desc: "Log aggregation" },
                  { name: "SOAR", desc: "Automation" },
                  { name: "MITRE ATT&CK", desc: "Threat framework" },
                  { name: "CIS Controls", desc: "Security standards" },
                  { name: "Detection Rules", desc: "Sigma/YARA style" },
                  { name: "Case Management", desc: "Incident tracking" },
                  { name: "GeoIP/Enrichment", desc: "Context addition" },
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
                <Award className="w-5 h-5 text-primary" />
                Certificate System
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-muted-foreground">
                Candidates earn certificates upon completing all labs in a category, providing verifiable proof of practical skills:
              </p>
              <div className="grid md:grid-cols-4 gap-3">
                {[
                  { name: "Storage Security", color: "text-teal-400" },
                  { name: "Network Security", color: "text-blue-400" },
                  { name: "SOC Operations", color: "text-violet-400" },
                  { name: "SOC Engineer", color: "text-orange-400" },
                  { name: "Cloud Security Analyst", color: "text-cyan-400" },
                  { name: "IAM Security", color: "text-yellow-400" },
                  { name: "Cloud Security Engineer", color: "text-rose-400" },
                ].map((cert, i) => (
                  <div key={i} className="bg-background/50 rounded-lg p-3 border border-border text-center">
                    <Award className={`w-6 h-6 mx-auto mb-2 ${cert.color}`} />
                    <p className="text-xs font-medium text-white">{cert.name}</p>
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
                  title: "SIEM Alert Investigation",
                  difficulty: "Intermediate", 
                  skills: ["Log analysis", "Alert triage", "Threat hunting", "Detection tuning"],
                  framework: "MITRE ATT&CK - T1110 Brute Force, T1078 Valid Accounts"
                },
                {
                  title: "Cross-Account Role Attack Investigation",
                  difficulty: "Advanced",
                  skills: ["CloudTrail analysis", "IAM forensics", "Privilege escalation detection", "Incident response"],
                  framework: "MITRE ATT&CK - T1098 Account Manipulation"
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
                cloud security, SOC operations, and incident response that directly translates to production environments. 
                They understand not just the "what" but the "why" behind security controls.
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
                <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/30 py-2 px-4">
                  <AlertTriangle className="w-4 h-4 mr-2" />
                  SOC Operations
                </Badge>
              </div>
            </CardContent>
          </Card>

          <div className="text-center space-y-4">
            <p className="text-muted-foreground text-sm">
              Built by Amir Fadelelsaid - SOC Professional & Cloud Security Enthusiast
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
