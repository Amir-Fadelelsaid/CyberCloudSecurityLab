import { Link } from "wouter";
import { motion } from "framer-motion";
import { ArrowLeft, Shield, Terminal, Database, Users, CheckCircle2, Target, Briefcase, Award } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

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
              What This Platform Demonstrates
            </h1>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              CyberLab showcases practical cloud security skills through hands-on labs that mirror real-world scenarios. 
              Here's what a candidate practicing on this platform has demonstrated.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-6">
            <Card className="bg-card/50 border-primary/20">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  SOC Analyst
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
                  IAM Specialist
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm text-muted-foreground">Skills demonstrated:</p>
                <ul className="space-y-2 text-sm">
                  {[
                    "Access control configuration",
                    "Credential rotation procedures",
                    "Permission boundary enforcement",
                    "Service account management",
                    "Identity governance awareness"
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
                Lab Scenarios Completed
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
                  title: "Insecure Security Group",
                  difficulty: "Intermediate", 
                  skills: ["Network segmentation", "Ingress rule analysis", "Port security"],
                  framework: "CIS Control 12.1 - Maintain Secure Network Configurations"
                },
                {
                  title: "CloudTrail Log Analysis",
                  difficulty: "Advanced",
                  skills: ["Log correlation", "IOC identification", "Incident response", "Credential revocation"],
                  framework: "MITRE ATT&CK T1078 - Valid Accounts"
                }
              ].map((lab, i) => (
                <div key={i} className="bg-background/50 rounded-lg p-4 border border-border">
                  <div className="flex items-start justify-between mb-2">
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

          <p className="text-center text-muted-foreground text-sm">
            Built by Amir Fadelelsaid - SOC Analyst & Cloud Security Professional
          </p>
        </motion.div>
      </div>
    </div>
  );
}
