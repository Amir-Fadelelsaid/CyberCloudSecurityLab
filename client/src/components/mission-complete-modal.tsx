import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { motion } from "framer-motion";
import { Shield, Clock, CheckCircle2, AlertTriangle, FileText, Download, Target, Zap, GraduationCap, ArrowRight } from "lucide-react";
import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Link } from "wouter";

interface MissionCompleteModalProps {
  isOpen: boolean;
  onClose: () => void;
  labTitle: string;
  labCategory: string;
  difficulty: string;
  elapsedTime?: string;
  commandStreak?: number;
  isNewCompletion?: boolean;
  stepsCompleted?: number;
  totalSteps?: number;
}

export function MissionCompleteModal({ isOpen, onClose, labTitle, labCategory, difficulty, elapsedTime, commandStreak, isNewCompletion = false, stepsCompleted = 0, totalSteps = 0 }: MissionCompleteModalProps) {
  const [activeTab, setActiveTab] = useState<'summary' | 'timeline' | 'detection' | 'scorecard'>('summary');
  const [certificateEarned, setCertificateEarned] = useState<{ isNew: boolean; category: string } | null>(null);
  const [hasCheckedCertificate, setHasCheckedCertificate] = useState(false);
  
  const scorecardMetrics = getScorecardMetrics(labTitle, labCategory, difficulty, stepsCompleted, totalSteps, commandStreak);

  const checkCertificateMutation = useMutation({
    mutationFn: async (category: string) => {
      const response = await apiRequest("POST", "/api/user/certificates/check", { category });
      return response.json();
    },
    onSuccess: (data) => {
      if (data.earned && data.isNew && data.certificate?.category === labCategory) {
        setCertificateEarned({ isNew: true, category: labCategory });
      }
    }
  });

  useEffect(() => {
    if (isOpen && isNewCompletion && labCategory && !hasCheckedCertificate && !checkCertificateMutation.isPending) {
      setCertificateEarned(null);
      setHasCheckedCertificate(true);
      checkCertificateMutation.mutate(labCategory);
    }
    if (!isOpen) {
      setHasCheckedCertificate(false);
      setCertificateEarned(null);
    }
  }, [isOpen, isNewCompletion, labCategory, hasCheckedCertificate, checkCertificateMutation.isPending]);

  const incidentData = getIncidentData(labCategory);

  const handleExport = () => {
    const report = generateMarkdownReport(labTitle, labCategory, incidentData);
    const blob = new Blob([report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `incident-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-4xl max-h-[85vh] overflow-hidden bg-card border-primary/30">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 text-2xl">
            <motion.div
              animate={{ rotate: 360, scale: [1, 1.2, 1] }}
              transition={{ duration: 1, repeat: 2 }}
            >
              <Shield className="w-8 h-8 text-primary" />
            </motion.div>
            <span className="text-white font-display">MISSION COMPLETE</span>
            <Badge variant="outline" className="ml-2 text-primary border-primary">
              {difficulty}
            </Badge>
          </DialogTitle>
        </DialogHeader>

        {certificateEarned && certificateEarned.isNew && (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-gradient-to-r from-amber-500/20 via-yellow-500/20 to-orange-500/20 border border-amber-500/50 rounded-lg p-4 mb-2"
          >
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <motion.div
                  animate={{ rotate: [0, -10, 10, -10, 0], scale: [1, 1.1, 1] }}
                  transition={{ duration: 0.5, repeat: 3 }}
                >
                  <GraduationCap className="w-8 h-8 text-amber-400" />
                </motion.div>
                <div>
                  <h3 className="text-amber-300 font-bold text-lg">Certificate Earned!</h3>
                  <p className="text-amber-200/80 text-sm">
                    You completed all {certificateEarned.category} labs!
                  </p>
                </div>
              </div>
              <Link href="/certificates" onClick={onClose}>
                <Button variant="outline" className="border-amber-500/50 text-amber-300 gap-2">
                  View Certificate
                  <ArrowRight className="w-4 h-4" />
                </Button>
              </Link>
            </div>
          </motion.div>
        )}

        <div className="flex gap-2 border-b border-border pb-2">
          {['summary', 'timeline', 'detection', 'scorecard'].map((tab) => (
            <Button
              key={tab}
              variant={activeTab === tab ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setActiveTab(tab as any)}
              className="capitalize"
            >
              {tab === 'summary' && <FileText className="w-4 h-4 mr-1" />}
              {tab === 'timeline' && <Clock className="w-4 h-4 mr-1" />}
              {tab === 'detection' && <Zap className="w-4 h-4 mr-1" />}
              {tab === 'scorecard' && <Target className="w-4 h-4 mr-1" />}
              {tab}
            </Button>
          ))}
        </div>

        <div className="overflow-y-auto max-h-[50vh] pr-2">
          {activeTab === 'summary' && (
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              className="space-y-4"
            >
              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h3 className="text-primary font-bold mb-2 flex items-center gap-2">
                  <FileText className="w-4 h-4" /> Incident Summary
                </h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  {incidentData.summary}
                </p>
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h3 className="text-primary font-bold mb-3">Remediation Checklist</h3>
                <div className="space-y-2">
                  {incidentData.remediationSteps.map((step: string, i: number) => (
                    <div key={i} className="flex items-start gap-2">
                      <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                      <span className="text-sm text-muted-foreground">{step}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h3 className="text-primary font-bold mb-2">Security Frameworks</h3>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-black/30 p-2 rounded">
                    <span className="text-primary font-bold">MITRE ATT&CK:</span>
                    <span className="text-muted-foreground ml-2">{incidentData.mitreAttack}</span>
                  </div>
                  <div className="bg-black/30 p-2 rounded">
                    <span className="text-primary font-bold">CIS Control:</span>
                    <span className="text-muted-foreground ml-2">{incidentData.cisControl}</span>
                  </div>
                </div>
              </div>
            </motion.div>
          )}

          {activeTab === 'timeline' && (
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              className="space-y-4"
            >
              <h3 className="text-primary font-bold mb-4 flex items-center gap-2">
                <Clock className="w-4 h-4" /> Attack Timeline
              </h3>
              <div className="relative pl-6 border-l-2 border-primary/30 space-y-4">
                {incidentData.timeline.map((event: { time: string; action: string; detail: string; type: string }, i: number) => (
                  <motion.div 
                    key={i}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.1 }}
                    className="relative"
                  >
                    <div className={`absolute -left-[25px] w-4 h-4 rounded-full border-2 ${
                      event.type === 'attack' ? 'bg-destructive border-destructive' :
                      event.type === 'detection' ? 'bg-yellow-500 border-yellow-500' :
                      'bg-primary border-primary'
                    }`} />
                    <div className="bg-background/50 rounded-lg p-3 border border-border ml-2">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono text-muted-foreground">{event.time}</span>
                        <Badge variant="outline" className={`text-[10px] ${
                          event.type === 'attack' ? 'text-destructive border-destructive' :
                          event.type === 'detection' ? 'text-yellow-500 border-yellow-500' :
                          'text-primary border-primary'
                        }`}>
                          {event.type.toUpperCase()}
                        </Badge>
                      </div>
                      <p className="text-sm font-medium text-white">{event.action}</p>
                      <p className="text-xs text-muted-foreground mt-1">{event.detail}</p>
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          )}

          {activeTab === 'detection' && (
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              className="space-y-4"
            >
              <h3 className="text-primary font-bold mb-4 flex items-center gap-2">
                <Zap className="w-4 h-4" /> Detection Engineering Analysis
              </h3>
              
              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h4 className="text-white font-bold mb-2">Triggering Events</h4>
                <div className="space-y-2">
                  {incidentData.triggeringEvents.map((event: { event: string; reason: string }, i: number) => (
                    <div key={i} className="flex items-start gap-2 text-sm">
                      <AlertTriangle className="w-4 h-4 text-yellow-500 mt-0.5" />
                      <div>
                        <span className="text-white font-mono">{event.event}</span>
                        <p className="text-muted-foreground text-xs">{event.reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h4 className="text-white font-bold mb-2">Why This Behavior is Suspicious</h4>
                <ul className="space-y-1">
                  {incidentData.suspiciousIndicators.map((indicator: string, i: number) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                      <span className="text-destructive">*</span>
                      {indicator}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-border">
                <h4 className="text-white font-bold mb-2">Detection Rule Logic</h4>
                <pre className="text-xs font-mono text-primary bg-black/50 p-3 rounded overflow-x-auto">
                  {incidentData.detectionRule}
                </pre>
              </div>
            </motion.div>
          )}

          {activeTab === 'scorecard' && (
            <motion.div 
              initial={{ opacity: 0 }} 
              animate={{ opacity: 1 }}
              className="space-y-4"
            >
              <h3 className="text-primary font-bold mb-4 flex items-center gap-2">
                <Target className="w-4 h-4" /> {scorecardMetrics.title}
              </h3>
              
              <div className="grid grid-cols-2 gap-4">
                {scorecardMetrics.metrics.map((metric, i) => (
                  <div key={i} className="bg-background/50 rounded-lg p-4 border border-border">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-sm text-muted-foreground">{metric.label}</span>
                      <span className={`text-2xl font-bold ${metric.color}`}>{metric.score}%</span>
                    </div>
                    <div className="h-2 bg-black/50 rounded-full overflow-hidden">
                      <motion.div 
                        className={`h-full ${metric.gradient}`}
                        initial={{ width: 0 }}
                        animate={{ width: `${metric.score}%` }}
                        transition={{ duration: 1, delay: i * 0.1 }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">{metric.description}</p>
                  </div>
                ))}
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-primary/30">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-white font-bold">{scorecardMetrics.overallLabel}</h4>
                    <p className="text-muted-foreground text-sm">{scorecardMetrics.overallDescription}</p>
                  </div>
                  <div className="text-4xl font-bold text-primary">{scorecardMetrics.grade}</div>
                </div>
              </div>

              {scorecardMetrics.recommendations && scorecardMetrics.recommendations.length > 0 && (
                <div className="bg-background/50 rounded-lg p-4 border border-border">
                  <h4 className="text-white font-bold mb-2">Lab-Specific Insights</h4>
                  <ul className="space-y-1">
                    {scorecardMetrics.recommendations.map((rec, i) => (
                      <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                        <CheckCircle2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </motion.div>
          )}
        </div>

        <div className="flex justify-between items-center pt-4 border-t border-border">
          <Button variant="outline" onClick={handleExport} className="gap-2">
            <Download className="w-4 h-4" />
            Export Report
          </Button>
          <Button onClick={onClose} className="bg-primary text-primary-foreground">
            Continue Training
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function getIncidentData(category: string) {
  const data: Record<string, any> = {
    'Storage Security': {
      summary: "A misconfigured S3 bucket was discovered with public read access, potentially exposing sensitive corporate payroll data. The bucket ACL allowed anonymous access, violating data protection policies. Immediate remediation was performed by applying a restrictive bucket policy.",
      remediationSteps: [
        "Identified publicly accessible S3 bucket via security scan",
        "Analyzed bucket ACL and policy configuration",
        "Applied restrictive bucket policy blocking public access",
        "Enabled S3 Block Public Access settings",
        "Verified remediation with follow-up scan"
      ],
      mitreAttack: "T1530 - Data from Cloud Storage",
      cisControl: "3.3 - Configure Data Access Control Lists",
      timeline: [
        { time: "T+0:00", action: "Security scan initiated", detail: "Automated scanner detected public bucket", type: "detection" },
        { time: "T+0:15", action: "Vulnerability confirmed", detail: "corp-payroll-data bucket has PUBLIC ACL", type: "attack" },
        { time: "T+1:30", action: "Bucket policy analyzed", detail: "Missing authentication requirements identified", type: "detection" },
        { time: "T+2:45", action: "Remediation applied", detail: "Restrictive bucket policy deployed", type: "remediation" },
        { time: "T+3:00", action: "Verification complete", detail: "Bucket now reports PRIVATE status", type: "remediation" }
      ],
      triggeringEvents: [
        { event: "s3:GetBucketAcl", reason: "Bucket ACL returned 'public-read' grant" },
        { event: "s3:GetBucketPolicy", reason: "No deny statements for anonymous access" }
      ],
      suspiciousIndicators: [
        "Bucket containing 'payroll' or 'pii' in name with public access",
        "No encryption requirements on sensitive data bucket",
        "Missing CloudTrail logging for data access events"
      ],
      detectionRule: `RULE s3_public_sensitive_bucket
  WHEN s3:GetBucketAcl.grants CONTAINS "AllUsers"
  AND bucket.name MATCHES /(payroll|pii|sensitive|confidential)/
  THEN ALERT "Critical: Sensitive bucket exposed"`
    },
    'Network Security': {
      summary: "An EC2 security group was configured with overly permissive ingress rules, allowing SSH access from any IP address (0.0.0.0/0). This exposed the database server to potential brute-force attacks and unauthorized access. The security group was updated to restrict SSH to internal network ranges only.",
      remediationSteps: [
        "Scanned infrastructure for misconfigured security groups",
        "Identified db-prod-01 with open SSH from 0.0.0.0/0",
        "Restricted SSH ingress to internal CIDR (10.0.0.0/8)",
        "Removed overly permissive inbound rules",
        "Verified network isolation with security scan"
      ],
      mitreAttack: "T1190 - Exploit Public-Facing Application",
      cisControl: "12.1 - Maintain Secure Network Configurations",
      timeline: [
        { time: "T+0:00", action: "Network scan initiated", detail: "Security group audit triggered", type: "detection" },
        { time: "T+0:30", action: "Vulnerability identified", detail: "SSH port 22 open to 0.0.0.0/0", type: "attack" },
        { time: "T+1:00", action: "Risk assessment", detail: "Database server exposed to internet", type: "detection" },
        { time: "T+2:00", action: "Security group updated", detail: "SSH restricted to 10.0.0.0/8", type: "remediation" },
        { time: "T+2:15", action: "Compliance verified", detail: "CIS Control 12.1 achieved", type: "remediation" }
      ],
      triggeringEvents: [
        { event: "ec2:AuthorizeSecurityGroupIngress", reason: "Rule added with source 0.0.0.0/0 on port 22" },
        { event: "ec2:DescribeSecurityGroups", reason: "Audit found unrestricted ingress" }
      ],
      suspiciousIndicators: [
        "SSH (22) or RDP (3389) open to 0.0.0.0/0",
        "Database ports exposed to public internet",
        "No VPC flow logs enabled for traffic analysis"
      ],
      detectionRule: `RULE overly_permissive_security_group
  WHEN ec2:SecurityGroup.ingress.source = "0.0.0.0/0"
  AND ec2:SecurityGroup.ingress.port IN [22, 3389, 3306, 5432]
  THEN ALERT "High: Sensitive port exposed to internet"`
    },
    'SOC Operations': {
      summary: "SOC team detected credential compromise through anomalous CloudTrail activity. An attacker gained access to IAM user 'dev-jenkins-sa' credentials, created new access keys, escalated privileges via AssumeRole, and attempted data exfiltration from S3. Incident response included immediate credential revocation and forensic analysis.",
      remediationSteps: [
        "Analyzed CloudTrail logs for anomalous API activity",
        "Identified compromised IAM user from suspicious source IP",
        "Revoked all active access keys for affected user",
        "Invalidated existing session tokens",
        "Generated incident report with IOCs",
        "Implemented detection rules for future prevention"
      ],
      mitreAttack: "T1078 - Valid Accounts",
      cisControl: "8.5 - Collect Detailed Audit Logs",
      timeline: [
        { time: "08:23:15", action: "CreateAccessKey", detail: "New access key created for dev-jenkins-sa from Tor exit node", type: "attack" },
        { time: "08:24:02", action: "AssumeRole", detail: "Privilege escalation to AdminRole", type: "attack" },
        { time: "08:25:30", action: "ListBuckets", detail: "Attacker enumerated S3 buckets", type: "attack" },
        { time: "08:26:45", action: "GetObject", detail: "Accessed customer-pii-data bucket", type: "attack" },
        { time: "08:30:00", action: "GuardDuty Alert", detail: "Anomalous behavior detected", type: "detection" },
        { time: "08:35:00", action: "Credentials Revoked", detail: "Access keys deactivated, sessions invalidated", type: "remediation" }
      ],
      triggeringEvents: [
        { event: "iam:CreateAccessKey", reason: "New key created from unrecognized IP (185.220.101.42 - known Tor exit)" },
        { event: "sts:AssumeRole", reason: "Service account assuming admin role is abnormal" },
        { event: "s3:GetObject", reason: "Bulk download from sensitive bucket" }
      ],
      suspiciousIndicators: [
        "API calls from known Tor exit nodes or VPN IPs",
        "Service account performing interactive operations",
        "Privilege escalation followed by data enumeration",
        "Access pattern differs from baseline behavior",
        "Geographic anomaly in login location"
      ],
      detectionRule: `RULE credential_compromise_detection
  WHEN iam:CreateAccessKey.sourceIP IN threat_intel.tor_exits
  OR (sts:AssumeRole.targetRole = "Admin*" 
      AND sts:AssumeRole.userIdentity.type = "ServiceAccount")
  THEN ALERT "Critical: Potential credential compromise"
  ACTIONS: revoke_sessions, notify_soc, enable_enhanced_logging`
    }
  };

  return data[category] || data['Storage Security'];
}

function generateMarkdownReport(labTitle: string, category: string, data: any) {
  return `# Incident Report: ${labTitle}

## Executive Summary
${data.summary}

## Classification
- **Category:** ${category}
- **MITRE ATT&CK:** ${data.mitreAttack}
- **CIS Control:** ${data.cisControl}

## Attack Timeline
${data.timeline.map((e: any) => `- **${e.time}** [${e.type.toUpperCase()}] ${e.action}: ${e.detail}`).join('\n')}

## Remediation Steps
${data.remediationSteps.map((s: string, i: number) => `${i + 1}. ${s}`).join('\n')}

## Detection Engineering
### Triggering Events
${data.triggeringEvents.map((e: any) => `- **${e.event}**: ${e.reason}`).join('\n')}

### Suspicious Indicators
${data.suspiciousIndicators.map((s: string) => `- ${s}`).join('\n')}

### Detection Rule
\`\`\`
${data.detectionRule}
\`\`\`

---
*Report generated by CloudShieldLab Security Training Platform*
*${new Date().toISOString()}*
`;
}

interface ScorecardMetric {
  label: string;
  score: number;
  color: string;
  gradient: string;
  description: string;
}

interface ScorecardData {
  title: string;
  metrics: ScorecardMetric[];
  overallLabel: string;
  overallDescription: string;
  grade: string;
  recommendations: string[];
}

function getScorecardMetrics(labTitle: string, labCategory: string, difficulty: string, stepsCompleted: number, totalSteps: number, commandStreak?: number): ScorecardData {
  const titleLower = labTitle.toLowerCase();
  const completionRate = totalSteps > 0 ? Math.round((stepsCompleted / totalSteps) * 100) : 100;
  const streakBonus = commandStreak && commandStreak > 1 ? Math.min(commandStreak * 2, 10) : 0;
  
  const categoryMetrics: Record<string, ScorecardData> = {
    'Storage Security': getStorageSecurityMetrics(titleLower, completionRate, streakBonus),
    'Network Security': getNetworkSecurityMetrics(titleLower, completionRate, streakBonus),
    'IAM Security': getIAMSecurityMetrics(titleLower, completionRate, streakBonus),
    'SOC Operations': getSOCOperationsMetrics(titleLower, completionRate, streakBonus),
    'SOC Engineer': getSOCEngineerMetrics(titleLower, completionRate, streakBonus),
    'Cloud Security Analyst': getCloudSecurityAnalystMetrics(titleLower, completionRate, streakBonus),
    'Cloud Security Engineer': getCloudSecurityEngineerMetrics(titleLower, completionRate, streakBonus),
  };

  return categoryMetrics[labCategory] || getDefaultMetrics(titleLower, labCategory, completionRate, streakBonus);
}

function getStorageSecurityMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('public') || titleLower.includes('exposed')) {
    metrics = [
      { label: "Access Control Audit", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Identified and remediated public access misconfigurations" },
      { label: "Policy Enforcement", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Applied least-privilege bucket policies" },
      { label: "Data Classification", score: Math.min(88 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Sensitivity level properly assessed" },
      { label: "Encryption Status", score: 92, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Server-side encryption verification" },
    ];
    recommendations = [
      "You correctly identified the public access vulnerability",
      "Bucket policy now enforces authenticated access only",
      "Consider enabling S3 Block Public Access at account level"
    ];
  } else if (titleLower.includes('encryption') || titleLower.includes('kms')) {
    metrics = [
      { label: "Encryption Coverage", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "All objects now encrypted at rest" },
      { label: "Key Management", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "KMS key policies properly configured" },
      { label: "Key Rotation", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Automatic key rotation enabled" },
      { label: "Access Logging", score: Math.min(86 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "CloudTrail logging for key usage" },
    ];
    recommendations = [
      "KMS encryption is now enforced for all new objects",
      "Key policies follow least-privilege principles",
      "Consider implementing key deletion protection"
    ];
  } else if (titleLower.includes('logging') || titleLower.includes('audit')) {
    metrics = [
      { label: "Audit Coverage", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Access logging enabled on sensitive buckets" },
      { label: "Log Integrity", score: Math.min(96 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Log tampering protection verified" },
      { label: "Retention Policy", score: 88, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Logs retained for compliance period" },
      { label: "Alert Configuration", score: Math.min(82 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Anomaly detection rules configured" },
    ];
    recommendations = [
      "Audit logging now captures all access events",
      "Logs are protected against unauthorized modification",
      "Consider integrating with SIEM for real-time analysis"
    ];
  } else if (titleLower.includes('versioning') || titleLower.includes('compliance') || titleLower.includes('worm')) {
    metrics = [
      { label: "Version Control", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Object versioning enabled for recovery" },
      { label: "WORM Protection", score: Math.min(95 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Object lock preventing deletion" },
      { label: "Compliance Mode", score: 92, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Regulatory retention requirements met" },
      { label: "Recovery Testing", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Restore procedures validated" },
    ];
    recommendations = [
      "Data immutability now protects against ransomware",
      "Versioning enables point-in-time recovery",
      "Retention policies meet regulatory requirements"
    ];
  } else {
    metrics = [
      { label: "Security Posture", score: Math.min(94 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Overall storage security assessment" },
      { label: "Access Controls", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Authorization policies verified" },
      { label: "Data Protection", score: Math.min(90 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Encryption and backup status" },
      { label: "Monitoring", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Logging and alerting coverage" },
    ];
    recommendations = [
      "Storage security vulnerability successfully remediated",
      "Applied defense-in-depth principles",
      "Consider periodic security assessments"
    ];
  }

  return {
    title: "Storage Security Assessment",
    metrics,
    overallLabel: "Data Protection Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getNetworkSecurityMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('ssh') || titleLower.includes('rdp') || titleLower.includes('port')) {
    metrics = [
      { label: "Port Exposure", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Dangerous ports no longer internet-accessible" },
      { label: "Network Segmentation", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Traffic restricted to authorized subnets" },
      { label: "Firewall Rules", score: Math.min(96 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Security group follows least-privilege" },
      { label: "Attack Surface", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Reduced external attack vectors" },
    ];
    recommendations = [
      "Management ports now restricted to internal networks",
      "Security group rules follow zero-trust principles",
      "Consider implementing bastion host for remote access"
    ];
  } else if (titleLower.includes('vpc') || titleLower.includes('flow')) {
    metrics = [
      { label: "Traffic Visibility", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "VPC Flow Logs capturing all traffic" },
      { label: "Network Isolation", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Proper subnet segmentation" },
      { label: "Egress Control", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Outbound traffic restrictions" },
      { label: "Route Security", score: Math.min(86 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Route tables properly configured" },
    ];
    recommendations = [
      "Network traffic now fully visible for forensics",
      "VPC architecture follows security best practices",
      "Consider adding network traffic anomaly detection"
    ];
  } else if (titleLower.includes('nacl') || titleLower.includes('acl')) {
    metrics = [
      { label: "NACL Hardening", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Network ACLs properly restrictive" },
      { label: "Rule Ordering", score: Math.min(95 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Deny rules correctly prioritized" },
      { label: "Stateless Security", score: 92, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Both directions properly secured" },
      { label: "Defense Depth", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Layered security with SGs" },
    ];
    recommendations = [
      "NACLs now provide subnet-level protection",
      "Combined with security groups for defense-in-depth",
      "Consider periodic rule audits for drift detection"
    ];
  } else {
    metrics = [
      { label: "Network Hardening", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Overall network security posture" },
      { label: "Access Controls", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Firewall rules properly configured" },
      { label: "Segmentation", score: Math.min(90 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Network isolation verified" },
      { label: "Monitoring", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Traffic logging enabled" },
    ];
    recommendations = [
      "Network vulnerability successfully remediated",
      "Defense-in-depth architecture implemented",
      "Consider ongoing network security monitoring"
    ];
  }

  return {
    title: "Network Security Assessment",
    metrics,
    overallLabel: "Network Defense Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getIAMSecurityMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('mfa') || titleLower.includes('multi-factor')) {
    metrics = [
      { label: "MFA Enforcement", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Multi-factor authentication enabled" },
      { label: "Identity Strength", score: Math.min(96 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Authentication hardened against phishing" },
      { label: "Policy Compliance", score: 94, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Meets security policy requirements" },
      { label: "Access Risk", score: Math.min(90 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Reduced credential theft impact" },
    ];
    recommendations = [
      "Account now protected by multi-factor authentication",
      "Significantly reduced risk of credential compromise",
      "Consider hardware security keys for privileged accounts"
    ];
  } else if (titleLower.includes('privilege') || titleLower.includes('admin') || titleLower.includes('permission')) {
    metrics = [
      { label: "Least Privilege", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Permissions reduced to minimum required" },
      { label: "Blast Radius", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Limited damage from compromise" },
      { label: "Policy Specificity", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Granular resource restrictions" },
      { label: "Access Review", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Permissions audit completed" },
    ];
    recommendations = [
      "Excessive permissions successfully removed",
      "User now has only minimum required access",
      "Consider implementing access certification reviews"
    ];
  } else if (titleLower.includes('key') || titleLower.includes('credential') || titleLower.includes('rotation')) {
    metrics = [
      { label: "Key Hygiene", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Access keys properly managed" },
      { label: "Rotation Policy", score: Math.min(95 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Credential rotation configured" },
      { label: "Key Age", score: Math.min(90 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "No stale credentials present" },
      { label: "Usage Audit", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Key usage patterns analyzed" },
    ];
    recommendations = [
      "Credential lifecycle now properly managed",
      "Stale or unused keys have been remediated",
      "Consider implementing automatic key rotation"
    ];
  } else if (titleLower.includes('role') || titleLower.includes('trust') || titleLower.includes('assume')) {
    metrics = [
      { label: "Trust Policies", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Role trust relationships secured" },
      { label: "Cross-Account", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "External access properly restricted" },
      { label: "Session Control", score: 92, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Session duration limits applied" },
      { label: "Assumption Logging", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Role usage fully auditable" },
    ];
    recommendations = [
      "Role trust policies now follow least-privilege",
      "Cross-account access properly controlled",
      "Consider implementing external ID requirements"
    ];
  } else {
    metrics = [
      { label: "Identity Security", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Overall IAM security posture" },
      { label: "Access Controls", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Permission policies verified" },
      { label: "Credential Health", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Key and password management" },
      { label: "Audit Trail", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Identity actions logged" },
    ];
    recommendations = [
      "IAM security vulnerability successfully remediated",
      "Identity controls strengthened",
      "Consider regular IAM access reviews"
    ];
  }

  return {
    title: "Identity & Access Assessment",
    metrics,
    overallLabel: "IAM Security Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getSOCOperationsMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('triage') || titleLower.includes('alert')) {
    metrics = [
      { label: "Triage Speed", score: Math.min(94 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Rapid alert classification" },
      { label: "Classification", score: Math.min(96 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Accurate severity assessment" },
      { label: "False Positive ID", score: 88, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Correctly identified non-threats" },
      { label: "Escalation", score: Math.min(92 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Proper incident escalation" },
    ];
    recommendations = [
      "Alert triage completed efficiently",
      "Severity levels correctly prioritized",
      "Consider automation for common alert types"
    ];
  } else if (titleLower.includes('phishing') || titleLower.includes('email')) {
    metrics = [
      { label: "Threat Detection", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Phishing indicators identified" },
      { label: "IOC Extraction", score: Math.min(95 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Malicious artifacts catalogued" },
      { label: "Containment", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Threat properly isolated" },
      { label: "User Response", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Affected users notified" },
    ];
    recommendations = [
      "Phishing campaign successfully investigated",
      "Malicious URLs and IPs blocked",
      "Consider user awareness training follow-up"
    ];
  } else if (titleLower.includes('malware') || titleLower.includes('ransomware')) {
    metrics = [
      { label: "Containment Speed", score: Math.min(96 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Rapid threat isolation" },
      { label: "Impact Scope", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Blast radius assessment" },
      { label: "Evidence Preserved", score: 100, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Forensic artifacts captured" },
      { label: "Eradication", score: Math.min(90 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Malware fully removed" },
    ];
    recommendations = [
      "Malware contained before significant spread",
      "Forensic evidence preserved for analysis",
      "Consider IOC sharing with threat intel community"
    ];
  } else {
    metrics = [
      { label: "Detection Rate", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Threat identification accuracy" },
      { label: "Response Time", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Time to containment" },
      { label: "Investigation", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Forensic analysis depth" },
      { label: "Documentation", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Incident record quality" },
    ];
    recommendations = [
      "SOC incident handled effectively",
      "Proper playbook execution demonstrated",
      "Consider updating runbooks with lessons learned"
    ];
  }

  return {
    title: "SOC Performance Assessment",
    metrics,
    overallLabel: "Analyst Effectiveness",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getSOCEngineerMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('detection') || titleLower.includes('rule') || titleLower.includes('siem')) {
    metrics = [
      { label: "Rule Accuracy", score: Math.min(96 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Detection logic correctly implemented" },
      { label: "Coverage", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Attack techniques detected" },
      { label: "Tuning Quality", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "False positive rate optimized" },
      { label: "Performance", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Query efficiency" },
    ];
    recommendations = [
      "Detection rule properly engineered",
      "Rule logic covers known attack patterns",
      "Consider correlation with other data sources"
    ];
  } else if (titleLower.includes('log') || titleLower.includes('pipeline')) {
    metrics = [
      { label: "Data Quality", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Log parsing and enrichment" },
      { label: "Pipeline Health", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Data flow reliability" },
      { label: "Normalization", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Field standardization" },
      { label: "Retention", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Compliance requirements met" },
    ];
    recommendations = [
      "Log pipeline optimized for security analysis",
      "Data enrichment improves detection quality",
      "Consider adding threat intel enrichment"
    ];
  } else {
    metrics = [
      { label: "Engineering Quality", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Technical implementation" },
      { label: "Scalability", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Solution handles growth" },
      { label: "Maintainability", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Documentation and clarity" },
      { label: "Integration", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Works with existing tools" },
    ];
    recommendations = [
      "SOC engineering task completed successfully",
      "Solution follows security engineering best practices",
      "Consider automation opportunities"
    ];
  }

  return {
    title: "Security Engineering Assessment",
    metrics,
    overallLabel: "Engineering Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getCloudSecurityAnalystMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('credential') || titleLower.includes('compromise')) {
    metrics = [
      { label: "Threat Analysis", score: Math.min(96 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Attack chain fully mapped" },
      { label: "Containment", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Credentials revoked promptly" },
      { label: "Forensics", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Evidence properly preserved" },
      { label: "IOC Collection", score: Math.min(90 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Indicators documented" },
    ];
    recommendations = [
      "Credential compromise fully investigated",
      "Attack timeline reconstructed from logs",
      "Consider implementing credential anomaly detection"
    ];
  } else if (titleLower.includes('exfil') || titleLower.includes('data')) {
    metrics = [
      { label: "Data Protection", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Exfiltration stopped" },
      { label: "Impact Assessment", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Data exposure quantified" },
      { label: "Root Cause", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Attack vector identified" },
      { label: "Prevention", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Controls enhanced" },
    ];
    recommendations = [
      "Data exfiltration successfully stopped",
      "Breach scope properly assessed",
      "Consider implementing DLP controls"
    ];
  } else {
    metrics = [
      { label: "Analysis Depth", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Thorough investigation" },
      { label: "Response Speed", score: Math.min(92 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Quick containment" },
      { label: "Documentation", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Findings well documented" },
      { label: "Recommendations", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Actionable improvements" },
    ];
    recommendations = [
      "Cloud security incident properly handled",
      "Analysis followed best practices",
      "Consider threat hunting for similar patterns"
    ];
  }

  return {
    title: "Cloud Security Analysis",
    metrics,
    overallLabel: "Analyst Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getCloudSecurityEngineerMetrics(titleLower: string, completionRate: number, streakBonus: number): ScorecardData {
  let metrics: ScorecardMetric[] = [];
  let recommendations: string[] = [];

  if (titleLower.includes('guardduty') || titleLower.includes('detection')) {
    metrics = [
      { label: "Detection Config", score: 100, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "GuardDuty properly configured" },
      { label: "Coverage", score: Math.min(95 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "All regions monitored" },
      { label: "Alert Routing", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Notifications configured" },
      { label: "Integration", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Connected to SIEM" },
    ];
    recommendations = [
      "Threat detection properly implemented",
      "Alert coverage spans your environment",
      "Consider custom threat intelligence feeds"
    ];
  } else if (titleLower.includes('config') || titleLower.includes('compliance')) {
    metrics = [
      { label: "Compliance", score: Math.min(96 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Configuration rules enforced" },
      { label: "Drift Detection", score: 100, color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Changes automatically detected" },
      { label: "Remediation", score: Math.min(92 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Auto-fix where applicable" },
      { label: "Reporting", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Compliance dashboards ready" },
    ];
    recommendations = [
      "Configuration management properly implemented",
      "Drift detection catches unauthorized changes",
      "Consider implementing preventive controls"
    ];
  } else {
    metrics = [
      { label: "Architecture", score: Math.min(95 + streakBonus, 100), color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "Security design quality" },
      { label: "Implementation", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Technical execution" },
      { label: "Automation", score: 90, color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Infrastructure as code" },
      { label: "Resilience", score: Math.min(88 + streakBonus, 100), color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Fault tolerance" },
    ];
    recommendations = [
      "Cloud security engineering completed",
      "Solution follows AWS Well-Architected Framework",
      "Consider ongoing security posture monitoring"
    ];
  }

  return {
    title: "Security Engineering Assessment",
    metrics,
    overallLabel: "Engineering Score",
    overallDescription: getPerformanceDescription(metrics),
    grade: calculateGrade(metrics),
    recommendations
  };
}

function getDefaultMetrics(titleLower: string, category: string, completionRate: number, streakBonus: number): ScorecardData {
  return {
    title: `${category} Assessment`,
    metrics: [
      { label: "Task Completion", score: completionRate, color: "text-primary", gradient: "bg-gradient-to-r from-primary to-emerald-400", description: "All steps successfully completed" },
      { label: "Technical Accuracy", score: Math.min(94 + streakBonus, 100), color: "text-cyan-400", gradient: "bg-gradient-to-r from-cyan-400 to-blue-400", description: "Correct remediation actions" },
      { label: "Response Speed", score: Math.min(90 + streakBonus, 100), color: "text-amber-400", gradient: "bg-gradient-to-r from-amber-400 to-orange-400", description: "Efficient execution" },
      { label: "Best Practices", score: 88, color: "text-violet-400", gradient: "bg-gradient-to-r from-violet-400 to-purple-400", description: "Industry standard compliance" },
    ],
    overallLabel: "Performance Score",
    overallDescription: "Lab completed successfully",
    grade: "A",
    recommendations: [
      "Lab objective successfully achieved",
      "Security vulnerability properly remediated",
      "Consider reviewing related labs for deeper knowledge"
    ]
  };
}

function getPerformanceDescription(metrics: ScorecardMetric[]): string {
  const avgScore = metrics.reduce((sum, m) => sum + m.score, 0) / metrics.length;
  if (avgScore >= 95) return "Exceptional security response";
  if (avgScore >= 90) return "Excellent threat remediation";
  if (avgScore >= 85) return "Strong security performance";
  if (avgScore >= 80) return "Good defensive actions";
  return "Solid security fundamentals";
}

function calculateGrade(metrics: ScorecardMetric[]): string {
  const avgScore = metrics.reduce((sum, m) => sum + m.score, 0) / metrics.length;
  if (avgScore >= 95) return "A+";
  if (avgScore >= 90) return "A";
  if (avgScore >= 85) return "B+";
  if (avgScore >= 80) return "B";
  if (avgScore >= 75) return "C+";
  return "C";
}
