import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { motion } from "framer-motion";
import { Shield, Clock, CheckCircle2, AlertTriangle, FileText, Download, Target, Zap } from "lucide-react";
import { useState } from "react";

interface MissionCompleteModalProps {
  isOpen: boolean;
  onClose: () => void;
  labTitle: string;
  labCategory: string;
  difficulty: string;
}

export function MissionCompleteModal({ isOpen, onClose, labTitle, labCategory, difficulty }: MissionCompleteModalProps) {
  const [activeTab, setActiveTab] = useState<'summary' | 'timeline' | 'detection' | 'scorecard'>('summary');

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
                <Target className="w-4 h-4" /> Blue Team Scorecard
              </h3>
              
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: "Detection Accuracy", score: 95, color: "text-primary" },
                  { label: "Time to Remediation", score: 88, color: "text-cyan-400" },
                  { label: "Least Privilege", score: 100, color: "text-primary" },
                  { label: "False Positive Rate", score: 92, color: "text-violet-400" },
                ].map((metric, i) => (
                  <div key={i} className="bg-background/50 rounded-lg p-4 border border-border">
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-sm text-muted-foreground">{metric.label}</span>
                      <span className={`text-2xl font-bold ${metric.color}`}>{metric.score}%</span>
                    </div>
                    <div className="h-2 bg-black/50 rounded-full overflow-hidden">
                      <motion.div 
                        className={`h-full bg-gradient-to-r from-primary to-cyan-400`}
                        initial={{ width: 0 }}
                        animate={{ width: `${metric.score}%` }}
                        transition={{ duration: 1, delay: i * 0.1 }}
                      />
                    </div>
                  </div>
                ))}
              </div>

              <div className="bg-background/50 rounded-lg p-4 border border-primary/30">
                <div className="flex items-center justify-between">
                  <div>
                    <h4 className="text-white font-bold">Overall Performance</h4>
                    <p className="text-muted-foreground text-sm">Excellent threat response</p>
                  </div>
                  <div className="text-4xl font-bold text-primary">A+</div>
                </div>
              </div>
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
