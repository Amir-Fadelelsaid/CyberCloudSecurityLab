import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertTriangle, 
  Shield, 
  Server,
  Monitor,
  Globe,
  Laptop,
  Smartphone,
  Network,
  ChevronDown,
  ChevronRight,
  ChevronUp,
  Check,
  X,
  Search,
  Filter,
  Download,
  MoreHorizontal,
  Terminal,
  Eye,
  Clock,
  MapPin,
  Cpu,
  HardDrive,
  Wifi,
  Activity,
  AlertCircle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Settings,
  FileText,
  Layers
} from "lucide-react";
import { clsx } from "clsx";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuCheckboxItem,
} from "@/components/ui/dropdown-menu";
import { useToast } from "@/hooks/use-toast";
import { 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer,
  Legend 
} from "recharts";

// ============================================
// TYPES
// ============================================

interface Device {
  id: string;
  type: "server" | "workstation" | "unknown" | "mobile" | "network" | "video" | "storage";
  ipAddress: string;
  os: string;
  osIcon: "linux" | "windows" | "macos" | "unknown";
  deviceFunction: string;
  osVersion: string;
  hostName: string;
  securedState: "secured" | "unsecured" | "at-risk";
  macAddress: string;
  networkName: string;
  manufacturer: string;
  agentVersion?: string;
  lastSeen: string;
  cpu?: string;
  memory?: string;
  disk?: string;
  riskScore?: number;
  tags?: string[];
  reviewStatus?: "not-reviewed" | "allowed" | "under-analysis";
}

interface ThreatData {
  name: string;
  value: number;
  color: string;
}

interface SOCDashboardProps {
  labId: number;
  labCategory: string;
  labTitle?: string;
  onAlertSelect?: (alertId: string) => void;
  selectedAlertId?: string;
  className?: string;
}

// ============================================
// LAB-SPECIFIC DATA GENERATORS
// ============================================

// Generate devices based on specific lab title for contextual relevance
const generateDevicesForLab = (labTitle: string, category: string): Device[] => {
  // Lab-specific data based on exact lab titles
  const labDataMap: Record<string, Device[]> = {
    // === SOC OPERATIONS LABS ===
    "Phishing Email Investigation": [
      { id: "ws-001", type: "workstation", ipAddress: "192.168.1.102", os: "Windows 11", osIcon: "windows", deviceFunction: "Workstation", osVersion: "22H2", hostName: "WS-FINANCE-04", securedState: "unsecured", macAddress: "00:1B:2C:3D:4E:5F", networkName: "Corp-Finance", manufacturer: "HP Inc.", lastSeen: "2 min ago", riskScore: 92, reviewStatus: "not-reviewed", tags: ["PHISHING-CLICK", "MALICIOUS-URL"] },
      { id: "mail-001", type: "server", ipAddress: "10.0.20.15", os: "Exchange Server", osIcon: "windows", deviceFunction: "Mail Server", osVersion: "2019", hostName: "MAIL-PROD-01", securedState: "at-risk", macAddress: "00:50:56:AA:BB:CC", networkName: "Corp-Internal", manufacturer: "Microsoft", lastSeen: "Active", riskScore: 65, reviewStatus: "under-analysis", tags: ["SUSPICIOUS-SENDER"] },
      { id: "ws-002", type: "workstation", ipAddress: "192.168.1.89", os: "Windows 11", osIcon: "windows", deviceFunction: "Workstation", osVersion: "22H2", hostName: "WS-HR-02", securedState: "secured", macAddress: "00:1C:2D:3E:4F:60", networkName: "Corp-HR", manufacturer: "Dell Inc.", lastSeen: "5 min ago", riskScore: 15, reviewStatus: "allowed" },
    ],
    "Brute Force Attack Detection": [
      { id: "dc-001", type: "server", ipAddress: "192.168.1.10", os: "Windows Server 2022", osIcon: "windows", deviceFunction: "Domain Controller", osVersion: "21H2", hostName: "DC-PROD-01", securedState: "unsecured", macAddress: "00:1A:2B:3C:4D:5E", networkName: "Corp-AD", manufacturer: "Dell Inc.", lastSeen: "30 sec ago", riskScore: 95, reviewStatus: "not-reviewed", tags: ["BRUTE-FORCE", "5000-FAILED-LOGINS"] },
      { id: "dc-002", type: "server", ipAddress: "192.168.1.11", os: "Windows Server 2022", osIcon: "windows", deviceFunction: "Domain Controller", osVersion: "21H2", hostName: "DC-PROD-02", securedState: "at-risk", macAddress: "00:1A:2B:3C:4D:5F", networkName: "Corp-AD", manufacturer: "Dell Inc.", lastSeen: "1 min ago", riskScore: 72, reviewStatus: "under-analysis", tags: ["AUTH-SPIKE"] },
      { id: "vpn-001", type: "network", ipAddress: "10.0.0.5", os: "VPN Gateway", osIcon: "linux", deviceFunction: "VPN Concentrator", osVersion: "v9.1", hostName: "VPN-GW-01", securedState: "secured", macAddress: "00:0C:29:AA:BB:CC", networkName: "Edge", manufacturer: "Palo Alto", lastSeen: "Active", riskScore: 20, reviewStatus: "allowed" },
    ],
    "Malware Infection Response": [
      { id: "ws-mal-001", type: "workstation", ipAddress: "192.168.5.45", os: "Windows 10", osIcon: "windows", deviceFunction: "Workstation", osVersion: "21H2", hostName: "WS-DEV-12", securedState: "unsecured", macAddress: "00:1E:2F:3G:4H:5I", networkName: "Corp-Dev", manufacturer: "Lenovo", lastSeen: "Active", riskScore: 98, reviewStatus: "not-reviewed", tags: ["EMOTET", "C2-CALLBACK", "LATERAL-MOVEMENT"] },
      { id: "ws-mal-002", type: "workstation", ipAddress: "192.168.5.46", os: "Windows 10", osIcon: "windows", deviceFunction: "Workstation", osVersion: "21H2", hostName: "WS-DEV-13", securedState: "at-risk", macAddress: "00:1E:2F:3G:4H:5J", networkName: "Corp-Dev", manufacturer: "Lenovo", lastSeen: "5 min ago", riskScore: 75, reviewStatus: "under-analysis", tags: ["SUSPICIOUS-PROCESS"] },
      { id: "edr-001", type: "server", ipAddress: "10.0.10.60", os: "EDR Platform", osIcon: "linux", deviceFunction: "Endpoint Detection", osVersion: "v22.1", hostName: "edr-console-01", securedState: "secured", macAddress: "00:1A:2B:CC:DD:EE", networkName: "Security-Mgmt", manufacturer: "CrowdStrike", lastSeen: "Active", riskScore: 10, reviewStatus: "allowed" },
    ],
    "Ransomware Attack Triage": [
      { id: "fs-001", type: "server", ipAddress: "10.0.50.20", os: "Windows Server 2019", osIcon: "windows", deviceFunction: "File Server", osVersion: "1809", hostName: "FS-PROD-01", securedState: "unsecured", macAddress: "00:50:56:11:22:33", networkName: "Corp-Data", manufacturer: "HPE", lastSeen: "10 min ago", riskScore: 99, reviewStatus: "not-reviewed", tags: ["LOCKBIT-3.0", "ENCRYPTED-FILES", "RANSOM-NOTE"] },
      { id: "backup-001", type: "storage", ipAddress: "10.0.50.25", os: "Veeam Backup", osIcon: "linux", deviceFunction: "Backup Server", osVersion: "v12", hostName: "BACKUP-PROD-01", securedState: "at-risk", macAddress: "00:50:56:44:55:66", networkName: "Corp-Data", manufacturer: "Veeam", lastSeen: "15 min ago", riskScore: 85, reviewStatus: "under-analysis", tags: ["BACKUP-TARGETED"] },
      { id: "dc-001", type: "server", ipAddress: "192.168.1.10", os: "Windows Server 2022", osIcon: "windows", deviceFunction: "Domain Controller", osVersion: "21H2", hostName: "DC-PROD-01", securedState: "secured", macAddress: "00:1A:2B:3C:4D:5E", networkName: "Corp-AD", manufacturer: "Dell Inc.", lastSeen: "Active", riskScore: 25, reviewStatus: "allowed" },
    ],
    "Insider Threat Investigation": [
      { id: "ws-insider", type: "workstation", ipAddress: "192.168.3.101", os: "Windows 11", osIcon: "windows", deviceFunction: "Workstation", osVersion: "22H2", hostName: "WS-EXEC-CFO", securedState: "unsecured", macAddress: "A4:83:E7:2B:1C:9D", networkName: "Corp-Exec", manufacturer: "Apple Inc.", lastSeen: "Active", riskScore: 88, reviewStatus: "not-reviewed", tags: ["MASS-DOWNLOAD", "USB-ACTIVITY", "OFF-HOURS"] },
      { id: "dlp-001", type: "server", ipAddress: "10.0.10.70", os: "DLP Platform", osIcon: "linux", deviceFunction: "Data Loss Prevention", osVersion: "v8.5", hostName: "DLP-MONITOR-01", securedState: "at-risk", macAddress: "00:16:3E:DD:EE:FF", networkName: "Security-Mgmt", manufacturer: "Symantec", lastSeen: "Active", riskScore: 55, reviewStatus: "under-analysis", tags: ["ALERT-TRIGGERED"] },
      { id: "siem-001", type: "server", ipAddress: "10.0.10.50", os: "SIEM Platform", osIcon: "linux", deviceFunction: "Log Analysis", osVersion: "v8.12", hostName: "SIEM-PROD-01", securedState: "secured", macAddress: "00:16:3E:AA:BB:CC", networkName: "Security-Mgmt", manufacturer: "Splunk", lastSeen: "Active", riskScore: 10, reviewStatus: "allowed" },
    ],
    "Suspicious Network Traffic": [
      { id: "srv-c2", type: "server", ipAddress: "10.0.100.50", os: "Ubuntu 22.04", osIcon: "linux", deviceFunction: "Application Server", osVersion: "22.04 LTS", hostName: "APP-PROD-05", securedState: "unsecured", macAddress: "02:42:AC:11:00:32", networkName: "DMZ", manufacturer: "VMware", lastSeen: "Active", riskScore: 92, reviewStatus: "not-reviewed", tags: ["C2-BEACON", "DNS-TUNNEL", "COBALT-STRIKE"] },
      { id: "fw-001", type: "network", ipAddress: "10.0.0.1", os: "Firewall", osIcon: "linux", deviceFunction: "Perimeter Firewall", osVersion: "10.2.3", hostName: "FW-EDGE-01", securedState: "at-risk", macAddress: "00:0C:29:11:22:33", networkName: "Edge", manufacturer: "Palo Alto", lastSeen: "Active", riskScore: 60, reviewStatus: "under-analysis", tags: ["ANOMALY-DETECTED"] },
      { id: "ids-001", type: "server", ipAddress: "10.0.10.55", os: "IDS/IPS", osIcon: "linux", deviceFunction: "Intrusion Detection", osVersion: "6.0.15", hostName: "IDS-NETWORK-01", securedState: "secured", macAddress: "00:50:56:DD:EE:FF", networkName: "Security-Mgmt", manufacturer: "Suricata", lastSeen: "Active", riskScore: 15, reviewStatus: "allowed" },
    ],
    
    // === SOC ENGINEER LABS ===
    "SIEM Log Analysis": [
      { id: "siem-main", type: "server", ipAddress: "10.0.10.50", os: "Splunk Enterprise", osIcon: "linux", deviceFunction: "SIEM Platform", osVersion: "9.1.2", hostName: "SIEM-PROD-01", securedState: "at-risk", macAddress: "00:16:3E:AA:BB:CC", networkName: "Security-Mgmt", manufacturer: "Splunk", lastSeen: "Active", riskScore: 45, reviewStatus: "under-analysis", tags: ["LOG-GAP", "PARSING-ERROR"] },
      { id: "log-fwd", type: "server", ipAddress: "10.0.10.51", os: "Syslog Server", osIcon: "linux", deviceFunction: "Log Forwarder", osVersion: "Ubuntu 22.04", hostName: "LOG-FWD-01", securedState: "unsecured", macAddress: "00:16:3E:BB:CC:DD", networkName: "Security-Mgmt", manufacturer: "Canonical", lastSeen: "Active", riskScore: 78, reviewStatus: "not-reviewed", tags: ["MISSING-SOURCES"] },
      { id: "dc-log", type: "server", ipAddress: "192.168.1.10", os: "Windows Server 2022", osIcon: "windows", deviceFunction: "Domain Controller", osVersion: "21H2", hostName: "DC-PROD-01", securedState: "secured", macAddress: "00:1A:2B:3C:4D:5E", networkName: "Corp-AD", manufacturer: "Dell Inc.", lastSeen: "Active", riskScore: 20, reviewStatus: "allowed" },
    ],
    "Alert Tuning and Correlation": [
      { id: "siem-tune", type: "server", ipAddress: "10.0.10.50", os: "Elastic SIEM", osIcon: "linux", deviceFunction: "SIEM Platform", osVersion: "8.11", hostName: "SIEM-ELASTIC-01", securedState: "unsecured", macAddress: "00:16:3E:AA:BB:CC", networkName: "Security-Mgmt", manufacturer: "Elastic", lastSeen: "Active", riskScore: 72, reviewStatus: "not-reviewed", tags: ["FALSE-POSITIVES", "1000-ALERTS/DAY"] },
      { id: "soar-001", type: "server", ipAddress: "10.0.10.65", os: "SOAR Platform", osIcon: "linux", deviceFunction: "Security Orchestration", osVersion: "v6.8", hostName: "SOAR-PROD-01", securedState: "at-risk", macAddress: "00:16:3E:CC:DD:EE", networkName: "Security-Mgmt", manufacturer: "Palo Alto", lastSeen: "Active", riskScore: 55, reviewStatus: "under-analysis", tags: ["PLAYBOOK-FAILING"] },
      { id: "ticketing", type: "server", ipAddress: "10.0.10.70", os: "ServiceNow", osIcon: "linux", deviceFunction: "Ticketing System", osVersion: "Tokyo", hostName: "SNOW-PROD-01", securedState: "secured", macAddress: "00:16:3E:EE:FF:00", networkName: "Corp-IT", manufacturer: "ServiceNow", lastSeen: "Active", riskScore: 10, reviewStatus: "allowed" },
    ],
    "Threat Hunting Exercise": [
      { id: "hunt-target", type: "server", ipAddress: "10.0.50.100", os: "Windows Server 2019", osIcon: "windows", deviceFunction: "Application Server", osVersion: "1809", hostName: "APP-LEGACY-01", securedState: "unsecured", macAddress: "00:50:56:77:88:99", networkName: "Corp-Legacy", manufacturer: "VMware", lastSeen: "Active", riskScore: 85, reviewStatus: "not-reviewed", tags: ["PERSISTENCE", "SCHEDULED-TASK", "APT-INDICATOR"] },
      { id: "endpoint-001", type: "workstation", ipAddress: "192.168.5.200", os: "Windows 10", osIcon: "windows", deviceFunction: "Workstation", osVersion: "21H2", hostName: "WS-IT-ADMIN", securedState: "at-risk", macAddress: "00:1E:2F:3G:4H:5K", networkName: "Corp-IT", manufacturer: "Dell Inc.", lastSeen: "3 min ago", riskScore: 68, reviewStatus: "under-analysis", tags: ["LOL-BIN-USAGE"] },
      { id: "threat-intel", type: "server", ipAddress: "10.0.10.80", os: "MISP", osIcon: "linux", deviceFunction: "Threat Intel Platform", osVersion: "2.4.175", hostName: "MISP-PROD-01", securedState: "secured", macAddress: "00:16:3E:11:22:33", networkName: "Security-Mgmt", manufacturer: "CIRCL", lastSeen: "Active", riskScore: 12, reviewStatus: "allowed" },
    ],
    "Incident Response Playbook": [
      { id: "ir-target", type: "server", ipAddress: "10.0.100.25", os: "Ubuntu 20.04", osIcon: "linux", deviceFunction: "Web Server", osVersion: "20.04 LTS", hostName: "WEB-PROD-02", securedState: "unsecured", macAddress: "02:42:AC:11:00:19", networkName: "DMZ", manufacturer: "AWS", lastSeen: "Active", riskScore: 90, reviewStatus: "not-reviewed", tags: ["WEBSHELL", "REVERSE-SHELL", "ACTIVE-INTRUSION"] },
      { id: "forensics", type: "server", ipAddress: "10.0.10.90", os: "Forensics Workstation", osIcon: "linux", deviceFunction: "Forensics Platform", osVersion: "SIFT 22.04", hostName: "FORENSICS-01", securedState: "secured", macAddress: "00:16:3E:44:55:66", networkName: "Security-Mgmt", manufacturer: "SANS", lastSeen: "Active", riskScore: 5, reviewStatus: "allowed" },
      { id: "backup-ir", type: "storage", ipAddress: "10.0.50.25", os: "Veeam Backup", osIcon: "linux", deviceFunction: "Backup Server", osVersion: "v12", hostName: "BACKUP-PROD-01", securedState: "at-risk", macAddress: "00:50:56:44:55:66", networkName: "Corp-Data", manufacturer: "Veeam", lastSeen: "Active", riskScore: 45, reviewStatus: "under-analysis" },
    ],
    
    // === CLOUD SECURITY ANALYST LABS ===
    "CloudTrail Log Investigation": [
      { id: "ct-main", type: "server", ipAddress: "cloudtrail.amazonaws.com", os: "AWS CloudTrail", osIcon: "linux", deviceFunction: "Audit Logging", osVersion: "N/A", hostName: "trail-prod-us-east-1", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 88, reviewStatus: "not-reviewed", tags: ["SUSPICIOUS-API", "ROOT-ACTIVITY"] },
      { id: "iam-suspect", type: "unknown", ipAddress: "iam.amazonaws.com", os: "AWS IAM", osIcon: "linux", deviceFunction: "IAM User", osVersion: "N/A", hostName: "compromised-admin", securedState: "at-risk", macAddress: "N/A", networkName: "Global", manufacturer: "Amazon Web Services", lastSeen: "5 min ago", riskScore: 75, reviewStatus: "under-analysis", tags: ["NEW-ACCESS-KEY"] },
      { id: "s3-target", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "sensitive-data-bucket", securedState: "secured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 20, reviewStatus: "allowed" },
    ],
    "GuardDuty Finding Analysis": [
      { id: "gd-main", type: "server", ipAddress: "guardduty.amazonaws.com", os: "AWS GuardDuty", osIcon: "linux", deviceFunction: "Threat Detection", osVersion: "N/A", hostName: "guardduty-prod", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 85, reviewStatus: "not-reviewed", tags: ["HIGH-SEVERITY", "CRYPTO-MINING"] },
      { id: "ec2-mining", type: "server", ipAddress: "54.23.145.89", os: "Amazon Linux 2", osIcon: "linux", deviceFunction: "Compute Instance", osVersion: "2.0", hostName: "i-0abc123compromised", securedState: "at-risk", macAddress: "02:42:54:17:91:5B", networkName: "vpc-prod", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 92, reviewStatus: "under-analysis", tags: ["BITCOIN-MINER", "HIGH-CPU"] },
      { id: "vpc-flow", type: "network", ipAddress: "vpc.amazonaws.com", os: "AWS VPC", osIcon: "linux", deviceFunction: "Virtual Network", osVersion: "N/A", hostName: "vpc-production", securedState: "secured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 15, reviewStatus: "allowed" },
    ],
    "Security Hub Compliance Review": [
      { id: "sh-main", type: "server", ipAddress: "securityhub.amazonaws.com", os: "AWS Security Hub", osIcon: "linux", deviceFunction: "Security Posture", osVersion: "N/A", hostName: "securityhub-prod", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 78, reviewStatus: "not-reviewed", tags: ["CIS-FAILURES", "45-CRITICAL"] },
      { id: "config-001", type: "server", ipAddress: "config.amazonaws.com", os: "AWS Config", osIcon: "linux", deviceFunction: "Compliance Monitoring", osVersion: "N/A", hostName: "config-recorder-prod", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 55, reviewStatus: "under-analysis", tags: ["NON-COMPLIANT"] },
      { id: "inspector", type: "server", ipAddress: "inspector.amazonaws.com", os: "AWS Inspector", osIcon: "linux", deviceFunction: "Vulnerability Scanner", osVersion: "N/A", hostName: "inspector-prod", securedState: "secured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 20, reviewStatus: "allowed" },
    ],
    "AWS Config Rule Violation": [
      { id: "cfg-main", type: "server", ipAddress: "config.amazonaws.com", os: "AWS Config", osIcon: "linux", deviceFunction: "Configuration Compliance", osVersion: "N/A", hostName: "config-rules-prod", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 82, reviewStatus: "not-reviewed", tags: ["25-VIOLATIONS", "S3-RULES"] },
      { id: "s3-violate", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "dev-unencrypted-bucket", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 70, reviewStatus: "under-analysis", tags: ["ENCRYPTION-OFF"] },
      { id: "ec2-violate", type: "server", ipAddress: "54.23.145.100", os: "Amazon Linux 2", osIcon: "linux", deviceFunction: "Compute Instance", osVersion: "2.0", hostName: "i-untagged-instance", securedState: "at-risk", macAddress: "N/A", networkName: "vpc-dev", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 55, reviewStatus: "under-analysis", tags: ["NO-TAGS"] },
    ],
  };

  // Check for exact lab title match first
  if (labDataMap[labTitle]) {
    return labDataMap[labTitle];
  }

  // Fallback to category-based data
  return generateDevicesForCategory(category);
};

const generateDevicesForCategory = (category: string): Device[] => {
  switch (category) {
    case "Storage Security":
      return [
        { id: "s3-001", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "corp-payroll-data", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 95, reviewStatus: "not-reviewed", tags: ["PUBLIC", "PII"] },
        { id: "s3-002", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "customer-data-raw", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 88, reviewStatus: "not-reviewed", tags: ["UNENCRYPTED"] },
        { id: "s3-003", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "financial-reports", securedState: "at-risk", macAddress: "N/A", networkName: "us-west-2", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 72, reviewStatus: "under-analysis", tags: ["NO-LOGGING"] },
        { id: "s3-004", type: "storage", ipAddress: "s3.amazonaws.com", os: "AWS S3", osIcon: "linux", deviceFunction: "Object Storage", osVersion: "N/A", hostName: "disaster-recovery-backup", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 65, reviewStatus: "under-analysis", tags: ["NO-VERSIONING"] },
      ];
    case "Network Security":
      return [
        { id: "sg-001", type: "network", ipAddress: "0.0.0.0/0", os: "AWS Security Group", osIcon: "linux", deviceFunction: "Firewall", osVersion: "N/A", hostName: "web-app-sg", securedState: "unsecured", macAddress: "N/A", networkName: "vpc-prod", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 92, reviewStatus: "not-reviewed", tags: ["PORT-22-OPEN"] },
        { id: "sg-002", type: "network", ipAddress: "10.0.0.0/16", os: "AWS Security Group", osIcon: "linux", deviceFunction: "Firewall", osVersion: "N/A", hostName: "database-sg", securedState: "unsecured", macAddress: "N/A", networkName: "vpc-prod", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 85, reviewStatus: "not-reviewed", tags: ["RDP-EXPOSED"] },
        { id: "vpc-001", type: "network", ipAddress: "10.0.0.0/16", os: "AWS VPC", osIcon: "linux", deviceFunction: "Virtual Network", osVersion: "N/A", hostName: "vpc-production", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 68, reviewStatus: "under-analysis", tags: ["FLOW-LOGS-DISABLED"] },
      ];
    case "SOC Operations":
      return [
        { id: "alert-001", type: "server", ipAddress: "192.168.1.45", os: "Windows Server 2019", osIcon: "windows", deviceFunction: "Domain Controller", osVersion: "10.0.17763", hostName: "DC-PROD-01", securedState: "unsecured", macAddress: "00:1A:2B:3C:4D:5E", networkName: "Corp-Internal", manufacturer: "Dell Inc.", lastSeen: "2 min ago", riskScore: 95, reviewStatus: "not-reviewed", tags: ["BRUTE-FORCE"] },
        { id: "alert-002", type: "workstation", ipAddress: "192.168.1.102", os: "Windows 11", osIcon: "windows", deviceFunction: "Workstation", osVersion: "22H2", hostName: "WS-FINANCE-04", securedState: "unsecured", macAddress: "00:1B:2C:3D:4E:5F", networkName: "Corp-Internal", manufacturer: "HP Inc.", lastSeen: "5 min ago", riskScore: 88, reviewStatus: "not-reviewed", tags: ["MALWARE-DETECTED"] },
        { id: "alert-003", type: "server", ipAddress: "10.0.50.15", os: "Ubuntu 22.04", osIcon: "linux", deviceFunction: "Web Server", osVersion: "22.04 LTS", hostName: "web-prod-03", securedState: "at-risk", macAddress: "02:42:AC:11:00:02", networkName: "DMZ", manufacturer: "VMware", lastSeen: "1 min ago", riskScore: 75, reviewStatus: "under-analysis", tags: ["SQL-INJECTION"] },
      ];
    case "SOC Engineer":
      return [
        { id: "siem-001", type: "server", ipAddress: "10.0.10.50", os: "SIEM Platform", osIcon: "linux", deviceFunction: "Log Collector", osVersion: "v8.12", hostName: "siem-collector-01", securedState: "at-risk", macAddress: "00:16:3E:AA:BB:CC", networkName: "Security-Mgmt", manufacturer: "Splunk", lastSeen: "Active", riskScore: 45, reviewStatus: "under-analysis", tags: ["MISSING-LOGS"] },
        { id: "fw-001", type: "network", ipAddress: "10.0.0.1", os: "Firewall", osIcon: "linux", deviceFunction: "Perimeter Firewall", osVersion: "9.1.12", hostName: "fw-perimeter-01", securedState: "unsecured", macAddress: "00:0C:29:11:22:33", networkName: "Edge", manufacturer: "Palo Alto", lastSeen: "Active", riskScore: 78, reviewStatus: "not-reviewed", tags: ["LOGS-NOT-INTEGRATED"] },
        { id: "ids-001", type: "server", ipAddress: "10.0.10.55", os: "IDS/IPS", osIcon: "linux", deviceFunction: "Intrusion Detection", osVersion: "3.0.5", hostName: "ids-network-01", securedState: "at-risk", macAddress: "00:50:56:DD:EE:FF", networkName: "Security-Mgmt", manufacturer: "Suricata", lastSeen: "Active", riskScore: 55, reviewStatus: "under-analysis", tags: ["RULES-OUTDATED"] },
      ];
    case "Cloud Security Analyst":
      return [
        { id: "ct-001", type: "server", ipAddress: "cloudtrail.amazonaws.com", os: "AWS CloudTrail", osIcon: "linux", deviceFunction: "Audit Logging", osVersion: "N/A", hostName: "trail-prod", securedState: "unsecured", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 85, reviewStatus: "not-reviewed", tags: ["DISABLED"] },
        { id: "gd-001", type: "server", ipAddress: "guardduty.amazonaws.com", os: "AWS GuardDuty", osIcon: "linux", deviceFunction: "Threat Detection", osVersion: "N/A", hostName: "guardduty-prod", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 72, reviewStatus: "under-analysis", tags: ["HIGH-FINDINGS"] },
        { id: "sh-001", type: "server", ipAddress: "securityhub.amazonaws.com", os: "AWS Security Hub", osIcon: "linux", deviceFunction: "Security Posture", osVersion: "N/A", hostName: "securityhub-prod", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 65, reviewStatus: "under-analysis", tags: ["CRITICAL-FINDINGS"] },
      ];
    case "IAM Security":
      return [
        { id: "iam-001", type: "unknown", ipAddress: "iam.amazonaws.com", os: "AWS IAM", osIcon: "linux", deviceFunction: "IAM User", osVersion: "N/A", hostName: "admin-user", securedState: "unsecured", macAddress: "N/A", networkName: "Global", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 95, reviewStatus: "not-reviewed", tags: ["NO-MFA", "ADMIN"] },
        { id: "iam-002", type: "unknown", ipAddress: "iam.amazonaws.com", os: "AWS IAM", osIcon: "linux", deviceFunction: "IAM Role", osVersion: "N/A", hostName: "ec2-role-overprivileged", securedState: "unsecured", macAddress: "N/A", networkName: "Global", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 88, reviewStatus: "not-reviewed", tags: ["ADMIN-ACCESS"] },
        { id: "iam-003", type: "unknown", ipAddress: "iam.amazonaws.com", os: "AWS IAM", osIcon: "linux", deviceFunction: "Access Key", osVersion: "N/A", hostName: "AKIA...STALE", securedState: "at-risk", macAddress: "N/A", networkName: "Global", manufacturer: "Amazon Web Services", lastSeen: "180+ days", riskScore: 75, reviewStatus: "under-analysis", tags: ["STALE-KEY"] },
      ];
    case "Cloud Security Engineer":
      return [
        { id: "ec2-001", type: "server", ipAddress: "54.23.145.89", os: "Amazon Linux 2", osIcon: "linux", deviceFunction: "Web Server", osVersion: "2.0", hostName: "web-prod-01", securedState: "unsecured", macAddress: "02:42:54:17:91:5B", networkName: "vpc-prod", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 85, reviewStatus: "not-reviewed", tags: ["PUBLIC-IP", "NO-IMDSV2"] },
        { id: "rds-001", type: "storage", ipAddress: "db.cluster.us-east-1.rds.amazonaws.com", os: "AWS RDS MySQL", osIcon: "linux", deviceFunction: "Database", osVersion: "8.0.32", hostName: "prod-mysql-cluster", securedState: "unsecured", macAddress: "N/A", networkName: "vpc-prod", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 78, reviewStatus: "not-reviewed", tags: ["PUBLIC-ACCESS"] },
        { id: "lambda-001", type: "server", ipAddress: "lambda.amazonaws.com", os: "AWS Lambda", osIcon: "linux", deviceFunction: "Serverless Function", osVersion: "Python 3.9", hostName: "data-processor", securedState: "at-risk", macAddress: "N/A", networkName: "us-east-1", manufacturer: "Amazon Web Services", lastSeen: "Active", riskScore: 65, reviewStatus: "under-analysis", tags: ["SECRETS-IN-ENV"] },
      ];
    default:
      return [
        { id: "dev-001", type: "server", ipAddress: "192.168.1.133", os: "Debian", osIcon: "linux", deviceFunction: "Server", osVersion: "N/A", hostName: "N/A", securedState: "unsecured", macAddress: "e0:63:da:ca:84:04", networkName: "N/A", manufacturer: "Ubiquiti Networks Inc.", lastSeen: "2 min ago", riskScore: 85, reviewStatus: "not-reviewed" },
        { id: "dev-002", type: "server", ipAddress: "192.168.1.130", os: "Debian", osIcon: "linux", deviceFunction: "Server", osVersion: "N/A", hostName: "N/A", securedState: "unsecured", macAddress: "e0:63:da:e6:64:28", networkName: "N/A", manufacturer: "Ubiquiti Networks Inc.", lastSeen: "5 min ago", riskScore: 72, reviewStatus: "not-reviewed" },
      ];
  }
};

const generateDevices = (): Device[] => {
  return [
    {
      id: "dev-001",
      type: "server",
      ipAddress: "192.168.1.133",
      os: "Debian",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "e0:63:da:ca:84:04",
      networkName: "N/A",
      manufacturer: "Ubiquiti Networks Inc.",
      lastSeen: "2 min ago",
      riskScore: 85,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-002",
      type: "server",
      ipAddress: "192.168.1.130",
      os: "Debian",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "e0:63:da:e6:64:28",
      networkName: "N/A",
      manufacturer: "Ubiquiti Networks Inc.",
      lastSeen: "5 min ago",
      riskScore: 72,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-003",
      type: "server",
      ipAddress: "192.168.1.1",
      os: "Debian",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "74:ac:b9:55:3b:66",
      networkName: "N/A",
      manufacturer: "Ubiquiti Networks Inc.",
      lastSeen: "1 min ago",
      riskScore: 90,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-004",
      type: "server",
      ipAddress: "172.17.20.1",
      os: "Linux Distribution",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "0a:e4:ee:99:a4:5f",
      networkName: "N/A",
      manufacturer: "N/A",
      lastSeen: "30 sec ago",
      riskScore: 65,
      reviewStatus: "under-analysis"
    },
    {
      id: "dev-005",
      type: "server",
      ipAddress: "192.168.11.150",
      os: "Debian",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "1c:a9:7e:62:3c:d2",
      networkName: "BenM-Home",
      manufacturer: "EliteGroup Computer Syst...",
      lastSeen: "3 min ago",
      riskScore: 55,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-006",
      type: "server",
      ipAddress: "192.168.11.151",
      os: "Ubuntu",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "00:0c:29:c4:a4:75",
      networkName: "BenM-Home",
      manufacturer: "VMware, Inc.",
      lastSeen: "1 min ago",
      riskScore: 78,
      reviewStatus: "allowed"
    },
    {
      id: "dev-007",
      type: "server",
      ipAddress: "172.17.20.42",
      os: "CentOS",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "0a:dc:08:f5:40:a9",
      networkName: "N/A",
      manufacturer: "N/A",
      lastSeen: "45 sec ago",
      riskScore: 82,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-008",
      type: "server",
      ipAddress: "10.10.10.125",
      os: "Linux Distribution",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "b0:02:47:98:1b:5d",
      networkName: "N/A",
      manufacturer: "AMPAK Technology, Inc.",
      lastSeen: "2 min ago",
      riskScore: 45,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-009",
      type: "server",
      ipAddress: "192.168.0.1",
      os: "Debian",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "4c:ed:fb:7a:f4:10",
      networkName: "Merrick - LA8",
      manufacturer: "ASUSTek COMPUTER INC.",
      lastSeen: "4 min ago",
      riskScore: 68,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-010",
      type: "server",
      ipAddress: "10.0.0.26",
      os: "Windows Server 2016 or 2019",
      osIcon: "windows",
      deviceFunction: "Server",
      osVersion: "dc-sso1",
      hostName: "dc-sso1",
      securedState: "unsecured",
      macAddress: "00:15:5d:01:05:07",
      networkName: "N/A",
      manufacturer: "Microsoft Corporation",
      lastSeen: "1 min ago",
      riskScore: 95,
      reviewStatus: "not-reviewed",
      tags: ["Domain Controller", "Critical"]
    },
    {
      id: "dev-011",
      type: "server",
      ipAddress: "192.168.1.1",
      os: "Ubuntu",
      osIcon: "linux",
      deviceFunction: "Server",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "00:90:7f:a0:0c:66",
      networkName: "N/A",
      manufacturer: "WatchGuard Technologies...",
      lastSeen: "30 sec ago",
      riskScore: 70,
      reviewStatus: "not-reviewed"
    },
    {
      id: "dev-012",
      type: "workstation",
      ipAddress: "192.168.1.100",
      os: "MacOS",
      osIcon: "macos",
      deviceFunction: "Workstation",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "88:66:5a:33:5a:e8",
      networkName: "N/A",
      manufacturer: "Apple, Inc.",
      lastSeen: "5 min ago",
      riskScore: 40,
      reviewStatus: "allowed"
    },
    {
      id: "dev-013",
      type: "workstation",
      ipAddress: "192.168.1.200",
      os: "Windows 10",
      osIcon: "windows",
      deviceFunction: "Unknown",
      osVersion: "N/A",
      hostName: "N/A",
      securedState: "unsecured",
      macAddress: "10:08:b1:6d:a3:31",
      networkName: "N/A",
      manufacturer: "Hon Hai Precision Ind. Co...",
      lastSeen: "2 min ago",
      riskScore: 55,
      reviewStatus: "not-reviewed"
    }
  ];
};

const securedStateData: ThreatData[] = [
  { name: "Secured", value: 0, color: "#22c55e" },
  { name: "Unsecured", value: 57, color: "#ef4444" }
];

const deviceReviewData: ThreatData[] = [
  { name: "Not Reviewed", value: 43, color: "#6366f1" },
  { name: "Allowed", value: 12, color: "#22c55e" },
  { name: "Under Analysis", value: 2, color: "#f59e0b" }
];

const threatsByEngine: { name: string; value: number; }[] = [
  { name: "SentinelOne Cloud", value: 10500 },
  { name: "On-Write Static AI", value: 8200 },
  { name: "Documents, Scripts", value: 4100 },
  { name: "Manual", value: 2800 },
  { name: "On-Write Static AI - Suspicious", value: 2200 },
  { name: "Behavioral AI", value: 1800 },
  { name: "Application Control", value: 1200 },
  { name: "Reputation", value: 800 },
  { name: "User-Defined Blacklist", value: 400 },
  { name: "Intrusion Detection", value: 200 }
];

const threatsByType: ThreatData[] = [
  { name: "Ransomware", value: 35, color: "#ef4444" },
  { name: "Malware", value: 25, color: "#f97316" },
  { name: "Trojan", value: 15, color: "#eab308" },
  { name: "Application Control", value: 10, color: "#22c55e" },
  { name: "Virus", value: 5, color: "#06b6d4" },
  { name: "Backdoor", value: 4, color: "#8b5cf6" },
  { name: "Adware", value: 3, color: "#ec4899" },
  { name: "Worm", value: 3, color: "#64748b" }
];

const osTypeData = {
  linux: 29,
  windows: 13,
  apple: 3,
  android: 0,
  unix: 0,
  unknown: 6
};

// ============================================
// COMPONENTS
// ============================================

// Donut Chart Component
function DonutChart({ 
  data, 
  centerLabel, 
  centerValue,
  size = 120 
}: { 
  data: ThreatData[]; 
  centerLabel?: string; 
  centerValue?: string | number;
  size?: number;
}) {
  const total = data.reduce((sum, item) => sum + item.value, 0);
  
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={size * 0.35}
            outerRadius={size * 0.45}
            paddingAngle={2}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      {centerLabel && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-xs text-slate-400 uppercase tracking-wider">{centerLabel}</span>
          <span className="text-xl font-bold text-white">{centerValue ?? total}</span>
        </div>
      )}
    </div>
  );
}

// OS Icon Component
function OSIcon({ os }: { os: "linux" | "windows" | "macos" | "unknown" }) {
  const iconClass = "w-4 h-4";
  
  switch (os) {
    case "linux":
      return <Server className={clsx(iconClass, "text-amber-400")} />;
    case "windows":
      return <Monitor className={clsx(iconClass, "text-blue-400")} />;
    case "macos":
      return <Laptop className={clsx(iconClass, "text-slate-300")} />;
    default:
      return <HardDrive className={clsx(iconClass, "text-slate-500")} />;
  }
}

// Device Type Icon
function DeviceTypeIcon({ type }: { type: Device["type"] }) {
  const iconClass = "w-4 h-4 text-slate-400";
  
  switch (type) {
    case "server":
      return <Server className={iconClass} />;
    case "workstation":
      return <Monitor className={iconClass} />;
    case "mobile":
      return <Smartphone className={iconClass} />;
    case "network":
      return <Network className={iconClass} />;
    default:
      return <HardDrive className={iconClass} />;
  }
}

// Secured State Badge
function SecuredStateBadge({ state }: { state: Device["securedState"] }) {
  const config = {
    secured: { icon: CheckCircle2, color: "text-green-400", label: "Secured" },
    unsecured: { icon: XCircle, color: "text-red-400", label: "Unsecured" },
    "at-risk": { icon: AlertTriangle, color: "text-yellow-400", label: "At Risk" }
  };
  
  const { icon: Icon, color, label } = config[state];
  
  return (
    <div className="flex items-center gap-1.5">
      <Icon className={clsx("w-4 h-4", color)} />
      <span className={clsx("text-xs", color)}>{label}</span>
    </div>
  );
}

// Expanded Device Details Panel
function DeviceDetailsPanel({ device, onClose }: { device: Device; onClose: () => void }) {
  const [showMoreInfo, setShowMoreInfo] = useState(false);
  
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      className="bg-slate-900/80 border-t border-slate-700/50"
    >
      <div className="p-4 grid grid-cols-4 gap-4">
        {/* Device Info */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-12 h-12 rounded-lg bg-slate-700/50 flex items-center justify-center">
              <Server className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="text-xs text-slate-400">Server</div>
              <div className="text-sm font-semibold text-white">{device.deviceFunction}</div>
            </div>
            <SecuredStateBadge state={device.securedState} />
          </div>
          
          <Button 
            size="sm" 
            variant="outline" 
            className="mb-4 text-cyan-400 border-cyan-500/50"
            onClick={(e) => { e.stopPropagation(); alert('Deploy Agent clicked'); }}
            data-testid="button-deploy-agent"
          >
            Deploy Agent
          </Button>
          
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Hostname</span>
              <span className="text-slate-200">{device.hostName}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">OS</span>
              <span className="text-slate-200">{device.os}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">IP Address</span>
              <span className="text-slate-200">{device.ipAddress}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">MAC Address</span>
              <span className="text-slate-200 font-mono text-[10px]">{device.macAddress}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Manufacturer</span>
              <span className="text-slate-200 truncate max-w-[150px]">{device.manufacturer}</span>
            </div>
          </div>
          
          <div className="flex gap-2 mt-4 flex-wrap">
            <Button size="sm" variant="ghost" className="text-xs text-slate-400" onClick={(e) => e.stopPropagation()}>
              <Search className="w-3 h-3 mr-1" /> Search
            </Button>
            <Button size="sm" variant="ghost" className="text-xs text-slate-400" onClick={(e) => e.stopPropagation()}>
              <FileText className="w-3 h-3 mr-1" /> Raw Data
            </Button>
            <Button size="sm" variant="ghost" className="text-xs text-slate-400" onClick={(e) => e.stopPropagation()}>
              <Network className="w-3 h-3 mr-1" /> Isolate
            </Button>
          </div>
        </div>
        
        {/* Device Review */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-white">Device Review</span>
            <Button size="sm" variant="outline" className="ml-auto text-xs text-cyan-400 border-cyan-500/50" onClick={(e) => e.stopPropagation()}>
              Review Device
            </Button>
          </div>
          
          <div className="mb-3">
            <div className="text-xs text-slate-400 mb-1">Current Status</div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <span className="text-green-400 font-medium">Allowed</span>
            </div>
          </div>
          
          <div className="text-xs text-slate-400 mb-2">
            Reviewed By: steven@sentinelone.c...
            <br />
            Tue, Nov 23, 2021, 8:54:06 PM
          </div>
          
          <Button 
            size="sm" 
            variant="ghost" 
            className="text-xs text-cyan-400 p-0 h-auto" 
            onClick={(e) => { e.stopPropagation(); setShowMoreInfo(!showMoreInfo); }}
          >
            {showMoreInfo ? 'Less Info' : 'More Info'}
          </Button>
          
          <AnimatePresence>
            {showMoreInfo && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="mt-3 space-y-2 text-xs overflow-hidden"
              >
                <div className="flex justify-between">
                  <span className="text-slate-400">Review Reason</span>
                  <span className="text-slate-200">Baseline Review</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Policy Applied</span>
                  <span className="text-cyan-400">Endpoint Protection v2.1</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Agent Version</span>
                  <span className="text-slate-200">21.1.4.10010</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Last Scan</span>
                  <span className="text-green-400">Clean (2 days ago)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Threat History</span>
                  <span className="text-slate-200">0 detected (90 days)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Group Policy</span>
                  <span className="text-slate-200">Corp Workstations</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-400">Exclusions</span>
                  <span className="text-amber-400">3 active</span>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
          
          <div className="mt-4 pt-4 border-t border-slate-700/50 space-y-2">
            <div className="flex items-center gap-2 text-xs">
              <div className="w-2 h-2 rounded-full bg-slate-500" />
              <span className="text-slate-400">Not Reviewed</span>
              <ChevronRight className="w-3 h-3 text-slate-500" />
              <div className="w-2 h-2 rounded-full bg-green-500" />
              <span className="text-slate-400">Allowed</span>
            </div>
          </div>
        </div>
        
        {/* Device Tags */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Layers className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-white">Device Tags</span>
          </div>
          
          <div className="flex items-center gap-2 mb-4">
            <input 
              type="text" 
              placeholder="Type tag name" 
              className="flex-1 bg-slate-700/50 border border-slate-600 rounded px-3 py-1.5 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          
          {device.tags && device.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {device.tags.map((tag, i) => (
                <span key={i} className="px-2 py-1 bg-cyan-500/20 text-cyan-300 text-xs rounded border border-cyan-500/30">
                  {tag}
                </span>
              ))}
            </div>
          )}
          
          <div className="flex gap-2 mt-4">
            <Button size="sm" variant="ghost" className="text-xs text-slate-400" onClick={(e) => e.stopPropagation()}>
              Undo
            </Button>
            <Button size="sm" className="text-xs bg-cyan-600 text-white" onClick={(e) => e.stopPropagation()}>
              Save
            </Button>
          </div>
        </div>
        
        {/* Network Details */}
        <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700/50">
          <div className="flex items-center gap-2 mb-4">
            <Wifi className="w-4 h-4 text-slate-400" />
            <span className="text-sm font-medium text-white">Network Details</span>
          </div>
          
          <div className="space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-slate-400">Network Name</span>
              <span className="text-slate-200">{device.networkName}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Gateway MAC</span>
              <span className="text-slate-200 font-mono text-[10px]">{device.macAddress}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Gateway IP</span>
              <span className="text-slate-200">{device.ipAddress}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Gateway Visible IP</span>
              <span className="text-slate-200">73.96.137.219</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Subnet</span>
              <span className="text-slate-200">192.168.1.0/24</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Discovered By</span>
              <div className="flex gap-1">
                <span className="px-1.5 py-0.5 bg-slate-700 text-slate-300 text-[10px] rounded">portscan</span>
                <span className="px-1.5 py-0.5 bg-slate-700 text-slate-300 text-[10px] rounded">ping</span>
              </div>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">TCP Ports</span>
              <div className="flex gap-1">
                <span className="px-1.5 py-0.5 bg-cyan-600/30 text-cyan-300 text-[10px] rounded">80</span>
                <span className="px-1.5 py-0.5 bg-cyan-600/30 text-cyan-300 text-[10px] rounded">443</span>
                <span className="px-1.5 py-0.5 bg-cyan-600/30 text-cyan-300 text-[10px] rounded">22</span>
              </div>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">UDP Ports</span>
              <span className="text-slate-200">N/A</span>
            </div>
            <div className="flex justify-between pt-2 border-t border-slate-700/50 mt-2">
              <span className="text-slate-400">First Seen</span>
              <span className="text-slate-200 text-[10px]">Mon, Aug 2, 2021</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Last Update</span>
              <span className="text-slate-200 text-[10px]">Mon, Mar 28, 2022</span>
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

// Main Table Row
function DeviceRow({ 
  device, 
  isExpanded, 
  onToggle,
  isSelected,
  onSelect
}: { 
  device: Device; 
  isExpanded: boolean;
  onToggle: () => void;
  isSelected: boolean;
  onSelect: () => void;
}) {
  return (
    <>
      <motion.tr
        className={clsx(
          "border-b border-slate-800/50 hover:bg-slate-800/30 cursor-pointer transition-colors",
          isExpanded && "bg-slate-800/40",
          isSelected && "bg-purple-900/20"
        )}
        onClick={onToggle}
        data-testid={`row-device-${device.id}`}
      >
        <td className="px-3 py-2">
          <button
            onClick={(e) => { e.stopPropagation(); onToggle(); }}
            className="p-1 hover:bg-slate-700 rounded"
          >
            {isExpanded ? (
              <ChevronDown className="w-4 h-4 text-slate-400" />
            ) : (
              <ChevronRight className="w-4 h-4 text-slate-400" />
            )}
          </button>
        </td>
        <td className="px-3 py-2">
          <input 
            type="checkbox" 
            checked={isSelected}
            onChange={onSelect}
            onClick={(e) => e.stopPropagation()}
            className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-purple-500 focus:ring-purple-500 focus:ring-offset-0"
          />
        </td>
        <td className="px-3 py-2">
          <DeviceTypeIcon type={device.type} />
        </td>
        <td className="px-3 py-2 text-xs text-slate-300 font-mono">{device.ipAddress}</td>
        <td className="px-3 py-2">
          <div className="flex items-center gap-1.5">
            <OSIcon os={device.osIcon} />
            <AlertTriangle className="w-3 h-3 text-yellow-500" />
          </div>
        </td>
        <td className="px-3 py-2 text-xs text-slate-300">{device.deviceFunction}</td>
        <td className="px-3 py-2 text-xs text-slate-400">{device.osVersion}</td>
        <td className="px-3 py-2 text-xs text-slate-400">{device.hostName}</td>
        <td className="px-3 py-2">
          <SecuredStateBadge state={device.securedState} />
        </td>
        <td className="px-3 py-2 text-[10px] text-slate-400 font-mono">{device.macAddress}</td>
        <td className="px-3 py-2 text-xs text-slate-400">{device.networkName}</td>
        <td className="px-3 py-2 text-xs text-slate-400 truncate max-w-[150px]">{device.manufacturer}</td>
      </motion.tr>
      
      <AnimatePresence>
        {isExpanded && (
          <tr>
            <td colSpan={12} className="p-0">
              <DeviceDetailsPanel device={device} onClose={onToggle} />
            </td>
          </tr>
        )}
      </AnimatePresence>
    </>
  );
}

// ============================================
// MAIN COMPONENT
// ============================================

export function SOCDashboard({ 
  labId, 
  labCategory, 
  labTitle = "",
  onAlertSelect, 
  selectedAlertId,
  className 
}: SOCDashboardProps) {
  const { toast } = useToast();
  const [devices] = useState<Device[]>(generateDevicesForLab(labTitle, labCategory));
  const [expandedDeviceId, setExpandedDeviceId] = useState<string | null>(null);
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeView, setActiveView] = useState<"devices" | "dashboard">("devices");
  const [resultsPerPage, setResultsPerPage] = useState(20);
  const [visibleColumns, setVisibleColumns] = useState({
    type: true,
    ip: true,
    os: true,
    function: true,
    version: true,
    host: true,
    state: true,
    mac: true,
    network: true,
    manufacturer: true
  });
  
  const handleAction = (action: string) => {
    const count = selectedDevices.size;
    if (count === 0) {
      toast({
        title: "No devices selected",
        description: "Please select one or more devices first",
        variant: "destructive"
      });
      return;
    }
    toast({
      title: `${action} initiated`,
      description: `Processing ${count} device${count > 1 ? 's' : ''}...`
    });
  };
  
  const handleExport = (format: string) => {
    toast({
      title: `Exporting as ${format}`,
      description: `Generating ${format.toUpperCase()} file with ${devices.length} devices...`
    });
  };

  // Simulate network scanning
  useEffect(() => {
    const interval = setInterval(() => {
      setIsScanning(true);
      setScanProgress(0);
      const progressInterval = setInterval(() => {
        setScanProgress(p => {
          if (p >= 100) {
            clearInterval(progressInterval);
            setTimeout(() => setIsScanning(false), 1000);
            return 100;
          }
          return p + 10;
        });
      }, 200);
    }, 30000); // Scan every 30 seconds

    return () => clearInterval(interval);
  }, []);

  const toggleDeviceSelection = (deviceId: string) => {
    setSelectedDevices(prev => {
      const next = new Set(prev);
      if (next.has(deviceId)) {
        next.delete(deviceId);
      } else {
        next.add(deviceId);
      }
      return next;
    });
  };

  const selectAllDevices = () => {
    if (selectedDevices.size === devices.length) {
      setSelectedDevices(new Set());
    } else {
      setSelectedDevices(new Set(devices.map(d => d.id)));
    }
  };

  return (
    <div className={clsx("h-full flex flex-col bg-[#0a0a0f] rounded-xl border border-slate-700/50 overflow-hidden", className)}>
      {/* Summary Cards Row */}
      <div className="flex-shrink-0 p-4 border-b border-slate-800/50 overflow-x-auto">
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 min-w-0">
          {/* Secured State */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30 overflow-hidden">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
              Secured State
            </div>
            <div className="flex items-center justify-center">
              <DonutChart 
                data={securedStateData} 
                centerLabel="TOTAL"
                centerValue="57"
                size={100}
              />
            </div>
            <div className="flex flex-wrap justify-center gap-2 mt-3">
              <div className="flex items-center gap-1 text-[10px]">
                <div className="w-2 h-2 rounded-full bg-green-500 flex-shrink-0" />
                <span className="text-slate-400">0%</span>
                <span className="text-slate-500">Secured</span>
              </div>
              <div className="flex items-center gap-1 text-[10px]">
                <div className="w-2 h-2 rounded-full bg-red-500 flex-shrink-0" />
                <span className="text-slate-400">100%</span>
                <span className="text-slate-500">Unsecured</span>
              </div>
            </div>
          </div>

          {/* Device Review */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30 overflow-hidden">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
              Device Review
            </div>
            <div className="flex items-center justify-center">
              <DonutChart 
                data={deviceReviewData} 
                centerLabel="TOTAL"
                centerValue="57"
                size={100}
              />
            </div>
            <div className="space-y-1 mt-3">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-purple-500" />
                  <span className="text-slate-400">Not Reviewed</span>
                </div>
                <span className="px-2 py-0.5 bg-purple-500/20 text-purple-300 rounded text-[10px]">75%</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-green-500" />
                  <span className="text-slate-400">Allowed</span>
                </div>
                <span className="px-2 py-0.5 bg-green-500/20 text-green-300 rounded text-[10px]">21%</span>
              </div>
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-full bg-yellow-500" />
                  <span className="text-slate-400">Under Analysis</span>
                </div>
                <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-300 rounded text-[10px]">4%</span>
              </div>
            </div>
          </div>

          {/* Devices Total */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30 overflow-hidden">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
              Devices (TOTAL: 57)
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-1 min-w-0">
                <Server className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Server</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">45</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Monitor className="w-4 h-4 text-purple-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Workstation</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">11</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <HardDrive className="w-4 h-4 text-slate-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Unknown</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">1</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Globe className="w-4 h-4 text-green-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Infra</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Smartphone className="w-4 h-4 text-orange-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Mobile</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Monitor className="w-4 h-4 text-blue-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Printer</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Eye className="w-4 h-4 text-red-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Video</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Smartphone className="w-4 h-4 text-pink-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Phone</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <Network className="w-4 h-4 text-yellow-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Network</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
              <div className="flex items-center gap-1 min-w-0">
                <HardDrive className="w-4 h-4 text-indigo-400 flex-shrink-0" />
                <span className="text-slate-300 truncate">Storage</span>
                <span className="ml-auto text-slate-400 flex-shrink-0">0</span>
              </div>
            </div>
          </div>

          {/* OS Type */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30 overflow-hidden">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
              OS Type
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-amber-500/20 flex items-center justify-center">
                  <Server className="w-4 h-4 text-amber-400" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.linux}</div>
                <div className="text-[10px] text-slate-500">Linux</div>
              </div>
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-blue-500/20 flex items-center justify-center">
                  <Monitor className="w-4 h-4 text-blue-400" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.windows}</div>
                <div className="text-[10px] text-slate-500">Windows</div>
              </div>
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-slate-500/20 flex items-center justify-center">
                  <Laptop className="w-4 h-4 text-slate-400" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.apple}</div>
                <div className="text-[10px] text-slate-500">Apple</div>
              </div>
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-green-500/20 flex items-center justify-center">
                  <Smartphone className="w-4 h-4 text-green-400" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.android}</div>
                <div className="text-[10px] text-slate-500">Android</div>
              </div>
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-purple-500/20 flex items-center justify-center">
                  <Terminal className="w-4 h-4 text-purple-400" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.unix}</div>
                <div className="text-[10px] text-slate-500">Unix</div>
              </div>
              <div className="text-center">
                <div className="w-8 h-8 mx-auto mb-1 rounded-lg bg-slate-600/20 flex items-center justify-center">
                  <HardDrive className="w-4 h-4 text-slate-500" />
                </div>
                <div className="text-lg font-bold text-white">{osTypeData.unknown}</div>
                <div className="text-[10px] text-slate-500">Unknown</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Action Bar */}
      <div className="flex-shrink-0 px-4 py-2 border-b border-slate-800/50 flex items-center gap-4">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button 
              variant="outline" 
              size="sm" 
              className="text-xs border-slate-600 text-slate-300"
              data-testid="button-actions"
            >
              Actions <ChevronDown className="w-3 h-3 ml-1" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent className="bg-slate-900 border-slate-700">
            <DropdownMenuLabel className="text-slate-400">Device Actions</DropdownMenuLabel>
            <DropdownMenuSeparator className="bg-slate-700" />
            <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleAction('Deploy Agent')}>
              <Shield className="w-4 h-4 mr-2" /> Deploy Agent
            </DropdownMenuItem>
            <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleAction('Isolate Device')}>
              <Network className="w-4 h-4 mr-2" /> Isolate Device
            </DropdownMenuItem>
            <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleAction('Scan')}>
              <RefreshCw className="w-4 h-4 mr-2" /> Scan Now
            </DropdownMenuItem>
            <DropdownMenuSeparator className="bg-slate-700" />
            <DropdownMenuItem className="text-red-400 focus:bg-slate-800 cursor-pointer" onSelect={() => handleAction('Remove Device')}>
              <XCircle className="w-4 h-4 mr-2" /> Remove Device
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
        
        <div className="flex items-center gap-2 text-xs text-slate-400">
          {isScanning ? (
            <>
              <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
              <span>Scanning Network...</span>
              <span className="text-cyan-400">{scanProgress}%</span>
            </>
          ) : (
            <>
              <CheckCircle2 className="w-4 h-4 text-green-400" />
              <span className="hidden sm:inline">Latest scan finished at {new Date().toLocaleString()}</span>
              <span className="sm:hidden">Scan complete</span>
            </>
          )}
        </div>
        
        <div className="ml-auto flex items-center gap-2">
          <span className="text-xs text-slate-400 hidden sm:inline">{devices.length} Items</span>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
                {resultsPerPage} Results <ChevronDown className="w-3 h-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-slate-900 border-slate-700">
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onClick={() => setResultsPerPage(10)}>10 per page</DropdownMenuItem>
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onClick={() => setResultsPerPage(20)}>20 per page</DropdownMenuItem>
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onClick={() => setResultsPerPage(50)}>50 per page</DropdownMenuItem>
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onClick={() => setResultsPerPage(100)}>100 per page</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
                Columns <ChevronDown className="w-3 h-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-slate-900 border-slate-700">
              <DropdownMenuLabel className="text-slate-400">Toggle Columns</DropdownMenuLabel>
              <DropdownMenuSeparator className="bg-slate-700" />
              <DropdownMenuCheckboxItem checked={visibleColumns.type} onCheckedChange={(c) => setVisibleColumns(v => ({...v, type: c}))} className="text-slate-300">Type</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem checked={visibleColumns.ip} onCheckedChange={(c) => setVisibleColumns(v => ({...v, ip: c}))} className="text-slate-300">IP Address</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem checked={visibleColumns.os} onCheckedChange={(c) => setVisibleColumns(v => ({...v, os: c}))} className="text-slate-300">OS</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem checked={visibleColumns.function} onCheckedChange={(c) => setVisibleColumns(v => ({...v, function: c}))} className="text-slate-300">Device Function</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem checked={visibleColumns.state} onCheckedChange={(c) => setVisibleColumns(v => ({...v, state: c}))} className="text-slate-300">Secured State</DropdownMenuCheckboxItem>
              <DropdownMenuCheckboxItem checked={visibleColumns.mac} onCheckedChange={(c) => setVisibleColumns(v => ({...v, mac: c}))} className="text-slate-300">MAC Address</DropdownMenuCheckboxItem>
            </DropdownMenuContent>
          </DropdownMenu>
          
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
                <Download className="w-4 h-4 mr-1" /> Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-slate-900 border-slate-700">
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleExport('CSV')}>
                <FileText className="w-4 h-4 mr-2" /> Export as CSV
              </DropdownMenuItem>
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleExport('JSON')}>
                <FileText className="w-4 h-4 mr-2" /> Export as JSON
              </DropdownMenuItem>
              <DropdownMenuItem className="text-slate-300 focus:bg-slate-800 cursor-pointer" onSelect={() => handleExport('PDF')}>
                <FileText className="w-4 h-4 mr-2" /> Generate PDF Report
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </div>

      {/* Data Table */}
      <div className="flex-1 overflow-auto">
        <div className="min-w-[1200px]">
          <table className="w-full text-left">
            <thead className="sticky top-0 bg-slate-900/95 backdrop-blur z-10">
              <tr className="border-b border-slate-700/50">
                <th className="px-3 py-2 w-10"></th>
                <th className="px-3 py-2 w-10">
                  <input 
                    type="checkbox" 
                    checked={selectedDevices.size === devices.length && devices.length > 0}
                    onChange={selectAllDevices}
                    className="w-4 h-4 rounded border-slate-600 bg-slate-700 text-purple-500 focus:ring-purple-500 focus:ring-offset-0"
                  />
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Type <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    IP Address <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    OS <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Device Function <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    OS Version <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Host Names <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Secured State <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    MAC Address <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Network Name <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
                <th className="px-3 py-2 text-xs font-medium text-slate-400 uppercase tracking-wider">
                  <div className="flex items-center gap-1">
                    Manufacturer <ChevronUp className="w-3 h-3" />
                  </div>
                </th>
              </tr>
            </thead>
            <tbody>
              {devices.map((device) => (
                <DeviceRow
                  key={device.id}
                  device={device}
                  isExpanded={expandedDeviceId === device.id}
                  onToggle={() => setExpandedDeviceId(
                    expandedDeviceId === device.id ? null : device.id
                  )}
                  isSelected={selectedDevices.has(device.id)}
                  onSelect={() => toggleDeviceSelection(device.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default SOCDashboard;
