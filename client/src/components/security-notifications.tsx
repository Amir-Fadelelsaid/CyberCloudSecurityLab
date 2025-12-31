import { useState, useEffect, useCallback, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { 
  AlertTriangle, 
  Shield, 
  Bell, 
  X, 
  AlertCircle, 
  Eye, 
  Lock, 
  Unlock,
  Server,
  Database,
  Network,
  Key,
  FileWarning,
  ShieldAlert,
  ShieldCheck,
  Zap,
  CheckCircle2
} from "lucide-react";
import { clsx } from "clsx";
import { Button } from "@/components/ui/button";

interface NotificationTemplate {
  id: string;
  type: "critical" | "warning" | "info" | "success";
  title: string;
  message: string;
  icon: typeof AlertTriangle;
  source?: string;
}

interface SecurityNotification extends NotificationTemplate {
  timestamp: Date;
  acknowledged: boolean;
}

export interface AlertInvestigation {
  id: string;
  title: string;
  message: string;
  type: "critical" | "warning" | "info" | "success";
  commands: string[];
}

interface SecurityNotificationsProps {
  labTitle: string;
  labCategory: string;
  isActive: boolean;
  onInvestigate?: (alert: AlertInvestigation) => void;
}

const CATEGORY_NOTIFICATIONS: Record<string, NotificationTemplate[]> = {
  "Storage Security": [
    { id: "1", type: "critical", title: "Data Exfiltration Detected", message: "Unusual S3 bucket download pattern from unknown IP", icon: Database, source: "CloudTrail" },
    { id: "2", type: "warning", title: "Public Access Warning", message: "S3 bucket policy allows public read access", icon: Unlock, source: "AWS Config" },
    { id: "3", type: "info", title: "Access Logging Enabled", message: "Server access logging activated for audit trail", icon: Eye, source: "S3 Events" },
    { id: "4", type: "critical", title: "Encryption Disabled", message: "Object uploaded without server-side encryption", icon: Lock, source: "S3 Events" },
    { id: "5", type: "warning", title: "Cross-Account Access", message: "Bucket accessed from external AWS account", icon: Key, source: "CloudTrail" },
  ],
  "Network Security": [
    { id: "1", type: "critical", title: "Port Scan Detected", message: "Sequential port scanning from 203.0.113.42", icon: Network, source: "VPC Flow Logs" },
    { id: "2", type: "warning", title: "Security Group Modified", message: "Inbound rule added allowing 0.0.0.0/0 on port 22", icon: ShieldAlert, source: "CloudTrail" },
    { id: "3", type: "critical", title: "DDoS Attack Pattern", message: "Abnormal traffic spike detected on public endpoints", icon: Zap, source: "AWS Shield" },
    { id: "4", type: "info", title: "NACL Updated", message: "Network ACL rules modified for subnet isolation", icon: Shield, source: "VPC Events" },
    { id: "5", type: "warning", title: "Unencrypted Traffic", message: "HTTP traffic detected on production load balancer", icon: Unlock, source: "ALB Logs" },
  ],
  "SOC Operations": [
    { id: "1", type: "critical", title: "Malware Signature Match", message: "Known ransomware behavior detected on endpoint", icon: FileWarning, source: "EDR" },
    { id: "2", type: "warning", title: "Suspicious Process", message: "PowerShell executing encoded commands", icon: AlertTriangle, source: "SIEM" },
    { id: "3", type: "critical", title: "Credential Dumping", message: "LSASS memory access attempt detected", icon: Key, source: "EDR" },
    { id: "4", type: "info", title: "Threat Intel Update", message: "New IOCs added from threat feed", icon: Shield, source: "TIP" },
    { id: "5", type: "warning", title: "Lateral Movement", message: "RDP connection to multiple hosts in sequence", icon: Network, source: "SIEM" },
  ],
  "SOC Engineer": [
    { id: "1", type: "critical", title: "SIEM Alert Triggered", message: "Correlation rule matched for brute force attack", icon: AlertCircle, source: "Splunk" },
    { id: "2", type: "warning", title: "Log Source Offline", message: "Firewall log ingestion stopped 15 minutes ago", icon: Server, source: "SIEM" },
    { id: "3", type: "info", title: "New Detection Rule", message: "MITRE ATT&CK T1566 detection rule deployed", icon: Shield, source: "Detection Engine" },
    { id: "4", type: "critical", title: "High Severity Incident", message: "Data exfiltration indicators across multiple systems", icon: ShieldAlert, source: "SOAR" },
    { id: "5", type: "warning", title: "Alert Fatigue Risk", message: "500+ low-priority alerts in queue", icon: Bell, source: "SIEM" },
  ],
  "Cloud Security Analyst": [
    { id: "1", type: "critical", title: "Privilege Escalation", message: "IAM user assumed admin role unexpectedly", icon: Key, source: "GuardDuty" },
    { id: "2", type: "warning", title: "Unusual API Activity", message: "First-time API call from new region", icon: AlertTriangle, source: "CloudTrail" },
    { id: "3", type: "critical", title: "Instance Compromise", message: "EC2 instance communicating with known C2 server", icon: Server, source: "GuardDuty" },
    { id: "4", type: "info", title: "Compliance Scan Complete", message: "AWS Config rules evaluation finished", icon: ShieldCheck, source: "AWS Config" },
    { id: "5", type: "warning", title: "Exposed Credentials", message: "Access key detected in public repository", icon: Unlock, source: "Secrets Manager" },
  ],
  "IAM Security": [
    { id: "1", type: "critical", title: "Root Account Login", message: "AWS root user console login detected", icon: Key, source: "CloudTrail" },
    { id: "2", type: "warning", title: "Excessive Permissions", message: "New policy grants admin access to all resources", icon: ShieldAlert, source: "IAM Access Analyzer" },
    { id: "3", type: "critical", title: "MFA Not Enabled", message: "Privileged user account lacks MFA protection", icon: Lock, source: "IAM" },
    { id: "4", type: "info", title: "Access Key Rotated", message: "Service account credentials successfully rotated", icon: Key, source: "Secrets Manager" },
    { id: "5", type: "warning", title: "Stale Credentials", message: "Access key unused for 90+ days detected", icon: AlertTriangle, source: "IAM" },
  ],
  "Cloud Security Engineer": [
    { id: "1", type: "critical", title: "Infrastructure Drift", message: "Terraform state mismatch detected in production", icon: Server, source: "IaC Scanner" },
    { id: "2", type: "warning", title: "Vulnerable AMI", message: "EC2 instance running outdated base image", icon: AlertTriangle, source: "Inspector" },
    { id: "3", type: "critical", title: "Secret in Code", message: "Hardcoded credentials found in Lambda function", icon: FileWarning, source: "CodeGuru" },
    { id: "4", type: "info", title: "Security Patch Available", message: "Critical CVE fix ready for deployment", icon: Shield, source: "Patch Manager" },
    { id: "5", type: "warning", title: "Untagged Resources", message: "15 resources missing required security tags", icon: Database, source: "AWS Config" },
  ],
};

const DEFAULT_NOTIFICATIONS: NotificationTemplate[] = [
  { id: "1", type: "warning", title: "Security Event", message: "Anomalous activity detected in environment", icon: AlertTriangle, source: "SIEM" },
  { id: "2", type: "info", title: "Monitoring Active", message: "Security sensors operational", icon: Eye, source: "SOC" },
  { id: "3", type: "critical", title: "Alert Triggered", message: "High-priority security event requires attention", icon: AlertCircle, source: "Detection Engine" },
];

const ALERT_COMMANDS: Record<string, string[]> = {
  "Data Exfiltration Detected": [
    "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject",
    "aws s3api get-bucket-logging --bucket corp-data-bucket",
    "aws s3api put-public-access-block --bucket corp-data-bucket --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true"
  ],
  "Public Access Warning": [
    "aws s3api get-bucket-policy --bucket vulnerable-bucket",
    "aws s3api get-public-access-block --bucket vulnerable-bucket",
    "aws s3api put-bucket-policy --bucket vulnerable-bucket --policy file://secure-policy.json"
  ],
  "Encryption Disabled": [
    "aws s3api get-bucket-encryption --bucket data-bucket",
    "aws s3api put-bucket-encryption --bucket data-bucket --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
  ],
  "Port Scan Detected": [
    "aws ec2 describe-flow-logs --filter Name=resource-id,Values=vpc-12345",
    "aws ec2 describe-security-groups --group-ids sg-vulnerable",
    "aws ec2 revoke-security-group-ingress --group-id sg-vulnerable --protocol tcp --port 22 --cidr 0.0.0.0/0"
  ],
  "Security Group Modified": [
    "aws ec2 describe-security-groups --group-ids sg-modified",
    "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress",
    "aws ec2 revoke-security-group-ingress --group-id sg-modified --protocol tcp --port 22 --cidr 0.0.0.0/0"
  ],
  "DDoS Attack Pattern": [
    "aws shield describe-attack --attack-id attack-123",
    "aws wafv2 get-web-acl --name production-waf --scope REGIONAL",
    "aws shield create-protection --name WebApp --resource-arn arn:aws:elasticloadbalancing:..."
  ],
  "Malware Signature Match": [
    "aws guardduty get-findings --detector-id detector-123 --finding-ids finding-456",
    "aws ec2 describe-instances --instance-ids i-infected",
    "aws ec2 stop-instances --instance-ids i-infected"
  ],
  "Credential Dumping": [
    "aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=GetSecretValue",
    "aws iam list-access-keys --user-name compromised-user",
    "aws iam update-access-key --user-name compromised-user --access-key-id AKIA... --status Inactive"
  ],
  "Privilege Escalation": [
    "aws iam get-user --user-name suspicious-user",
    "aws iam list-attached-user-policies --user-name suspicious-user",
    "aws iam detach-user-policy --user-name suspicious-user --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
  ],
  "Root Account Login": [
    "aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=root",
    "aws iam create-virtual-mfa-device --virtual-mfa-device-name root-mfa",
    "aws iam enable-mfa-device --user-name root --serial-number arn:aws:iam::account:mfa/root-mfa"
  ],
  "MFA Not Enabled": [
    "aws iam list-users",
    "aws iam list-mfa-devices --user-name admin-user",
    "aws iam create-virtual-mfa-device --virtual-mfa-device-name admin-mfa"
  ],
  "Infrastructure Drift": [
    "terraform plan -detailed-exitcode",
    "terraform refresh",
    "terraform apply -auto-approve"
  ],
  "Secret in Code": [
    "aws secretsmanager list-secrets",
    "aws lambda get-function --function-name vulnerable-function",
    "aws lambda update-function-configuration --function-name vulnerable-function --environment Variables={}"
  ],
  "default": [
    "aws cloudtrail lookup-events --max-results 10",
    "aws guardduty list-findings --detector-id detector-123",
    "aws iam get-account-summary"
  ]
};

export function SecurityNotifications({ labTitle, labCategory, isActive, onInvestigate }: SecurityNotificationsProps) {
  const [notifications, setNotifications] = useState<SecurityNotification[]>([]);
  const [isMinimized, setIsMinimized] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const seenTemplateIds = useRef<Set<string>>(new Set());
  const hasInitialized = useRef(false);

  const categoryNotifications = CATEGORY_NOTIFICATIONS[labCategory] || DEFAULT_NOTIFICATIONS;

  const addNotification = useCallback(() => {
    const availableTemplates = categoryNotifications.filter(
      t => !seenTemplateIds.current.has(t.id)
    );
    
    if (availableTemplates.length === 0) {
      seenTemplateIds.current.clear();
      return;
    }
    
    const template = availableTemplates[Math.floor(Math.random() * availableTemplates.length)];
    seenTemplateIds.current.add(template.id);
    
    const newNotification: SecurityNotification = {
      ...template,
      id: `${template.id}-${Date.now()}`,
      timestamp: new Date(),
      acknowledged: false,
    };
    
    setNotifications(prev => [newNotification, ...prev].slice(0, 5));
    setUnreadCount(prev => prev + 1);
  }, [categoryNotifications]);

  const dismissNotification = (id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  };

  const investigateNotification = (notification: SecurityNotification) => {
    setNotifications(prev => prev.map(n => 
      n.id === notification.id ? { ...n, acknowledged: true } : n
    ));
    
    const commands = ALERT_COMMANDS[notification.title] || ALERT_COMMANDS["default"];
    
    if (onInvestigate) {
      onInvestigate({
        id: notification.id,
        title: notification.title,
        message: notification.message,
        type: notification.type,
        commands
      });
    }
    
    setIsMinimized(true);
  };

  const clearAll = () => {
    setNotifications([]);
    setUnreadCount(0);
    seenTemplateIds.current.clear();
  };

  useEffect(() => {
    if (!isActive) return;

    let initialTimeout: ReturnType<typeof setTimeout> | null = null;
    
    if (!hasInitialized.current) {
      initialTimeout = setTimeout(() => {
        addNotification();
        hasInitialized.current = true;
      }, 2000);
    }

    const interval = setInterval(() => {
      if (Math.random() > 0.4) {
        addNotification();
      }
    }, 12000);

    return () => {
      if (initialTimeout) clearTimeout(initialTimeout);
      clearInterval(interval);
    };
  }, [isActive, addNotification]);

  useEffect(() => {
    if (!isMinimized) {
      setUnreadCount(0);
    }
  }, [isMinimized]);

  const typeConfig = {
    critical: {
      bg: "bg-red-950/90",
      border: "border-red-500/50",
      icon: "text-red-400",
      pulse: "animate-pulse",
    },
    warning: {
      bg: "bg-amber-950/90",
      border: "border-amber-500/50",
      icon: "text-amber-400",
      pulse: "",
    },
    info: {
      bg: "bg-cyan-950/90",
      border: "border-cyan-500/50",
      icon: "text-cyan-400",
      pulse: "",
    },
    success: {
      bg: "bg-green-950/90",
      border: "border-green-500/50",
      icon: "text-green-400",
      pulse: "",
    },
  };

  return (
    <div className="fixed bottom-4 right-4 z-50" data-testid="security-notifications">
      <AnimatePresence>
        {isMinimized ? (
          <motion.button
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0 }}
            onClick={() => setIsMinimized(false)}
            className={clsx(
              "relative p-3 rounded-full bg-slate-900/95 border border-primary/50 backdrop-blur-sm",
              "hover:border-primary hover:bg-slate-800/95 transition-colors"
            )}
            data-testid="button-expand-notifications"
          >
            <Bell className="w-5 h-5 text-primary" />
            {unreadCount > 0 && (
              <motion.span
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                className="absolute -top-1 -right-1 w-5 h-5 bg-red-500 rounded-full text-[10px] font-bold text-white flex items-center justify-center"
              >
                {unreadCount > 9 ? "9+" : unreadCount}
              </motion.span>
            )}
          </motion.button>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            className="w-80 bg-slate-900/95 border border-slate-700/50 rounded-lg backdrop-blur-sm overflow-hidden"
          >
            <div className="flex items-center justify-between px-3 py-2 bg-slate-800/80 border-b border-slate-700/50">
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Shield className="w-4 h-4 text-primary" />
                  {notifications.some(n => n.type === "critical") && (
                    <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-red-500 rounded-full animate-pulse" />
                  )}
                </div>
                <span className="text-xs font-semibold text-white">Security Events</span>
                <span className="text-[10px] text-slate-400">LIVE</span>
              </div>
              <div className="flex items-center gap-1">
                {notifications.length > 0 && (
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 px-2 text-[10px] text-slate-400"
                    onClick={clearAll}
                    data-testid="button-clear-notifications"
                  >
                    Clear All
                  </Button>
                )}
                <button
                  onClick={() => setIsMinimized(true)}
                  className="p-1 hover:bg-slate-700 rounded transition-colors"
                  data-testid="button-minimize-notifications"
                >
                  <X className="w-3 h-3 text-slate-400" />
                </button>
              </div>
            </div>

            <div className="max-h-64 overflow-y-auto">
              <AnimatePresence>
                {notifications.length === 0 ? (
                  <div className="p-4 text-center">
                    <Eye className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                    <p className="text-xs text-slate-500">Monitoring for security events...</p>
                  </div>
                ) : (
                  notifications.map((notification, index) => {
                    const config = typeConfig[notification.type];
                    const IconComponent = notification.icon;
                    
                    return (
                      <motion.div
                        key={notification.id}
                        initial={{ opacity: 0, x: 50, height: 0 }}
                        animate={{ opacity: 1, x: 0, height: "auto" }}
                        exit={{ opacity: 0, x: -50, height: 0 }}
                        transition={{ delay: index * 0.05 }}
                        className={clsx(
                          "p-3 border-b border-slate-700/30",
                          config.bg,
                          "relative group"
                        )}
                        data-testid={`notification-${notification.id}`}
                      >
                        <div className={clsx("absolute left-0 top-0 bottom-0 w-1", config.border.replace("border-", "bg-").replace("/50", ""))} />
                        
                        <div className="flex items-start gap-2 pl-2">
                          <IconComponent className={clsx("w-4 h-4 mt-0.5 flex-shrink-0", config.icon, config.pulse)} />
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-xs font-semibold text-white truncate">{notification.title}</span>
                              <button
                                onClick={() => dismissNotification(notification.id)}
                                className="opacity-0 group-hover:opacity-100 transition-opacity p-0.5 hover:bg-slate-700 rounded"
                                data-testid={`button-dismiss-${notification.id}`}
                              >
                                <X className="w-3 h-3 text-slate-400" />
                              </button>
                            </div>
                            <p className="text-[11px] text-slate-300 mt-0.5 line-clamp-2">{notification.message}</p>
                            <div className="flex items-center justify-between mt-1.5">
                              {notification.source && (
                                <span className="text-[10px] text-slate-500">{notification.source}</span>
                              )}
                              <span className="text-[10px] text-slate-500">
                                {notification.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                              </span>
                            </div>
                            <div className="flex items-center gap-1 mt-2">
                              {notification.acknowledged ? (
                                <span className="text-[10px] text-green-400 flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" />
                                  Investigating
                                </span>
                              ) : (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-5 px-2 text-[10px] text-cyan-400 hover:text-cyan-300"
                                  onClick={(e) => { e.stopPropagation(); investigateNotification(notification); }}
                                  data-testid={`button-investigate-${notification.id}`}
                                >
                                  Investigate
                                </Button>
                              )}
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-5 px-2 text-[10px] text-slate-400 hover:text-white"
                                onClick={(e) => { e.stopPropagation(); dismissNotification(notification.id); }}
                                data-testid={`button-dismiss-${notification.id}`}
                              >
                                Dismiss
                              </Button>
                            </div>
                          </div>
                        </div>
                      </motion.div>
                    );
                  })
                )}
              </AnimatePresence>
            </div>

            <div className="px-3 py-2 bg-slate-800/50 border-t border-slate-700/30">
              <div className="flex items-center justify-between text-[10px]">
                <span className="text-slate-500">Threat Feed: Active</span>
                <span className="text-primary font-mono">{notifications.length} events</span>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export default SecurityNotifications;
