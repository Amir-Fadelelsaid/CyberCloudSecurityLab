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
  Globe
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
  message: string;
  details?: Record<string, string>;
}

interface NetworkEvent {
  timestamp: string;
  srcIp: string;
  destIp: string;
  port: number;
  protocol: string;
  action: "allow" | "deny" | "alert";
  bytes: number;
}

interface EndpointActivity {
  hostname: string;
  timestamp: string;
  eventType: string;
  process?: string;
  user?: string;
  status: "normal" | "suspicious" | "malicious";
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
    { timestamp: new Date(Date.now() - 30000).toISOString(), level: "error", source: "cloudtrail", message: "DeleteTrail API called by user 'unknown-admin'", details: { eventSource: "cloudtrail.amazonaws.com", userAgent: "aws-cli/2.0" } },
    { timestamp: new Date(Date.now() - 60000).toISOString(), level: "warn", source: "guardduty", message: "CryptoMining DNS request detected from i-0abc123", details: { destination: "pool.minexmr.com" } },
    { timestamp: new Date(Date.now() - 90000).toISOString(), level: "warn", source: "vpc-flow", message: "Unusual outbound traffic volume detected (2.4GB/hr)", details: { instanceId: "i-0def456" } },
    { timestamp: new Date(Date.now() - 120000).toISOString(), level: "info", source: "iam", message: "AssumeRole successful for role 'AdminAccess'", details: { sourceIp: "198.51.100.45" } },
    { timestamp: new Date(Date.now() - 150000).toISOString(), level: "info", source: "s3", message: "GetBucketAcl called on 'prod-data-bucket'", details: { requester: "arn:aws:iam::123456789012:user/dev-user" } },
    { timestamp: new Date(Date.now() - 180000).toISOString(), level: "error", source: "lambda", message: "Function 'DataExporter' timeout after 900s", details: { memoryUsed: "512MB" } },
    { timestamp: new Date(Date.now() - 210000).toISOString(), level: "debug", source: "ec2", message: "Instance i-0ghi789 health check passed" },
    { timestamp: new Date(Date.now() - 240000).toISOString(), level: "warn", source: "securityhub", message: "New HIGH severity finding: Public S3 bucket detected" }
  ];
};

const generateNetworkEvents = (): NetworkEvent[] => {
  return [
    { timestamp: new Date(Date.now() - 10000).toISOString(), srcIp: "10.0.1.50", destIp: "198.51.100.45", port: 443, protocol: "HTTPS", action: "allow", bytes: 15234 },
    { timestamp: new Date(Date.now() - 20000).toISOString(), srcIp: "198.51.100.45", destIp: "10.0.1.50", port: 22, protocol: "SSH", action: "alert", bytes: 8456 },
    { timestamp: new Date(Date.now() - 30000).toISOString(), srcIp: "10.0.2.100", destIp: "pool.minexmr.com", port: 3333, protocol: "TCP", action: "deny", bytes: 0 },
    { timestamp: new Date(Date.now() - 40000).toISOString(), srcIp: "10.0.1.25", destIp: "s3.amazonaws.com", port: 443, protocol: "HTTPS", action: "allow", bytes: 2456000 },
    { timestamp: new Date(Date.now() - 50000).toISOString(), srcIp: "203.0.113.50", destIp: "10.0.1.10", port: 3389, protocol: "RDP", action: "deny", bytes: 0 }
  ];
};

const generateEndpointActivity = (): EndpointActivity[] => {
  return [
    { hostname: "web-server-01", timestamp: new Date(Date.now() - 15000).toISOString(), eventType: "Process Start", process: "curl", user: "ec2-user", status: "suspicious" },
    { hostname: "db-server-01", timestamp: new Date(Date.now() - 45000).toISOString(), eventType: "File Access", process: "mysqldump", user: "root", status: "normal" },
    { hostname: "web-server-03", timestamp: new Date(Date.now() - 75000).toISOString(), eventType: "Network Connection", process: "xmrig", user: "www-data", status: "malicious" },
    { hostname: "app-server-02", timestamp: new Date(Date.now() - 105000).toISOString(), eventType: "Registry Modify", process: "powershell.exe", user: "SYSTEM", status: "suspicious" },
    { hostname: "bastion-01", timestamp: new Date(Date.now() - 135000).toISOString(), eventType: "User Login", user: "admin", status: "normal" }
  ];
};

const severityConfig = {
  critical: { color: "bg-red-500/20 text-red-400 border-red-500/40", icon: XCircle, priority: 1 },
  high: { color: "bg-orange-500/20 text-orange-400 border-orange-500/40", icon: AlertTriangle, priority: 2 },
  medium: { color: "bg-yellow-500/20 text-yellow-400 border-yellow-500/40", icon: AlertCircle, priority: 3 },
  low: { color: "bg-blue-500/20 text-blue-400 border-blue-500/40", icon: Info, priority: 4 },
  info: { color: "bg-slate-500/20 text-slate-400 border-slate-500/40", icon: Info, priority: 5 }
};

const statusConfig = {
  new: { color: "bg-red-500/30 text-red-300", label: "NEW" },
  investigating: { color: "bg-yellow-500/30 text-yellow-300", label: "INVESTIGATING" },
  escalated: { color: "bg-purple-500/30 text-purple-300", label: "ESCALATED" },
  resolved: { color: "bg-green-500/30 text-green-300", label: "RESOLVED" }
};

export function SOCDashboard({ labId, labCategory, onAlertSelect, selectedAlertId, className }: SOCDashboardProps) {
  const [alerts, setAlerts] = useState<SIEMAlert[]>([]);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [networkEvents, setNetworkEvents] = useState<NetworkEvent[]>([]);
  const [endpointActivity, setEndpointActivity] = useState<EndpointActivity[]>([]);
  const [activeTab, setActiveTab] = useState("alerts");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  useEffect(() => {
    setAlerts(generateMockAlerts(labId));
    setLogs(generateMockLogs());
    setNetworkEvents(generateNetworkEvents());
    setEndpointActivity(generateEndpointActivity());
  }, [labId]);

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

      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex-1 flex flex-col min-h-0">
        <TabsList className="w-full justify-start rounded-none border-b border-white/10 bg-black/20 px-2">
          <TabsTrigger value="alerts" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <AlertTriangle className="w-3 h-3" /> ALERTS
          </TabsTrigger>
          <TabsTrigger value="logs" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <FileText className="w-3 h-3" /> LOGS
          </TabsTrigger>
          <TabsTrigger value="network" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Network className="w-3 h-3" /> NETWORK
          </TabsTrigger>
          <TabsTrigger value="endpoints" className="text-[10px] font-mono gap-1 data-[state=active]:bg-primary/20 data-[state=active]:text-primary">
            <Monitor className="w-3 h-3" /> ENDPOINTS
          </TabsTrigger>
        </TabsList>

        <TabsContent value="alerts" className="flex-1 m-0 overflow-hidden">
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
          <ScrollArea className="flex-1 h-[calc(100%-2.5rem)]">
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
                        isSelected ? "bg-primary/10 border-primary/60" : "bg-black/30 border-white/10 hover:border-white/20",
                        alert.status === "new" && alert.severity === "critical" && "animate-pulse"
                      )}
                      data-testid={`alert-${alert.id}`}
                    >
                      <div className="flex items-start gap-3">
                        <div className={clsx("p-1.5 rounded", config.color)}>
                          <Icon className="w-3.5 h-3.5" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
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
                          <div className="flex items-center gap-3 mt-2 text-[9px] text-muted-foreground">
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
                        <ChevronRight className="w-4 h-4 text-muted-foreground" />
                      </div>
                    </motion.div>
                  );
                })}
              </AnimatePresence>
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="logs" className="flex-1 m-0 overflow-hidden">
          <ScrollArea className="h-full">
            <div className="p-2 font-mono text-[10px] space-y-1">
              {logs.map((log, idx) => (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: idx * 0.02 }}
                  className={clsx(
                    "p-2 rounded border-l-2",
                    log.level === "error" ? "bg-red-500/10 border-l-red-500 text-red-300" :
                    log.level === "warn" ? "bg-yellow-500/10 border-l-yellow-500 text-yellow-300" :
                    log.level === "info" ? "bg-blue-500/10 border-l-blue-500 text-blue-300" :
                    "bg-slate-500/10 border-l-slate-500 text-slate-300"
                  )}
                  data-testid={`log-${idx}`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-muted-foreground">{formatTime(log.timestamp)}</span>
                    <Badge variant="outline" className={clsx(
                      "text-[8px] px-1 py-0 uppercase",
                      log.level === "error" ? "text-red-400 border-red-400/30" :
                      log.level === "warn" ? "text-yellow-400 border-yellow-400/30" :
                      log.level === "info" ? "text-blue-400 border-blue-400/30" :
                      "text-slate-400 border-slate-400/30"
                    )}>
                      {log.level}
                    </Badge>
                    <span className="text-primary">[{log.source}]</span>
                  </div>
                  <p className="text-white/90">{log.message}</p>
                  {log.details && (
                    <div className="mt-1 text-[9px] text-muted-foreground">
                      {Object.entries(log.details).map(([k, v]) => (
                        <span key={k} className="mr-3">{k}=<span className="text-cyan-400">{v}</span></span>
                      ))}
                    </div>
                  )}
                </motion.div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>

        <TabsContent value="network" className="flex-1 m-0 overflow-hidden">
          <ScrollArea className="h-full">
            <div className="p-2">
              <table className="w-full text-[10px] font-mono">
                <thead>
                  <tr className="text-muted-foreground border-b border-white/10">
                    <th className="text-left py-2 px-2">TIME</th>
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
                      <td className="py-2 px-2 text-cyan-400">{event.srcIp}</td>
                      <td className="py-2 px-2 text-purple-400">{event.destIp}</td>
                      <td className="py-2 px-2 text-white">{event.port}</td>
                      <td className="py-2 px-2 text-muted-foreground">{event.protocol}</td>
                      <td className="py-2 px-2">
                        <Badge className={clsx(
                          "text-[8px] px-1.5 py-0",
                          event.action === "allow" ? "bg-green-500/20 text-green-400" :
                          event.action === "deny" ? "bg-red-500/20 text-red-400" :
                          "bg-yellow-500/20 text-yellow-400"
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

        <TabsContent value="endpoints" className="flex-1 m-0 overflow-hidden">
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
                    activity.status === "malicious" ? "bg-red-500/10 border-red-500/30" :
                    activity.status === "suspicious" ? "bg-yellow-500/10 border-yellow-500/30" :
                    "bg-black/30 border-white/10"
                  )}
                  data-testid={`endpoint-${idx}`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Monitor className={clsx(
                        "w-4 h-4",
                        activity.status === "malicious" ? "text-red-400" :
                        activity.status === "suspicious" ? "text-yellow-400" :
                        "text-primary"
                      )} />
                      <span className="text-xs font-bold text-white">{activity.hostname}</span>
                    </div>
                    <Badge className={clsx(
                      "text-[8px]",
                      activity.status === "malicious" ? "bg-red-500/20 text-red-400" :
                      activity.status === "suspicious" ? "bg-yellow-500/20 text-yellow-400" :
                      "bg-green-500/20 text-green-400"
                    )}>
                      {activity.status.toUpperCase()}
                    </Badge>
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
                          activity.status === "malicious" ? "text-red-400" : "text-cyan-400"
                        )}>{activity.process}</span>
                      </div>
                    )}
                    {activity.user && (
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground">User:</span>
                        <span className="text-purple-400">{activity.user}</span>
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
      </Tabs>
    </div>
  );
}
