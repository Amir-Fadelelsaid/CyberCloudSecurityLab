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
  onAlertSelect?: (alertId: string) => void;
  selectedAlertId?: string;
  className?: string;
}

// ============================================
// MOCK DATA GENERATORS
// ============================================

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
          
          <Button size="sm" variant="ghost" className="text-xs text-cyan-400 p-0 h-auto" onClick={(e) => e.stopPropagation()}>
            More Info
          </Button>
          
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
  onAlertSelect, 
  selectedAlertId,
  className 
}: SOCDashboardProps) {
  const [devices] = useState<Device[]>(generateDevices());
  const [expandedDeviceId, setExpandedDeviceId] = useState<string | null>(null);
  const [selectedDevices, setSelectedDevices] = useState<Set<string>>(new Set());
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [activeView, setActiveView] = useState<"devices" | "dashboard">("devices");

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
      <div className="flex-shrink-0 p-3 border-b border-slate-800/50 overflow-x-auto">
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3 min-w-[600px]">
          {/* Secured State */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30">
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
            <div className="flex justify-center gap-4 mt-3">
              <div className="flex items-center gap-1.5 text-xs">
                <div className="w-2 h-2 rounded-full bg-green-500" />
                <span className="text-slate-400">0%</span>
                <span className="text-slate-500">Secured</span>
              </div>
              <div className="flex items-center gap-1.5 text-xs">
                <div className="w-2 h-2 rounded-full bg-red-500" />
                <span className="text-slate-400">100%</span>
                <span className="text-slate-500">Unsecured</span>
              </div>
            </div>
          </div>

          {/* Device Review */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30">
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
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30">
            <div className="text-xs font-medium text-slate-400 uppercase tracking-wider mb-3">
              Devices (TOTAL: 57)
            </div>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <span className="text-slate-300">Server</span>
                <span className="ml-auto text-slate-400">45</span>
              </div>
              <div className="flex items-center gap-2">
                <Monitor className="w-4 h-4 text-purple-400" />
                <span className="text-slate-300">Workstation</span>
                <span className="ml-auto text-slate-400">11</span>
              </div>
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-slate-400" />
                <span className="text-slate-300">Unknown</span>
                <span className="ml-auto text-slate-400">1</span>
              </div>
              <div className="flex items-center gap-2">
                <Globe className="w-4 h-4 text-green-400" />
                <span className="text-slate-300">Server Infrastructure</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <Smartphone className="w-4 h-4 text-orange-400" />
                <span className="text-slate-300">Mobile</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <Monitor className="w-4 h-4 text-blue-400" />
                <span className="text-slate-300">Printer</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <Eye className="w-4 h-4 text-red-400" />
                <span className="text-slate-300">Video</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <Smartphone className="w-4 h-4 text-pink-400" />
                <span className="text-slate-300">IP Phone</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-yellow-400" />
                <span className="text-slate-300">Network</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
              <div className="flex items-center gap-2">
                <HardDrive className="w-4 h-4 text-indigo-400" />
                <span className="text-slate-300">Storage</span>
                <span className="ml-auto text-slate-400">0</span>
              </div>
            </div>
          </div>

          {/* OS Type */}
          <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-700/30">
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
        <Button 
          variant="outline" 
          size="sm" 
          className="text-xs border-slate-600 text-slate-300"
          data-testid="button-actions"
        >
          Actions <ChevronDown className="w-3 h-3 ml-1" />
        </Button>
        
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
              <span>Latest scan finished at {new Date().toLocaleString()}</span>
            </>
          )}
        </div>
        
        <div className="ml-auto flex items-center gap-3">
          <span className="text-xs text-slate-400">57 Items</span>
          <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
            20 Results <ChevronDown className="w-3 h-3 ml-1" />
          </Button>
          <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
            Columns <ChevronDown className="w-3 h-3 ml-1" />
          </Button>
          <Button variant="ghost" size="sm" className="text-xs text-cyan-400">
            <Download className="w-4 h-4 mr-1" /> Export
          </Button>
        </div>
      </div>

      {/* Data Table */}
      <div className="flex-1 overflow-hidden">
        <ScrollArea className="h-full">
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
        </ScrollArea>
      </div>
    </div>
  );
}

export default SOCDashboard;
