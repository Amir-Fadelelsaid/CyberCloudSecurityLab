import { useLabResources } from "@/hooks/use-labs";
import { Users, Key, Shield, GitBranch, AlertTriangle, CheckCircle2, UserCheck, Settings, Lock, Unlock, Link2, UserX } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";
import { type Resource } from "@shared/schema";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";

interface IdentityGraphProps {
  labId: number;
  labTitle?: string;
}

// Lab-specific context messages based on lab title
const getIAMLabContext = (labTitle: string): { message: string; severity: 'critical' | 'high' | 'medium' } | null => {
  const contextMap: Record<string, { message: string; severity: 'critical' | 'high' | 'medium' }> = {
    "IAM User Without MFA": { message: "CRITICAL: Admin user lacks multi-factor authentication", severity: 'critical' },
    "Overprivileged IAM Role": { message: "HIGH RISK: EC2 role has AdministratorAccess policy", severity: 'critical' },
    "Stale Access Keys": { message: "COMPLIANCE: Access keys unused for 180+ days detected", severity: 'high' },
    "Wildcard IAM Policy": { message: "CRITICAL: Policy grants Action: *, Resource: * permissions", severity: 'critical' },
    "Cross-Account Role Trust": { message: "SUSPICIOUS: Role trusts unknown external AWS account", severity: 'high' },
    "IAM Group Membership Audit": { message: "AUDIT: Reviewing group permissions and membership", severity: 'medium' },
    "Service Account Key Rotation": { message: "COMPLIANCE: Service account keys exceed rotation policy", severity: 'high' },
    "Permission Boundary Bypass": { message: "VULNERABILITY: User can escalate beyond permission boundary", severity: 'critical' },
    "Identity Provider Configuration": { message: "REVIEW: SAML/OIDC identity provider settings", severity: 'medium' },
    "Root Account Usage Detection": { message: "ALERT: Root account API activity detected", severity: 'critical' },
    "IAM Policy Simulator": { message: "ANALYSIS: Evaluating effective permissions", severity: 'medium' },
    "Privilege Escalation Path": { message: "THREAT: Potential privilege escalation chain identified", severity: 'critical' },
    "Identity Graph Analysis Challenge": { message: "CHALLENGE: Map the complete identity attack surface", severity: 'high' },
  };
  return contextMap[labTitle] || null;
};

interface IdentityNode {
  id: number;
  type: string;
  name: string;
  config: Record<string, any>;
  isVulnerable: boolean;
  status: string;
  category: 'user' | 'service' | 'role' | 'group' | 'provider' | 'policy';
}

export function IdentityGraph({ labId, labTitle = "" }: IdentityGraphProps) {
  const { data: resources, isLoading } = useLabResources(labId);
  const [selectedNode, setSelectedNode] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<'grid' | 'relationships'>('relationships');
  const labContext = getIAMLabContext(labTitle);

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-3">
        <motion.div
          className="w-12 h-12 border-2 border-primary/30 border-t-primary rounded-full"
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        />
        <span className="text-xs font-mono animate-pulse">Mapping identity ecosystem...</span>
      </div>
    );
  }

  if (!resources?.length) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-2">
        <Users className="w-10 h-10 opacity-30" />
        <span className="text-sm">No identity resources detected</span>
      </div>
    );
  }

  const categorizeResource = (resource: Resource): IdentityNode['category'] => {
    const type = resource.type;
    if (type.includes('user') || type === 'iam_user') return 'user';
    if (type.includes('service_account')) return 'service';
    if (type.includes('role') || type === 'iam_role') return 'role';
    if (type.includes('group') || type === 'iam_group') return 'group';
    if (type.includes('provider') || type === 'identity_provider') return 'provider';
    if (type.includes('policy') || type === 'permission_boundary') return 'policy';
    return 'role';
  };

  const nodes: IdentityNode[] = resources.map(r => ({
    id: r.id,
    type: r.type,
    name: r.name,
    config: r.config as Record<string, any>,
    isVulnerable: r.isVulnerable ?? false,
    status: r.status ?? 'unknown',
    category: categorizeResource(r)
  }));

  const vulnerableCount = nodes.filter(n => n.isVulnerable).length;
  const secureCount = nodes.length - vulnerableCount;

  const userNodes = nodes.filter(n => n.category === 'user');
  const serviceNodes = nodes.filter(n => n.category === 'service');
  const roleNodes = nodes.filter(n => n.category === 'role');
  const groupNodes = nodes.filter(n => n.category === 'group');
  const providerNodes = nodes.filter(n => n.category === 'provider');
  const policyNodes = nodes.filter(n => n.category === 'policy');

  const getSeverityStyles = (severity: 'critical' | 'high' | 'medium') => {
    switch (severity) {
      case 'critical': return 'bg-destructive/10 border-destructive/30 text-destructive';
      case 'high': return 'bg-amber-500/10 border-amber-500/30 text-amber-500';
      case 'medium': return 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400';
    }
  };

  return (
    <div className="space-y-4">
      {/* Lab Context Alert */}
      {labContext && (
        <motion.div 
          className={clsx("flex items-center gap-3 border rounded-lg px-4 py-2", getSeverityStyles(labContext.severity))}
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          <span className="text-xs font-mono">{labContext.message}</span>
        </motion.div>
      )}
      
      <div className="flex items-center justify-between bg-black/30 rounded-lg px-4 py-2 border border-white/5">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
            <span className="text-xs font-mono text-destructive">{vulnerableCount} At Risk</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-primary" />
            <span className="text-xs font-mono text-primary">{secureCount} Compliant</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setViewMode('relationships')}
            className={clsx(
              "text-[10px] font-mono px-2 py-1 rounded transition-colors",
              viewMode === 'relationships' ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"
            )}
            data-testid="button-view-relationships"
          >
            Relationships
          </button>
          <button
            onClick={() => setViewMode('grid')}
            className={clsx(
              "text-[10px] font-mono px-2 py-1 rounded transition-colors",
              viewMode === 'grid' ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"
            )}
            data-testid="button-view-grid"
          >
            Grid
          </button>
        </div>
      </div>

      {viewMode === 'relationships' ? (
        <div className="space-y-4">
          {providerNodes.length > 0 && (
            <IdentityLayer title="Identity Provider" icon={Key} nodes={providerNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
          )}
          
          <div className="flex items-center justify-center gap-2 py-1">
            <div className="h-px flex-1 bg-border/50" />
            <GitBranch className="w-3 h-3 text-muted-foreground" />
            <span className="text-[10px] text-muted-foreground font-mono">Federation / Trust</span>
            <GitBranch className="w-3 h-3 text-muted-foreground rotate-180" />
            <div className="h-px flex-1 bg-border/50" />
          </div>

          {groupNodes.length > 0 && (
            <IdentityLayer title="Groups" icon={Users} nodes={groupNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
          )}

          <div className="grid grid-cols-2 gap-4">
            {userNodes.length > 0 && (
              <IdentityLayer title="Human Users" icon={UserCheck} nodes={userNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
            )}
            {serviceNodes.length > 0 && (
              <IdentityLayer title="Service Accounts" icon={Settings} nodes={serviceNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
            )}
          </div>

          <div className="flex items-center justify-center gap-2 py-1">
            <div className="h-px flex-1 bg-border/50" />
            <Link2 className="w-3 h-3 text-muted-foreground" />
            <span className="text-[10px] text-muted-foreground font-mono">Role Assumption</span>
            <Link2 className="w-3 h-3 text-muted-foreground" />
            <div className="h-px flex-1 bg-border/50" />
          </div>

          {roleNodes.length > 0 && (
            <IdentityLayer title="IAM Roles" icon={Shield} nodes={roleNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
          )}

          {policyNodes.length > 0 && (
            <IdentityLayer title="Permission Boundaries" icon={Lock} nodes={policyNodes} selectedNode={selectedNode} onSelect={setSelectedNode} />
          )}
        </div>
      ) : (
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
          <AnimatePresence mode="popLayout">
            {nodes.map((node) => (
              <IdentityCard
                key={node.id}
                node={node}
                isSelected={selectedNode === node.id}
                onSelect={() => setSelectedNode(selectedNode === node.id ? null : node.id)}
              />
            ))}
          </AnimatePresence>
        </div>
      )}

      {selectedNode && (
        <IdentityDetails node={nodes.find(n => n.id === selectedNode)!} onClose={() => setSelectedNode(null)} />
      )}
    </div>
  );
}

interface IdentityLayerProps {
  title: string;
  icon: React.ElementType;
  nodes: IdentityNode[];
  selectedNode: number | null;
  onSelect: (id: number | null) => void;
}

function IdentityLayer({ title, icon: Icon, nodes, selectedNode, onSelect }: IdentityLayerProps) {
  const vulnerableCount = nodes.filter(n => n.isVulnerable).length;

  return (
    <div className="bg-black/20 rounded-lg border border-white/5 p-3">
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-4 h-4 text-muted-foreground" />
        <span className="text-xs font-mono text-muted-foreground">{title}</span>
        {vulnerableCount > 0 && (
          <Badge variant="destructive" className="text-[9px] px-1.5 py-0">
            {vulnerableCount} issues
          </Badge>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        {nodes.map(node => (
          <IdentityChip
            key={node.id}
            node={node}
            isSelected={selectedNode === node.id}
            onSelect={() => onSelect(selectedNode === node.id ? null : node.id)}
          />
        ))}
      </div>
    </div>
  );
}

interface IdentityChipProps {
  node: IdentityNode;
  isSelected: boolean;
  onSelect: () => void;
}

function IdentityChip({ node, isSelected, onSelect }: IdentityChipProps) {
  const getCategoryIcon = () => {
    switch (node.category) {
      case 'user': return UserCheck;
      case 'service': return Settings;
      case 'role': return Shield;
      case 'group': return Users;
      case 'provider': return Key;
      case 'policy': return Lock;
      default: return Shield;
    }
  };

  const Icon = getCategoryIcon();

  return (
    <motion.button
      onClick={onSelect}
      className={clsx(
        "flex items-center gap-1.5 px-2 py-1 rounded-md border text-xs font-mono transition-all",
        node.isVulnerable
          ? "bg-destructive/10 border-destructive/30 text-destructive hover:border-destructive/60"
          : "bg-primary/10 border-primary/30 text-primary hover:border-primary/60",
        isSelected && "ring-2 ring-offset-1 ring-offset-background",
        isSelected && (node.isVulnerable ? "ring-destructive" : "ring-primary")
      )}
      whileHover={{ scale: 1.02 }}
      whileTap={{ scale: 0.98 }}
      data-testid={`identity-chip-${node.name}`}
    >
      <Icon className="w-3 h-3" />
      <span className="truncate max-w-[120px]">{node.name}</span>
      {node.isVulnerable ? (
        <AlertTriangle className="w-3 h-3" />
      ) : (
        <CheckCircle2 className="w-3 h-3" />
      )}
    </motion.button>
  );
}

interface IdentityCardProps {
  node: IdentityNode;
  isSelected: boolean;
  onSelect: () => void;
}

function IdentityCard({ node, isSelected, onSelect }: IdentityCardProps) {
  const getCategoryIcon = () => {
    switch (node.category) {
      case 'user': return UserCheck;
      case 'service': return Settings;
      case 'role': return Shield;
      case 'group': return Users;
      case 'provider': return Key;
      case 'policy': return Lock;
      default: return Shield;
    }
  };

  const getCategoryLabel = () => {
    switch (node.category) {
      case 'user': return 'IAM User';
      case 'service': return 'Service Account';
      case 'role': return 'IAM Role';
      case 'group': return 'IAM Group';
      case 'provider': return 'Identity Provider';
      case 'policy': return 'Permission Boundary';
      default: return node.type;
    }
  };

  const getVulnerabilityHint = () => {
    if (!node.isVulnerable) return null;
    const config = node.config;
    
    if (node.status === 'escalation-path') return "Privilege escalation path detected";
    if (node.status === 'wildcard-trust') return "Wildcard trust policy - any account can assume";
    if (node.status === 'no-conditions') return "No conditional access configured";
    if (node.status === 'overly-permissive') return "Overly broad permissions";
    if (node.status === 'unused-credentials') return "Stale credentials - potential backdoor";
    if (node.status === 'stale-contractor') return "Expired contractor access";
    if (node.status === 'direct-policy-attached') return "Direct policies should use groups";
    if (node.status === 'no-mfa') return "MFA not enforced";
    if (node.status === 'not-implemented') return "Security control missing";
    
    return "Security misconfiguration detected";
  };

  const Icon = getCategoryIcon();

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
      onClick={onSelect}
      className={clsx(
        "relative overflow-visible rounded-lg border cursor-pointer transition-all duration-200",
        node.isVulnerable
          ? "bg-gradient-to-br from-destructive/10 to-destructive/5 border-destructive/30 hover:border-destructive/60"
          : "bg-gradient-to-br from-primary/10 to-primary/5 border-primary/30 hover:border-primary/60",
        isSelected && "ring-2 ring-offset-2 ring-offset-background",
        isSelected && (node.isVulnerable ? "ring-destructive" : "ring-primary")
      )}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.98 }}
      data-testid={`identity-card-${node.id}`}
    >
      {node.isVulnerable && (
        <motion.div
          className="absolute inset-0 bg-destructive/10 rounded-lg"
          animate={{ opacity: [0, 0.3, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
      )}

      <div className="p-3 relative z-10">
        <div className="flex items-start justify-between mb-2">
          <div className={clsx(
            "p-1.5 rounded-md",
            node.isVulnerable ? "bg-destructive/20 text-destructive" : "bg-primary/20 text-primary"
          )}>
            <Icon className="w-4 h-4" />
          </div>
          
          {node.isVulnerable ? (
            <motion.div
              className="flex items-center gap-1 text-[9px] font-mono font-bold text-destructive bg-destructive/20 px-1.5 py-0.5 rounded"
              animate={{ scale: [1, 1.05, 1] }}
              transition={{ duration: 1, repeat: Infinity }}
            >
              <AlertTriangle className="w-2.5 h-2.5" />
              <span>RISK</span>
            </motion.div>
          ) : (
            <div className="flex items-center gap-1 text-[9px] font-mono text-primary bg-primary/20 px-1.5 py-0.5 rounded">
              <CheckCircle2 className="w-2.5 h-2.5" />
              <span>OK</span>
            </div>
          )}
        </div>

        <h4 className="font-mono text-sm font-medium text-foreground truncate mb-1">
          {node.name}
        </h4>
        <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">
          {getCategoryLabel()}
        </p>

        {node.isVulnerable && (
          <div className="mt-2 pt-2 border-t border-destructive/20">
            <p className="text-[10px] text-destructive/80 flex items-center gap-1">
              <AlertTriangle className="w-2.5 h-2.5 flex-shrink-0" />
              <span className="truncate">{getVulnerabilityHint()}</span>
            </p>
          </div>
        )}
      </div>
    </motion.div>
  );
}

interface IdentityDetailsProps {
  node: IdentityNode;
  onClose: () => void;
}

function IdentityDetails({ node, onClose }: IdentityDetailsProps) {
  const config = node.config;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: 10 }}
      className={clsx(
        "rounded-lg border p-4",
        node.isVulnerable ? "bg-destructive/5 border-destructive/30" : "bg-primary/5 border-primary/30"
      )}
    >
      <div className="flex items-center justify-between mb-3">
        <h3 className="font-mono text-sm font-semibold">{node.name}</h3>
        <button
          onClick={onClose}
          className="text-xs text-muted-foreground hover:text-foreground"
          data-testid="button-close-details"
        >
          Close
        </button>
      </div>

      <div className="grid grid-cols-2 gap-3 text-xs font-mono">
        <div>
          <span className="text-muted-foreground">Type:</span>
          <span className="ml-2 text-foreground">{node.type}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Status:</span>
          <span className={clsx("ml-2", node.isVulnerable ? "text-destructive" : "text-primary")}>
            {node.status}
          </span>
        </div>
        
        {config.permissions && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Permissions:</span>
            <span className="ml-2 text-foreground">
              {Array.isArray(config.permissions) ? config.permissions.join(', ') : config.permissions}
            </span>
          </div>
        )}

        {config.trustPolicy && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Trust Policy:</span>
            <span className="ml-2 text-foreground">
              {Array.isArray(config.trustPolicy) ? config.trustPolicy.join(', ') : config.trustPolicy}
            </span>
          </div>
        )}

        {config.groups && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Groups:</span>
            <span className="ml-2 text-foreground">
              {Array.isArray(config.groups) ? config.groups.join(', ') : config.groups}
            </span>
          </div>
        )}

        {config.mfaEnabled !== undefined && (
          <div>
            <span className="text-muted-foreground">MFA:</span>
            <span className={clsx("ml-2", config.mfaEnabled ? "text-primary" : "text-destructive")}>
              {config.mfaEnabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
        )}

        {config.keyAge && (
          <div>
            <span className="text-muted-foreground">Key Age:</span>
            <span className={clsx("ml-2", config.keyAge > 90 ? "text-destructive" : "text-foreground")}>
              {config.keyAge} days
            </span>
          </div>
        )}

        {config.canAssumeRoles && config.canAssumeRoles.length > 0 && (
          <div className="col-span-2">
            <span className="text-muted-foreground">Can Assume:</span>
            <span className="ml-2 text-amber-500">{config.canAssumeRoles.join(', ')}</span>
          </div>
        )}
      </div>
    </motion.div>
  );
}
