import { useLabResources } from "@/hooks/use-labs";
import { Cloud, Server, Database, Lock, AlertOctagon, CheckCircle2, ChevronDown, Shield, Eye, Terminal, Info } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";
import { type Resource } from "@shared/schema";
import { useState } from "react";

interface ResourceGraphProps {
  labId: number;
}

export function ResourceGraph({ labId }: ResourceGraphProps) {
  const { data: resources, isLoading } = useLabResources(labId);
  const [selectedResource, setSelectedResource] = useState<number | null>(null);

  if (isLoading) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-3">
        <motion.div
          className="w-12 h-12 border-2 border-primary/30 border-t-primary rounded-full"
          animate={{ rotate: 360 }}
          transition={{ duration: 1, repeat: Infinity, ease: "linear" }}
        />
        <span className="text-xs font-mono animate-pulse">Scanning infrastructure...</span>
      </div>
    );
  }

  if (!resources?.length) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground gap-2">
        <Cloud className="w-10 h-10 opacity-30" />
        <span className="text-sm">No resources detected</span>
      </div>
    );
  }

  const vulnerableCount = resources.filter(r => r.isVulnerable).length;
  const secureCount = resources.length - vulnerableCount;

  return (
    <div className="space-y-4">
      {/* Stats Bar */}
      <div className="flex items-center justify-between bg-black/30 rounded-lg px-4 py-2 border border-white/5">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-destructive animate-pulse" />
            <span className="text-xs font-mono text-destructive">{vulnerableCount} Vulnerable</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-primary" />
            <span className="text-xs font-mono text-primary">{secureCount} Secure</span>
          </div>
        </div>
        <span className="text-[10px] text-muted-foreground font-mono">
          Click a resource for details
        </span>
      </div>

      {/* Resource Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 auto-rows-min">
        <AnimatePresence mode="popLayout">
          {resources.map((resource) => (
            <ResourceCard 
              key={resource.id} 
              resource={resource} 
              isSelected={selectedResource === resource.id}
              onSelect={() => setSelectedResource(selectedResource === resource.id ? null : resource.id)}
            />
          ))}
        </AnimatePresence>
      </div>
    </div>
  );
}

interface ResourceCardProps {
  resource: Resource;
  isSelected: boolean;
  onSelect: () => void;
}

function ResourceCard({ resource, isSelected, onSelect }: ResourceCardProps) {
  const isVulnerable = resource.isVulnerable;
  
  const getIcon = () => {
    switch (resource.type) {
      case 's3': return Database;
      case 'ec2': return Server;
      case 'iam_role': return Lock;
      case 'security_group': return Shield;
      default: return Cloud;
    }
  };

  const getTypeLabel = () => {
    switch (resource.type) {
      case 's3': return 'S3 Bucket';
      case 'ec2': return 'EC2 Instance';
      case 'iam_role': return 'IAM Role';
      case 'security_group': return 'Security Group';
      default: return resource.type;
    }
  };

  const getVulnerabilityHint = () => {
    if (!isVulnerable) return null;
    const config = resource.config as Record<string, any>;
    
    if (resource.type === 's3') {
      if (config.acl === 'public-read') return "Public ACL detected - data exposed!";
      if (config.blockPublicAccess === false) return "Block Public Access disabled";
      return "Bucket policy misconfiguration";
    }
    if (resource.type === 'ec2' || resource.type === 'security_group') {
      if (config.sshOpen) return "SSH open to 0.0.0.0/0 - brute force risk!";
      if (config.rdpOpen) return "RDP exposed to internet";
      return "Overly permissive security rules";
    }
    if (resource.type === 'iam_role') {
      return "Excessive permissions detected";
    }
    return "Security misconfiguration detected";
  };

  const Icon = getIcon();

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      exit={{ opacity: 0, scale: 0.9 }}
      onClick={onSelect}
      className={clsx(
        "relative overflow-hidden rounded-lg border cursor-pointer transition-all duration-200",
        isVulnerable 
          ? "bg-gradient-to-br from-destructive/10 to-destructive/5 border-destructive/30 hover:border-destructive/60" 
          : "bg-gradient-to-br from-primary/10 to-primary/5 border-primary/30 hover:border-primary/60",
        isSelected && "ring-2 ring-offset-2 ring-offset-background",
        isSelected && (isVulnerable ? "ring-destructive" : "ring-primary")
      )}
      whileHover={{ y: -2 }}
      whileTap={{ scale: 0.98 }}
      data-testid={`resource-${resource.id}`}
    >
      {/* Pulse effect for vulnerable resources */}
      {isVulnerable && (
        <motion.div
          className="absolute inset-0 bg-destructive/10"
          animate={{ opacity: [0, 0.3, 0] }}
          transition={{ duration: 2, repeat: Infinity }}
        />
      )}

      <div className="p-3 relative z-10">
        <div className="flex items-start justify-between mb-2">
          <div className={clsx(
            "p-1.5 rounded-md",
            isVulnerable 
              ? "bg-destructive/20 text-destructive" 
              : "bg-primary/20 text-primary"
          )}>
            <Icon className="w-4 h-4" />
          </div>
          
          <div className="flex items-center gap-1">
            {isVulnerable ? (
              <motion.div 
                className="flex items-center gap-1 text-[9px] font-mono font-bold text-destructive bg-destructive/20 px-1.5 py-0.5 rounded"
                animate={{ scale: [1, 1.05, 1] }}
                transition={{ duration: 1, repeat: Infinity }}
              >
                <AlertOctagon className="w-2.5 h-2.5" />
                <span>VULN</span>
              </motion.div>
            ) : (
              <div className="flex items-center gap-1 text-[9px] font-mono font-bold text-primary bg-primary/20 px-1.5 py-0.5 rounded">
                <CheckCircle2 className="w-2.5 h-2.5" />
                <span>OK</span>
              </div>
            )}
            <motion.div
              animate={{ rotate: isSelected ? 180 : 0 }}
              transition={{ duration: 0.2 }}
            >
              <ChevronDown className="w-3 h-3 text-muted-foreground" />
            </motion.div>
          </div>
        </div>

        <h3 className="font-mono font-semibold text-foreground text-xs truncate">{resource.name}</h3>
        <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-wider">{getTypeLabel()}</p>

        {/* Vulnerability Hint */}
        {isVulnerable && (
          <p className="text-[10px] text-destructive/80 mt-1 flex items-center gap-1">
            <Info className="w-2.5 h-2.5 flex-shrink-0" />
            <span className="truncate">{getVulnerabilityHint()}</span>
          </p>
        )}

        {/* Expanded Details */}
        <AnimatePresence>
          {isSelected && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.2 }}
              className="overflow-hidden"
            >
              <div className="mt-3 pt-3 border-t border-white/10 space-y-2">
                <div className="flex items-center gap-1 text-[10px] text-muted-foreground mb-2">
                  <Eye className="w-3 h-3" />
                  <span>Configuration Details</span>
                </div>
                
                {Object.entries(resource.config as Record<string, any>).map(([key, val]) => (
                  <div key={key} className="flex justify-between text-[10px] font-mono bg-black/20 rounded px-2 py-1">
                    <span className="text-muted-foreground">{key}:</span>
                    <span className={clsx(
                      "truncate max-w-[120px]",
                      isVulnerable && (key === 'acl' || key === 'sshOpen' || key === 'source') ? "text-destructive font-bold" : 
                      isVulnerable ? "text-yellow-300" : "text-primary"
                    )}>
                      {typeof val === 'boolean' ? (val ? 'true' : 'false') : String(val)}
                    </span>
                  </div>
                ))}

                {/* Command Hint */}
                {isVulnerable && (
                  <div className="mt-2 pt-2 border-t border-white/5">
                    <div className="flex items-center gap-1 text-[10px] text-cyan-400">
                      <Terminal className="w-3 h-3" />
                      <span>Try: </span>
                      <code className="bg-cyan-950/50 px-1 rounded text-cyan-300">
                        {resource.type === 's3' ? `aws s3 block-public-access ${resource.name}` :
                         resource.type === 'ec2' || resource.type === 'security_group' ? `aws ec2 restrict-ssh ${resource.name}` :
                         `aws iam fix-permissions ${resource.name}`}
                      </code>
                    </div>
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
