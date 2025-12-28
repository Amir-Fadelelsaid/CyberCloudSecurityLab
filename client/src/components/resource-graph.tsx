import { useLabResources } from "@/hooks/use-labs";
import { Cloud, Server, Database, Lock, AlertOctagon, CheckCircle2 } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { clsx } from "clsx";
import { type Resource } from "@shared/schema";

interface ResourceGraphProps {
  labId: number;
}

export function ResourceGraph({ labId }: ResourceGraphProps) {
  const { data: resources, isLoading } = useLabResources(labId);

  if (isLoading) {
    return <div className="h-full flex items-center justify-center text-muted-foreground animate-pulse">Scanning infrastructure...</div>;
  }

  if (!resources?.length) {
    return <div className="h-full flex items-center justify-center text-muted-foreground">No resources detected.</div>;
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 auto-rows-min">
      <AnimatePresence>
        {resources.map((resource) => (
          <ResourceCard key={resource.id} resource={resource} />
        ))}
      </AnimatePresence>
    </div>
  );
}

function ResourceCard({ resource }: { resource: Resource }) {
  const isVulnerable = resource.isVulnerable;
  
  // Icon mapping based on resource type
  const getIcon = () => {
    switch (resource.type) {
      case 's3': return Database;
      case 'ec2': return Server;
      case 'iam_role': return Lock;
      case 'security_group': return Cloud;
      default: return Cloud;
    }
  };

  const Icon = getIcon();

  return (
    <motion.div
      layout
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className={clsx(
        "relative overflow-hidden rounded-xl border p-4 transition-all duration-300 backdrop-blur-sm group",
        isVulnerable 
          ? "bg-destructive/5 border-destructive/30 shadow-[0_0_15px_-5px_rgba(239,68,68,0.3)] hover:border-destructive/60" 
          : "bg-primary/5 border-primary/30 shadow-[0_0_15px_-5px_rgba(34,197,94,0.3)] hover:border-primary/60"
      )}
    >
      {/* Background Status Indicator (Glow) */}
      <div className={clsx(
        "absolute -right-4 -top-4 w-20 h-20 rounded-full blur-2xl opacity-20 transition-colors",
        isVulnerable ? "bg-destructive" : "bg-primary"
      )} />

      <div className="flex items-start justify-between mb-4 relative z-10">
        <div className={clsx(
          "p-2 rounded-lg border",
          isVulnerable 
            ? "bg-destructive/10 border-destructive/20 text-destructive" 
            : "bg-primary/10 border-primary/20 text-primary"
        )}>
          <Icon className="w-5 h-5" />
        </div>
        
        {isVulnerable ? (
          <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-destructive bg-destructive/10 px-2 py-1 rounded border border-destructive/20">
            <AlertOctagon className="w-3 h-3" />
            <span>VULNERABLE</span>
          </div>
        ) : (
          <div className="flex items-center gap-1 text-[10px] font-mono font-bold text-primary bg-primary/10 px-2 py-1 rounded border border-primary/20">
            <CheckCircle2 className="w-3 h-3" />
            <span>SECURE</span>
          </div>
        )}
      </div>

      <div className="relative z-10">
        <h3 className="font-display font-semibold text-foreground tracking-wide text-sm">{resource.name}</h3>
        <p className="text-xs text-muted-foreground font-mono mt-1 uppercase tracking-wider opacity-70">{resource.type}</p>
        
        {/* Config Summary - visualize JSON config roughly */}
        <div className="mt-4 pt-3 border-t border-white/5 space-y-1">
           {Object.entries(resource.config as Record<string, any>).slice(0, 2).map(([key, val]) => (
             <div key={key} className="flex justify-between text-[10px] font-mono">
               <span className="text-muted-foreground">{key}:</span>
               <span className={clsx("truncate max-w-[100px]", isVulnerable ? "text-red-300" : "text-green-300")}>
                 {String(val)}
               </span>
             </div>
           ))}
        </div>
      </div>
    </motion.div>
  );
}
