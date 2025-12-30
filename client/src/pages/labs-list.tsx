import { useLabs } from "@/hooks/use-labs";
import { useProgress } from "@/hooks/use-progress";
import { Link } from "wouter";
import { motion } from "framer-motion";
import { Loader2, Search, Clock, ListChecks, CheckCircle2, X } from "lucide-react";
import { useState } from "react";
import { clsx } from "clsx";
import { useMutation } from "@tanstack/react-query";
import { apiRequest, queryClient } from "@/lib/queryClient";
import { api } from "@shared/routes";

const SEARCH_KEYWORDS: Record<string, string[]> = {
  "Cloud Security Analyst": ["soc", "analyst", "cloud", "security", "csa"],
  "Cloud Security Engineer": ["cloud", "security", "engineer", "cse"],
  "SOC Operations": ["soc", "operations", "ops", "security"],
  "SOC Engineer": ["soc", "engineer", "security"],
  "IAM Security": ["iam", "identity", "access", "security"],
  "Network Security": ["network", "firewall", "vpc", "security"],
  "Storage Security": ["storage", "s3", "bucket", "security"],
};

export default function LabsList() {
  const { data: labs, isLoading } = useLabs();
  const { data: progress } = useProgress();
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');

  const isLabCompleted = (labId: number) => {
    return progress?.some(p => p.labId === labId && p.completed) || false;
  };

  const resetProgressMutation = useMutation({
    mutationFn: async (labId: number) => {
      await apiRequest("DELETE", `/api/progress/${labId}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [api.progress.get.path] });
    }
  });

  const handleResetProgress = (e: React.MouseEvent, labId: number) => {
    e.preventDefault();
    e.stopPropagation();
    resetProgressMutation.mutate(labId);
  };

  const filteredLabs = labs?.filter(lab => {
    const matchesFilter = filter === 'All' || lab.difficulty === filter;
    const searchLower = search.toLowerCase().trim();
    if (!searchLower) return matchesFilter;
    
    const matchesTitle = lab.title.toLowerCase().includes(searchLower);
    const matchesDescription = lab.description.toLowerCase().includes(searchLower);
    const matchesCategory = lab.category.toLowerCase().includes(searchLower);
    const categoryKeywords = SEARCH_KEYWORDS[lab.category] || [];
    const matchesKeywords = categoryKeywords.some(keyword => keyword.includes(searchLower) || searchLower.includes(keyword));
    
    const matchesSearch = matchesTitle || matchesDescription || matchesCategory || matchesKeywords;
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="space-y-8 max-w-6xl mx-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white mb-2">TRAINING SIMULATIONS</h1>
          <p className="text-muted-foreground">Select a scenario to begin your security assessment.</p>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col md:flex-row gap-4 bg-card p-4 rounded-xl border border-border/50">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
          <input 
            type="text" 
            placeholder="Search missions..." 
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-background/50 border border-border rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-primary/50 focus:ring-1 focus:ring-primary/50 transition-all"
          />
        </div>
        <div className="flex gap-2 overflow-x-auto pb-2 md:pb-0">
          {['All', 'Beginner', 'Intermediate', 'Advanced', 'Challenge'].map((lvl) => (
            <button
              key={lvl}
              onClick={() => setFilter(lvl)}
              className={clsx(
                "px-4 py-2 rounded-lg text-sm font-mono whitespace-nowrap transition-all border",
                filter === lvl 
                  ? "bg-primary/10 text-primary border-primary/30" 
                  : "bg-transparent text-muted-foreground border-transparent hover:bg-white/5 hover:text-white"
              )}
            >
              {lvl.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      {/* Grid */}
      {isLoading ? (
        <div className="flex justify-center py-20">
          <Loader2 className="w-8 h-8 text-primary animate-spin" />
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {filteredLabs?.map((lab, index) => {
            const completed = isLabCompleted(lab.id);
            return (
            <motion.div
              key={lab.id}
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ delay: index * 0.08, duration: 0.4 }}
              whileHover={{ y: -8, scale: 1.02 }}
            >
              <Link href={`/labs/${lab.id}`} className="block h-full">
                <div className="h-full relative overflow-hidden rounded-xl flex flex-col transition-all duration-300 group shadow-xl hover:shadow-2xl hover:shadow-primary/30">
                  {/* Animated gradient background */}
                  <div className="absolute inset-0 bg-gradient-to-br from-primary/10 via-card to-accent/10 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  <div className="absolute inset-0 bg-card group-hover:bg-gradient-to-br group-hover:from-card group-hover:via-card/80 group-hover:to-accent/5 transition-all duration-300" />
                  
                  {/* Animated border glow */}
                  <div className="absolute inset-0 rounded-xl border border-primary/30 group-hover:border-primary/60 transition-all duration-300" />
                  <div className="absolute inset-0 rounded-xl border border-accent/20 group-hover:border-accent/40 transition-all duration-300 blur-sm opacity-0 group-hover:opacity-100" />
                  
                  {/* Category Stripe - Enhanced */}
                  <motion.div 
                    className={clsx(
                      "absolute top-0 left-0 w-1.5 h-full transition-all group-hover:w-2",
                      lab.category === 'IAM' ? "bg-gradient-to-b from-blue-500 to-blue-600" :
                      lab.category === 'Network' ? "bg-gradient-to-b from-purple-500 to-purple-600" : "bg-gradient-to-b from-orange-500 to-orange-600"
                    )}
                    animate={{ boxShadow: ["0 0 10px rgba(0, 0, 0, 0)", "0 0 20px rgba(255, 150, 0, 0.5)"] }}
                    transition={{ duration: 2, repeat: Infinity }}
                  />

                  <div className="relative z-10 flex justify-between items-start mb-4 p-6 pb-0">
                     <motion.span 
                       className="text-[10px] font-mono text-primary/80 uppercase tracking-widest bg-primary/10 px-3 py-1.5 rounded-full border border-primary/40 font-bold"
                       whileHover={{ scale: 1.1 }}
                     >
                        {lab.category}
                     </motion.span>
                     <motion.span 
                       className={clsx(
                          "text-[10px] font-bold px-3 py-1.5 rounded-full border uppercase font-mono",
                          lab.difficulty === 'Beginner' ? "text-green-300 border-green-500/50 bg-green-500/15 shadow-lg shadow-green-500/20" :
                          lab.difficulty === 'Intermediate' ? "text-yellow-300 border-yellow-500/50 bg-yellow-500/15 shadow-lg shadow-yellow-500/20" :
                          lab.difficulty === 'Advanced' ? "text-red-300 border-red-500/50 bg-red-500/15 shadow-lg shadow-red-500/20" :
                          "text-purple-300 border-purple-500/50 bg-purple-500/15 shadow-lg shadow-purple-500/20"
                       )}
                       animate={{ boxShadow: ["0 0 10px rgba(255, 200, 0, 0.2)", "0 0 20px rgba(255, 200, 0, 0.4)"] }}
                       transition={{ duration: 2, repeat: Infinity }}
                     >
                        {lab.difficulty}
                     </motion.span>
                  </div>

                  <h3 className="relative z-10 text-lg font-bold font-display mb-3 px-6 group-hover:text-transparent group-hover:bg-clip-text group-hover:bg-gradient-to-r group-hover:from-primary group-hover:to-accent transition-all duration-300">
                    {lab.title}
                  </h3>
                  
                  <p className="relative z-10 text-sm text-muted-foreground/80 flex-1 px-6 mb-4 group-hover:text-muted-foreground transition-colors">
                    {lab.description}
                  </p>

                  <div className="relative z-10 flex items-center gap-4 px-6 mb-4 text-xs text-muted-foreground/70">
                    {lab.estimatedTime && (
                      <span className="flex items-center gap-1" data-testid={`text-time-${lab.id}`}>
                        <Clock className="w-3 h-3" />
                        {String(lab.estimatedTime)}
                      </span>
                    )}
                    {lab.steps && Array.isArray(lab.steps) && (lab.steps as Array<unknown>).length > 0 && (
                      <span className="flex items-center gap-1" data-testid={`text-steps-${lab.id}`}>
                        <ListChecks className="w-3 h-3" />
                        {String((lab.steps as Array<unknown>).length)} steps
                      </span>
                    )}
                  </div>

                  <div className="relative z-10 mt-auto px-6 pb-6 space-y-2">
                    {completed && (
                      <div className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-green-400 text-xs font-mono font-bold">
                          <CheckCircle2 className="w-4 h-4" />
                          Completed
                        </span>
                        <button 
                          onClick={(e) => handleResetProgress(e, lab.id)}
                          className="flex items-center gap-1 text-muted-foreground hover:text-red-400 text-xs font-mono transition-colors"
                          data-testid={`button-reset-${lab.id}`}
                        >
                          <X className="w-3.5 h-3.5" />
                          Remove
                        </button>
                      </div>
                    )}
                    <motion.button 
                      className="w-full py-3 rounded-lg bg-gradient-to-r from-primary/20 to-accent/20 border border-primary/40 text-primary text-center text-xs font-mono font-bold group-hover:from-primary group-hover:to-accent group-hover:text-background transition-all uppercase tracking-wider shadow-lg"
                      whileHover={{ 
                        boxShadow: "0 0 25px rgba(0, 255, 128, 0.5)",
                        scale: 1.05
                      }}
                      whileTap={{ scale: 0.95 }}
                    >
                      Initialize Simulation
                    </motion.button>
                  </div>
                </div>
              </Link>
            </motion.div>
          );
          })}
          
          {filteredLabs?.length === 0 && (
             <div className="col-span-full text-center py-20 text-muted-foreground">
               No missions found matching your criteria.
             </div>
          )}
        </div>
      )}
    </div>
  );
}
