import { useAuth } from "@/hooks/use-auth";
import { Link } from "wouter";
import { motion } from "framer-motion";
import { ArrowRight, ShieldAlert, CheckCircle, Clock, Award } from "lucide-react";
import { useLabs } from "@/hooks/use-labs";
import { useProgress } from "@/hooks/use-progress";
import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";

type LevelInfo = {
  level: number;
  title: string;
  nextLevel: number | null;
  progress: number;
  completedLabs: number;
};

export default function Dashboard() {
  const { user } = useAuth();
  const { data: labs, isLoading: labsLoading } = useLabs();
  const { data: progress } = useProgress();
  
  const { data: levelInfo } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level", user?.id],
    enabled: !!user,
    staleTime: 0,
  });
  
  const { data: userBadges } = useQuery<any[]>({
    queryKey: ["/api/user/badges", user?.id],
    enabled: !!user,
    staleTime: 0,
  });

  // Basic stats
  const completedCount = progress?.filter(p => p.completed).length || 0;
  const totalScore = progress?.reduce((acc, p) => acc + (p.score || 0), 0) || 0;
  const badgeCount = userBadges?.length || 0;

  return (
    <div className="space-y-8">
      {/* Header */}
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 border-b border-border/50 pb-8"
      >
        <div>
          <h1 className="text-4xl font-display font-bold text-transparent bg-clip-text bg-gradient-to-r from-white to-white/50 mb-2">
            MISSION CONTROL
          </h1>
          <p className="text-muted-foreground font-mono">
            Welcome back, <span className="text-white">Level {levelInfo?.level || 0} {levelInfo?.title || 'Recruit'}</span> {user?.firstName || 'Guest'}
            <span className="text-primary ml-2">
              <Award className="w-3.5 h-3.5 inline-block mr-1" />
              {badgeCount}/19
            </span>
          </p>
        </div>
        <div className="flex gap-4">
          <div className="px-4 py-2 bg-card border border-border/50 rounded-lg">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Total Score</p>
            <p className="text-2xl font-mono text-primary drop-shadow-[0_0_8px_rgba(0,255,128,0.5)]">{totalScore}</p>
          </div>
          <div className="px-4 py-2 bg-card border border-border/50 rounded-lg">
            <p className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Missions Cleared</p>
            <p className="text-2xl font-mono text-white">{completedCount}</p>
          </div>
        </div>
      </motion.div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Recommended Mission (Large Card) */}
        <motion.div 
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-xl font-display font-semibold flex items-center gap-2">
              <ShieldAlert className="text-primary w-5 h-5" />
              Available Missions
            </h2>
            <Link href="/labs" className="text-sm text-primary hover:text-primary/80 font-mono flex items-center gap-1">
              VIEW_ALL <ArrowRight className="w-3 h-3" />
            </Link>
          </div>

          <div className="grid gap-4">
            {labsLoading ? (
              // Loading Skeletons
              [1, 2, 3].map(i => (
                <div key={i} className="h-40 rounded-xl bg-card/50 animate-pulse border border-border/30" />
              ))
            ) : (
              // Show one lab from each difficulty level
              (() => {
                const beginner = labs?.find(l => l.difficulty === 'Beginner');
                const intermediate = labs?.find(l => l.difficulty === 'Intermediate');
                const advanced = labs?.find(l => l.difficulty === 'Advanced');
                return [beginner, intermediate, advanced].filter((l): l is NonNullable<typeof l> => l !== undefined);
              })().map((lab) => {
                const isCompleted = progress?.some(p => p.labId === lab.id && p.completed);
                return (
                  <Link key={lab.id} href={`/labs/${lab.id}`}>
                    <div className="group relative overflow-hidden bg-card hover:bg-card/80 border border-border/50 hover:border-primary/50 transition-all duration-300 rounded-xl p-6 cursor-pointer">
                      <div className="absolute top-0 right-0 w-32 h-32 bg-primary/5 rounded-full blur-3xl group-hover:bg-primary/10 transition-colors" />
                      
                      <div className="relative z-10 flex justify-between items-start">
                        <div className="space-y-2">
                          <div className="flex items-center gap-3">
                            <span className={clsx(
                              "px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold border",
                              lab.difficulty === 'Beginner' ? "bg-green-500/10 text-green-400 border-green-500/20" :
                              lab.difficulty === 'Intermediate' ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/20" :
                              lab.difficulty === 'Advanced' ? "bg-red-500/10 text-red-400 border-red-500/20" :
                              "bg-purple-500/10 text-purple-400 border-purple-500/20"
                            )}>
                              {lab.difficulty}
                            </span>
                            <span className="text-[10px] font-mono text-muted-foreground uppercase border border-border/30 px-2 py-0.5 rounded">
                              {lab.category}
                            </span>
                          </div>
                          <h3 className="text-xl font-bold group-hover:text-primary transition-colors">{lab.title}</h3>
                          <p className="text-sm text-muted-foreground max-w-xl">{lab.description}</p>
                        </div>
                        
                        <div className="flex flex-col items-end gap-2">
                           {isCompleted ? (
                             <div className="flex items-center gap-2 text-primary text-sm font-mono font-bold bg-primary/10 px-3 py-1 rounded-full border border-primary/20">
                               <CheckCircle className="w-4 h-4" /> COMPLETED
                             </div>
                           ) : (
                             <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center text-primary group-hover:bg-primary group-hover:text-black transition-all">
                               <ArrowRight className="w-5 h-5" />
                             </div>
                           )}
                        </div>
                      </div>
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </motion.div>

        {/* Recent Activity / Mini Stats */}
        <motion.div 
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4"
        >
          <h2 className="text-xl font-display font-semibold flex items-center gap-2">
            <Clock className="text-primary w-5 h-5" />
            Recent Activity
          </h2>
          
          <div className="bg-card border border-border/50 rounded-xl p-6 min-h-[300px] relative overflow-hidden">
            <div className="absolute inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-10"></div>
            
            <div className="relative z-10 space-y-6">
              {progress?.length ? (
                progress.slice(0, 5).map((p, i) => (
                  <div key={i} className="flex items-start gap-4 pb-4 border-b border-white/5 last:border-0">
                    <div className={clsx(
                      "w-2 h-2 mt-1.5 rounded-full shadow-[0_0_8px_rgba(0,0,0,0.5)]",
                      p.completed ? "bg-primary shadow-primary/50" : "bg-yellow-500 shadow-yellow-500/50"
                    )} />
                    <div>
                      <p className="text-sm font-medium text-white">{p.lab.title}</p>
                      <p className="text-xs text-muted-foreground font-mono mt-1">
                        {p.completed ? `Mission Complete (+${p.score} pts)` : "In Progress"}
                      </p>
                      <p className="text-[10px] text-muted-foreground/50 font-mono mt-0.5">
                        {p.completedAt ? new Date(p.completedAt).toLocaleDateString() : 'Active now'}
                      </p>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-center py-10">
                  <p className="text-muted-foreground text-sm">No activity logs yet.</p>
                  <Link href="/labs" className="inline-block mt-4 text-xs font-mono text-primary border border-primary/30 px-4 py-2 rounded hover:bg-primary/10">START_FIRST_MISSION</Link>
                </div>
              )}
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
}
