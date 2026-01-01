import { useLab, useLabResources } from "@/hooks/use-labs";
import { useRoute, Link } from "wouter";
import { TerminalWindow } from "@/components/terminal-window";
import { ResourceGraph } from "@/components/resource-graph";
import { IdentityGraph } from "@/components/identity-graph";
import { SOCDashboard } from "@/components/soc-dashboard";
import { MissionCompleteModal } from "@/components/mission-complete-modal";
import { Loader2, ArrowLeft, RefreshCw, AlertCircle, PlayCircle, BookOpen, CheckCircle2, PanelLeftClose, PanelLeft, Clock, Shield, Target, Zap, AlertTriangle, Trophy } from "lucide-react";
import { useResetLab } from "@/hooks/use-labs";
import { useState, useEffect, useCallback, useRef } from "react";
import { clsx } from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";

const SOC_CATEGORIES = ["Cloud Security Analyst", "SOC Engineer", "SOC Operations"];
const IAM_CATEGORIES = ["IAM Security"];

export default function LabWorkspace() {
  const [, params] = useRoute("/labs/:id");
  const labId = Number(params?.id);
  const { data: lab, isLoading, error } = useLab(labId);
  const { data: resources, refetch: refetchResources } = useLabResources(labId);
  const { mutate: resetLabMutation, isPending: isResetting } = useResetLab();
  const terminalResetKey = useRef(0);
  const [activeTab, setActiveTab] = useState<'brief' | 'steps'>('brief');
  const [showCompleteModal, setShowCompleteModal] = useState(false);
  const [isNewCompletion, setIsNewCompletion] = useState(false);
  const [showStepsPanel, setShowStepsPanel] = useState(() => {
    const saved = localStorage.getItem(`lab-${labId}-showSteps`);
    return saved !== null ? saved === 'true' : true;
  });
  
  // Game state
  const [elapsedTime, setElapsedTime] = useState(0);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(() => {
    const saved = localStorage.getItem(`lab-${labId}-completedSteps`);
    return saved ? new Set(JSON.parse(saved)) : new Set();
  });
  const [commandStreak, setCommandStreak] = useState(0);
  const [showSuccessFlash, setShowSuccessFlash] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);

  // Calculate threat level from resources
  const vulnerableCount = resources?.filter((r: any) => r.isVulnerable).length || 0;
  const totalResources = resources?.length || 1;
  const threatLevel = Math.round((vulnerableCount / totalResources) * 100);
  const totalSteps = lab?.steps ? (lab.steps as any[]).length : 0;
  const progressPercent = totalSteps > 0 ? Math.round((completedSteps.size / totalSteps) * 100) : 0;

  // Timer
  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedTime(prev => prev + 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [labId]);

  // Save completed steps
  useEffect(() => {
    localStorage.setItem(`lab-${labId}-completedSteps`, JSON.stringify(Array.from(completedSteps)));
  }, [labId, completedSteps]);

  useEffect(() => {
    localStorage.setItem(`lab-${labId}-showSteps`, String(showStepsPanel));
  }, [labId, showStepsPanel]);

  // Format time
  const formatTime = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  // Handle step completion
  const toggleStep = (stepNum: number) => {
    setCompletedSteps(prev => {
      const next = new Set(prev);
      if (next.has(stepNum)) {
        next.delete(stepNum);
      } else {
        next.add(stepNum);
      }
      return next;
    });
  };

  // Handle command success (called from terminal)
  const handleCommandSuccess = useCallback(() => {
    setCommandStreak(prev => prev + 1);
    setShowSuccessFlash(true);
    setTimeout(() => setShowSuccessFlash(false), 500);
  }, []);

  // Handle lab reset
  const handleResetLab = useCallback(() => {
    resetLabMutation(labId, {
      onSuccess: () => {
        // Reset all local state
        setCompletedSteps(new Set());
        setElapsedTime(0);
        setCommandStreak(0);
        setShowCompleteModal(false);
        // Clear localStorage for this lab
        localStorage.removeItem(`lab-${labId}-completedSteps`);
        localStorage.removeItem(`lab-${labId}-terminalHistory`);
        // Force terminal to reset by updating key
        terminalResetKey.current += 1;
        // Refetch resources
        refetchResources();
      }
    });
  }, [labId, resetLabMutation, refetchResources]);

  // Reset on lab change
  useEffect(() => {
    setElapsedTime(0);
    setCommandStreak(0);
    const saved = localStorage.getItem(`lab-${labId}-completedSteps`);
    setCompletedSteps(saved ? new Set(JSON.parse(saved)) : new Set());
  }, [labId]);

  if (isLoading) {
    return (
      <div className="h-screen flex flex-col items-center justify-center space-y-4">
        <Loader2 className="w-12 h-12 text-primary animate-spin" />
        <p className="text-primary font-mono animate-pulse">INITIALIZING VIRTUAL ENVIRONMENT...</p>
      </div>
    );
  }

  if (error || !lab) {
    return (
      <div className="h-[80vh] flex flex-col items-center justify-center space-y-4 text-center">
        <AlertCircle className="w-16 h-16 text-destructive" />
        <h2 className="text-2xl font-bold text-white">Simulation Load Failed</h2>
        <p className="text-muted-foreground">Could not connect to the lab environment.</p>
        <Link href="/labs" className="text-primary hover:underline">Return to Base</Link>
      </div>
    );
  }

  return (
    <div className="h-[calc(100vh-6rem)] flex flex-col space-y-3 overflow-hidden relative">
      {/* Success Flash Overlay */}
      <AnimatePresence>
        {showSuccessFlash && (
          <motion.div
            className="absolute inset-0 bg-primary/10 pointer-events-none z-50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          />
        )}
      </AnimatePresence>

      {/* Mission HUD Bar */}
      <div className="flex items-center justify-between flex-shrink-0 bg-gradient-to-r from-black/80 via-card/60 to-black/80 px-4 py-2 rounded-lg border border-primary/30 backdrop-blur-md">
        <div className="flex items-center gap-6">
          {/* Back Button & Title */}
          <Link href="/labs">
            <button className="p-2 hover:bg-primary/10 rounded-lg transition-all group" data-testid="button-back">
              <ArrowLeft className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
            </button>
          </Link>
          
          <div className="flex items-center gap-3">
            <motion.div
              className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary/20 to-accent/20 border border-primary/40 flex items-center justify-center"
              animate={{ rotate: [0, 5, -5, 0] }}
              transition={{ duration: 4, repeat: Infinity }}
            >
              <Target className="w-4 h-4 text-primary" />
            </motion.div>
            <div>
              <h1 className="text-sm font-bold text-white truncate max-w-[200px]">{lab.title}</h1>
              <p className="text-[10px] text-primary/60 font-mono">MISSION #{labId.toString().padStart(4, '0')}</p>
            </div>
          </div>
        </div>

        {/* HUD Stats */}
        <div className="flex items-center gap-4">
          {/* Timer */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-black/40 rounded-lg border border-white/10">
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-mono text-cyan-400">{formatTime(elapsedTime)}</span>
          </div>

          {/* Threat Level */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-black/40 rounded-lg border border-white/10 min-w-[120px]">
            <AlertTriangle className={clsx("w-3.5 h-3.5", threatLevel > 50 ? "text-destructive" : threatLevel > 0 ? "text-yellow-400" : "text-primary")} />
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-muted-foreground">THREAT</span>
                <span className={clsx("text-[10px] font-bold", threatLevel > 50 ? "text-destructive" : threatLevel > 0 ? "text-yellow-400" : "text-primary")}>{threatLevel}%</span>
              </div>
              <div className="h-1 bg-black/60 rounded-full overflow-hidden">
                <motion.div 
                  className={clsx("h-full rounded-full", threatLevel > 50 ? "bg-destructive" : threatLevel > 0 ? "bg-yellow-400" : "bg-primary")}
                  initial={{ width: 0 }}
                  animate={{ width: `${threatLevel}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
          </div>

          {/* Progress */}
          <div className="flex items-center gap-2 px-3 py-1.5 bg-black/40 rounded-lg border border-white/10 min-w-[120px]">
            <CheckCircle2 className="w-3.5 h-3.5 text-primary" />
            <div className="flex-1">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-mono text-muted-foreground">PROGRESS</span>
                <span className="text-[10px] font-bold text-primary">{progressPercent}%</span>
              </div>
              <div className="h-1 bg-black/60 rounded-full overflow-hidden">
                <motion.div 
                  className="h-full bg-gradient-to-r from-primary to-accent rounded-full"
                  initial={{ width: 0 }}
                  animate={{ width: `${progressPercent}%` }}
                  transition={{ duration: 0.5 }}
                />
              </div>
            </div>
          </div>

          {/* Command Streak */}
          {commandStreak > 0 && (
            <motion.div 
              className="flex items-center gap-2 px-3 py-1.5 bg-gradient-to-r from-amber-500/20 to-orange-500/20 rounded-lg border border-amber-500/40"
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
            >
              <Zap className="w-3.5 h-3.5 text-amber-400" />
              <span className="text-xs font-bold text-amber-400">{commandStreak}x STREAK</span>
            </motion.div>
          )}
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3">
          <Button
            variant={showStepsPanel ? "default" : "outline"}
            size="sm"
            onClick={() => setShowStepsPanel(!showStepsPanel)}
            className={clsx(
              "flex items-center gap-2 text-xs font-mono transition-all",
              showStepsPanel 
                ? "bg-primary/20 border-primary text-primary hover:bg-primary/30" 
                : "border-muted-foreground/30 text-muted-foreground hover:border-primary/60 hover:text-primary"
            )}
            data-testid="button-toggle-steps"
          >
            {showStepsPanel ? <PanelLeftClose className="w-3.5 h-3.5" /> : <PanelLeft className="w-3.5 h-3.5" />}
            <span>{showStepsPanel ? "Guided" : "Challenge"}</span>
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={handleResetLab}
            disabled={isResetting}
            className="flex items-center gap-2 text-xs font-mono border-primary/30 hover:border-primary/60"
            data-testid="button-reset"
          >
            <RefreshCw className={clsx("w-3.5 h-3.5", isResetting && "animate-spin")} />
          </Button>
        </div>
      </div>

      {/* Main Workspace Layout */}
      <div className={clsx("flex-1 grid grid-cols-1 gap-4 min-h-0", showStepsPanel ? "lg:grid-cols-12" : "lg:grid-cols-1")}>
        
        {/* Left Panel: Interactive Steps */}
        <AnimatePresence>
        {showStepsPanel && (
        <motion.div 
          className="lg:col-span-3 bg-gradient-to-b from-card/80 to-card/40 border border-border/50 rounded-xl flex flex-col overflow-hidden backdrop-blur-sm"
          initial={{ opacity: 0, x: -20, width: 0 }}
          animate={{ opacity: 1, x: 0, width: "auto" }}
          exit={{ opacity: 0, x: -20, width: 0 }}
          transition={{ duration: 0.3 }}
        >
          {/* Tabs */}
          <div className="flex border-b border-primary/20">
            <button 
              onClick={() => setActiveTab('brief')}
              className={clsx(
                "flex-1 py-2.5 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all flex items-center justify-center gap-2",
                activeTab === 'brief' 
                  ? "border-primary text-primary bg-primary/5" 
                  : "border-transparent text-muted-foreground hover:text-white"
              )}
              data-testid="tab-brief"
            >
              <BookOpen className="w-3.5 h-3.5" /> Intel
            </button>
            <button 
              onClick={() => setActiveTab('steps')}
              className={clsx(
                "flex-1 py-2.5 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all flex items-center justify-center gap-2",
                activeTab === 'steps' 
                  ? "border-primary text-primary bg-primary/5" 
                  : "border-transparent text-muted-foreground hover:text-white"
              )}
              data-testid="tab-steps"
            >
              <Target className="w-3.5 h-3.5" /> Objectives
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto p-4 space-y-4">
            {activeTab === 'steps' ? (
              <div className="space-y-3">
                {/* Progress Summary */}
                <div className="bg-black/30 rounded-lg p-3 border border-primary/20">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono text-muted-foreground">MISSION OBJECTIVES</span>
                    <span className="text-xs font-bold text-primary">{completedSteps.size}/{totalSteps}</span>
                  </div>
                  <Progress value={progressPercent} className="h-2" />
                </div>

                {/* Interactive Steps */}
                {lab.steps && Array.isArray(lab.steps) && lab.steps.length > 0 ? (
                  <div className="space-y-2">
                    {(lab.steps as any[]).map((step, idx) => {
                      const isCompleted = completedSteps.has(step.number);
                      return (
                        <motion.div 
                          key={step.number}
                          onClick={() => toggleStep(step.number)}
                          className={clsx(
                            "group relative rounded-lg border p-3 cursor-pointer transition-all",
                            isCompleted 
                              ? "bg-primary/10 border-primary/40" 
                              : "bg-black/20 border-white/10 hover:border-primary/30 hover:bg-black/30"
                          )}
                          initial={{ opacity: 0, y: 10 }}
                          animate={{ opacity: 1, y: 0 }}
                          transition={{ delay: idx * 0.05 }}
                          whileTap={{ scale: 0.98 }}
                          data-testid={`step-${step.number}`}
                        >
                          <div className="flex items-start gap-3">
                            {/* Checkbox */}
                            <motion.div 
                              className={clsx(
                                "w-6 h-6 rounded-full border-2 flex items-center justify-center flex-shrink-0 mt-0.5",
                                isCompleted 
                                  ? "bg-primary border-primary" 
                                  : "border-muted-foreground/40 group-hover:border-primary/60"
                              )}
                              animate={isCompleted ? { scale: [1, 1.2, 1] } : {}}
                            >
                              {isCompleted && <CheckCircle2 className="w-4 h-4 text-background" />}
                              {!isCompleted && <span className="text-[10px] font-bold text-muted-foreground">{step.number}</span>}
                            </motion.div>
                            
                            <div className="flex-1 min-w-0">
                              <h4 className={clsx(
                                "text-sm font-bold mb-1",
                                isCompleted ? "text-primary line-through opacity-70" : "text-white"
                              )}>
                                {step.title}
                              </h4>
                              <p className="text-[11px] text-muted-foreground mb-2">{step.description}</p>
                              
                              {/* Hint - collapsible */}
                              <div className="text-[10px] text-primary/70 font-mono bg-black/40 p-2 rounded border border-primary/20 overflow-x-auto">
                                <div className="whitespace-nowrap">
                                  <span className="text-primary font-bold">CMD:</span> <span>{step.hint?.match(/'([^']+)'/)?.[1] || step.hint}</span>
                                </div>
                              </div>
                              
                              {step.intel && !isCompleted && (
                                <motion.div 
                                  className="mt-2 text-[10px] font-mono bg-cyan-950/30 p-2 rounded border border-cyan-500/20 space-y-1 break-words"
                                  initial={{ height: 0, opacity: 0 }}
                                  animate={{ height: "auto", opacity: 1 }}
                                >
                                  <span className="text-cyan-400 font-bold">INTEL:</span>{" "}
                                  <span className="text-cyan-400/70 break-all">
                                    {step.intel.split(/(T\d{4}(?:\.\d{3})?)/g).map((part: string, i: number) => 
                                      /^T\d{4}(?:\.\d{3})?$/.test(part) ? (
                                        <span key={i} className="inline-flex items-center gap-1 bg-cyan-600/30 text-cyan-300 px-1.5 py-0.5 rounded mx-0.5 border border-cyan-500/40 hover:bg-cyan-600/50 cursor-help" title={`MITRE ATT&CK Technique ${part}`}>
                                          <Shield className="w-2.5 h-2.5" />
                                          {part}
                                        </span>
                                      ) : part
                                    )}
                                  </span>
                                </motion.div>
                              )}
                              
                              {/* Completion Feedback - Shows when step is done */}
                              {isCompleted && step.completionFeedback && (
                                <motion.div 
                                  className="mt-2 text-[10px] font-mono bg-primary/10 p-2.5 rounded border border-primary/30"
                                  initial={{ opacity: 0, scale: 0.95 }}
                                  animate={{ opacity: 1, scale: 1 }}
                                  transition={{ type: "spring", stiffness: 300, damping: 25 }}
                                >
                                  <div className="flex items-start gap-2">
                                    <Trophy className="w-3.5 h-3.5 text-primary flex-shrink-0 mt-0.5" />
                                    <div>
                                      <span className="text-primary font-bold block mb-1">COMPLETED!</span>
                                      <span className="text-primary/80 leading-relaxed">{step.completionFeedback}</span>
                                    </div>
                                  </div>
                                </motion.div>
                              )}
                            </div>
                          </div>
                        </motion.div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">No objectives available</p>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                {/* Mission Briefing - Combined Alert + Scenario for clarity */}
                <motion.div 
                  className="bg-gradient-to-br from-slate-900/80 to-slate-800/40 rounded-lg p-4 border border-slate-600/30"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <div className="flex items-center gap-2 mb-3">
                    <BookOpen className="w-4 h-4 text-slate-300" />
                    <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Mission Briefing</span>
                  </div>
                  {(lab as any).scenario ? (
                    <p className="text-xs text-slate-200/90 leading-relaxed">{(lab as any).scenario}</p>
                  ) : (lab as any).briefing ? (
                    <p className="text-xs text-slate-200/90 leading-relaxed">{(lab as any).briefing}</p>
                  ) : (
                    <p className="text-xs text-slate-200/90 leading-relaxed">Welcome to your security training lab. Follow the objectives panel to complete each step.</p>
                  )}
                </motion.div>

                {/* Your Goal - Clear objective */}
                <motion.div 
                  className="bg-primary/10 rounded-lg p-4 border border-primary/40"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.1 }}
                >
                  <div className="flex items-center gap-2 mb-3">
                    <Target className="w-4 h-4 text-primary" />
                    <span className="text-xs font-bold text-primary uppercase tracking-wider">Your Goal</span>
                  </div>
                  <p className="text-xs text-white/90 leading-relaxed font-medium">{lab.description}</p>
                </motion.div>

                {/* What You'll Learn - New beginner-friendly section */}
                {(lab as any).learningObjectives && (lab as any).learningObjectives.length > 0 && (
                  <motion.div 
                    className="bg-violet-950/30 rounded-lg p-4 border border-violet-500/30"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.15 }}
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <Zap className="w-4 h-4 text-violet-400" />
                      <span className="text-xs font-bold text-violet-400 uppercase tracking-wider">What You'll Learn</span>
                    </div>
                    <ul className="space-y-1.5">
                      {(lab as any).learningObjectives.map((obj: string, i: number) => (
                        <li key={i} className="text-[11px] text-violet-200/80 flex items-start gap-2">
                          <CheckCircle2 className="w-3 h-3 text-violet-400 mt-0.5 flex-shrink-0" />
                          <span>{obj}</span>
                        </li>
                      ))}
                    </ul>
                  </motion.div>
                )}

                {/* Difficulty & Time */}
                <div className="flex gap-2">
                  <div className="flex-1 bg-black/30 rounded-lg p-3 border border-white/10 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase mb-1">Difficulty</p>
                    <p className={clsx("text-sm font-bold", 
                      lab.difficulty === 'Beginner' ? 'text-primary' :
                      lab.difficulty === 'Intermediate' ? 'text-yellow-400' : 'text-destructive'
                    )}>{lab.difficulty}</p>
                  </div>
                  <div className="flex-1 bg-black/30 rounded-lg p-3 border border-white/10 text-center">
                    <p className="text-[10px] text-muted-foreground uppercase mb-1">Est. Time</p>
                    <p className="text-sm font-bold text-white">{lab.estimatedTime || '10-15 min'}</p>
                  </div>
                </div>

                {/* Getting Started Tip for beginners */}
                {lab.difficulty === 'Beginner' && (
                  <motion.div 
                    className="bg-amber-950/20 rounded-lg p-3 border border-amber-500/20"
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.2 }}
                  >
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 mt-0.5 flex-shrink-0" />
                      <p className="text-[10px] text-amber-200/80 leading-relaxed">
                        <span className="font-bold text-amber-400">Tip:</span> Switch to the Objectives tab on the left to see step-by-step instructions. Each step has a command you can type in the terminal below.
                      </p>
                    </div>
                  </motion.div>
                )}
              </div>
            )}
          </div>
        </motion.div>
        )}
        </AnimatePresence>

        {/* Center/Right Panel: Cloud Console & Terminal */}
        <div className={clsx("flex flex-col gap-4 min-h-0", showStepsPanel ? "lg:col-span-9" : "lg:col-span-1")}>
          
          {/* SOC Dashboard for SOC Labs, Identity Graph for IAM Labs, Cloud Console for other labs */}
          {SOC_CATEGORIES.includes(lab.category) ? (
            <SOCDashboard 
              labId={labId} 
              labCategory={lab.category}
              labTitle={lab.title}
              className="flex-[4] min-h-[280px]"
              selectedAlertId={selectedAlertId || undefined}
              onAlertSelect={(alertId) => setSelectedAlertId(alertId === selectedAlertId ? null : alertId)}
            />
          ) : IAM_CATEGORIES.includes(lab.category) ? (
            <div className="flex-[4] bg-gradient-to-b from-card/60 to-card/30 border border-border/50 rounded-xl p-4 relative overflow-hidden backdrop-blur-sm min-h-[280px]">
              <div className="absolute top-0 left-0 px-3 py-1.5 bg-black/60 border-r border-b border-white/10 rounded-br-lg text-[10px] font-mono text-primary uppercase tracking-widest z-20 flex items-center gap-2">
                <motion.div 
                  className="w-2 h-2 rounded-full bg-amber-500"
                  animate={{ opacity: [1, 0.4, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                />
                Identity Ecosystem
              </div>
              
              {/* Grid Background */}
              <div className="absolute inset-0 opacity-5 pointer-events-none" 
                   style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '30px 30px' }} 
              />

              <div className="h-full pt-6 overflow-y-auto pr-2">
                 <IdentityGraph labId={labId} labTitle={lab.title} />
              </div>
            </div>
          ) : (
            <div className="flex-[4] bg-gradient-to-b from-card/60 to-card/30 border border-border/50 rounded-xl p-4 relative overflow-hidden backdrop-blur-sm min-h-[280px]">
              <div className="absolute top-0 left-0 px-3 py-1.5 bg-black/60 border-r border-b border-white/10 rounded-br-lg text-[10px] font-mono text-primary uppercase tracking-widest z-20 flex items-center gap-2">
                <motion.div 
                  className="w-2 h-2 rounded-full bg-primary"
                  animate={{ opacity: [1, 0.4, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                />
                Infrastructure Status
              </div>
              
              {/* Grid Background */}
              <div className="absolute inset-0 opacity-5 pointer-events-none" 
                   style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '30px 30px' }} 
              />

              <div className="h-full pt-6 overflow-y-auto pr-2">
                 <ResourceGraph labId={labId} labTitle={lab.title} />
              </div>
            </div>
          )}

          {/* Terminal */}
          <div className="flex-[3] min-h-[220px] relative">
            <div className="absolute -top-2 left-4 px-2 bg-background z-10 text-[10px] font-mono text-primary flex items-center gap-2">
              <motion.span 
                className="w-2 h-2 rounded-full bg-primary"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 1, repeat: Infinity }}
              />
              SECURE_TERMINAL
            </div>
            <TerminalWindow 
              labId={labId} 
              className="h-full shadow-2xl border-primary/30" 
              onLabComplete={() => {
                // Mark all steps as complete when lab is done
                if (lab.steps && Array.isArray(lab.steps)) {
                  setCompletedSteps(new Set((lab.steps as any[]).map(s => s.number)));
                }
                setIsNewCompletion(true);
                setShowCompleteModal(true);
              }}
              onCommandSuccess={handleCommandSuccess}
              onStepComplete={(stepNumber) => {
                setCompletedSteps(prev => {
                  const next = new Set(prev);
                  next.add(stepNumber);
                  return next;
                });
              }}
            />
          </div>
        </div>
      </div>

      <MissionCompleteModal
        isOpen={showCompleteModal}
        onClose={() => {
          setShowCompleteModal(false);
          setIsNewCompletion(false);
        }}
        labTitle={lab.title}
        labCategory={lab.category}
        difficulty={lab.difficulty}
        elapsedTime={formatTime(elapsedTime)}
        commandStreak={commandStreak}
        isNewCompletion={isNewCompletion}
        stepsCompleted={completedSteps.size}
        totalSteps={Array.isArray(lab.steps) ? lab.steps.length : 0}
      />
    </div>
  );
}
