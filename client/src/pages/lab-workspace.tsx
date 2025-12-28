import { useLab } from "@/hooks/use-labs";
import { useRoute, Link } from "wouter";
import { TerminalWindow } from "@/components/terminal-window";
import { ResourceGraph } from "@/components/resource-graph";
import { MissionCompleteModal } from "@/components/mission-complete-modal";
import { Loader2, ArrowLeft, RefreshCw, AlertCircle, PlayCircle, BookOpen, CheckCircle2, PanelLeftClose, PanelLeft } from "lucide-react";
import { useResetLab } from "@/hooks/use-labs";
import { useState, useEffect } from "react";
import { clsx } from "clsx";
import { motion, AnimatePresence } from "framer-motion";
import { Button } from "@/components/ui/button";

export default function LabWorkspace() {
  const [, params] = useRoute("/labs/:id");
  const labId = Number(params?.id);
  const { data: lab, isLoading, error } = useLab(labId);
  const { mutate: resetLab, isPending: isResetting } = useResetLab();
  const [activeTab, setActiveTab] = useState<'brief' | 'steps'>('steps');
  const [showCompleteModal, setShowCompleteModal] = useState(false);
  const [showStepsPanel, setShowStepsPanel] = useState(() => {
    const saved = localStorage.getItem(`lab-${labId}-showSteps`);
    return saved !== null ? saved === 'true' : true;
  });

  useEffect(() => {
    localStorage.setItem(`lab-${labId}-showSteps`, String(showStepsPanel));
  }, [labId, showStepsPanel]);

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
    <div className="h-[calc(100vh-6rem)] flex flex-col space-y-4 overflow-hidden">
      {/* Workspace Header */}
      <header className="flex items-center justify-between flex-shrink-0 bg-gradient-to-r from-card/50 via-card/30 to-card/50 p-4 rounded-xl border border-primary/20 backdrop-blur-md shadow-lg shadow-primary/10">
        <div className="flex items-center gap-4">
          <Link href="/labs">
            <button className="p-2 hover:bg-primary/10 rounded-lg transition-all group hover:shadow-lg hover:shadow-primary/30">
              <ArrowLeft className="w-5 h-5 text-muted-foreground group-hover:text-primary transition-colors" />
            </button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <motion.h1 
                className="text-lg font-bold font-display tracking-wide bg-gradient-to-r from-primary via-accent to-primary bg-clip-text text-transparent"
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5 }}
              >
                {lab.title}
              </motion.h1>
              <motion.span 
                className="text-[10px] px-3 py-1 rounded-full bg-gradient-to-r from-primary/20 to-accent/20 text-primary border border-primary/40 font-mono uppercase font-bold shadow-md shadow-primary/20"
                animate={{ boxShadow: ["0 0 10px rgba(0, 255, 128, 0.2)", "0 0 20px rgba(0, 255, 128, 0.4)", "0 0 10px rgba(0, 255, 128, 0.2)"] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                Active Session
              </motion.span>
            </div>
            <p className="text-xs text-primary/60 font-mono mt-0.5">ID: LAB-{labId.toString().padStart(4, '0')}</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowStepsPanel(!showStepsPanel)}
            className="flex items-center gap-2 text-xs font-mono border-primary/30 hover:border-primary/60"
            data-testid="button-toggle-steps"
          >
            {showStepsPanel ? (
              <>
                <PanelLeftClose className="w-3.5 h-3.5" />
                HIDE_GUIDE
              </>
            ) : (
              <>
                <PanelLeft className="w-3.5 h-3.5" />
                SHOW_GUIDE
              </>
            )}
          </Button>
          <motion.button 
            onClick={() => resetLab(labId)}
            disabled={isResetting}
            className="flex items-center gap-2 px-4 py-2 text-xs font-mono text-primary hover:text-white hover:bg-gradient-to-r hover:from-primary/20 hover:to-accent/20 rounded-lg transition-all border border-primary/30 hover:border-primary/60 shadow-md hover:shadow-lg hover:shadow-primary/30"
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
          >
            <RefreshCw className={clsx("w-3.5 h-3.5", isResetting && "animate-spin")} />
            {isResetting ? "RESETTING..." : "RESET_ENV"}
          </motion.button>
        </div>
      </header>

      {/* Main Workspace Layout - Responsive Split */}
      <div className={clsx("flex-1 grid grid-cols-1 gap-6 min-h-0", showStepsPanel ? "lg:grid-cols-12" : "lg:grid-cols-1")}>
        
        {/* Left Panel: Brief & Info (3 cols) - Collapsible */}
        <AnimatePresence>
        {showStepsPanel && (
        <motion.div 
          className="lg:col-span-3 bg-card border border-border/50 rounded-xl flex flex-col overflow-hidden shadow-lg"
          initial={{ opacity: 0, x: -20, width: 0 }}
          animate={{ opacity: 1, x: 0, width: "auto" }}
          exit={{ opacity: 0, x: -20, width: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="flex border-b border-primary/20 bg-gradient-to-r from-primary/5 to-accent/5">
            <motion.button 
              onClick={() => setActiveTab('steps')}
              className={clsx(
                "flex-1 py-3 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all flex items-center justify-center gap-2",
                activeTab === 'steps' 
                  ? "border-primary text-primary bg-gradient-to-r from-primary/10 to-accent/10 shadow-lg shadow-primary/20" 
                  : "border-transparent text-muted-foreground hover:text-white hover:bg-white/5"
              )}
              whileHover={{ y: -2 }}
              whileTap={{ y: 0 }}
            >
              <motion.div
                animate={activeTab === 'steps' ? { rotate: 360 } : { rotate: 0 }}
                transition={{ duration: 0.6 }}
              >
                <CheckCircle2 className="w-4 h-4" />
              </motion.div>
              Steps
            </motion.button>
            <motion.button 
              onClick={() => setActiveTab('brief')}
              className={clsx(
                "flex-1 py-3 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-all flex items-center justify-center gap-2",
                activeTab === 'brief' 
                  ? "border-primary text-primary bg-gradient-to-r from-primary/10 to-accent/10 shadow-lg shadow-primary/20" 
                  : "border-transparent text-muted-foreground hover:text-white hover:bg-white/5"
              )}
              whileHover={{ y: -2 }}
              whileTap={{ y: 0 }}
            >
              <BookOpen className="w-4 h-4" /> Brief
            </motion.button>
          </div>
          
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
            {activeTab === 'steps' ? (
              <motion.div className="space-y-4" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.3 }}>
                <h3 className="text-primary font-bold flex items-center gap-2 mb-6 text-base">
                  <motion.div animate={{ rotate: 360 }} transition={{ duration: 3, repeat: Infinity }}>
                    <CheckCircle2 className="w-5 h-5" />
                  </motion.div>
                  Step-by-Step Guide
                </h3>
                {lab.steps && Array.isArray(lab.steps) && lab.steps.length > 0 ? (
                  <div className="space-y-3">
                    {(lab.steps as any[]).map((step, idx) => (
                      <motion.div 
                        key={step.number} 
                        className="group relative bg-gradient-to-r from-primary/5 to-accent/5 rounded-lg border border-primary/30 p-4 space-y-2 cursor-pointer transition-all hover:border-primary/60 hover:shadow-lg hover:shadow-primary/20"
                        initial={{ opacity: 0, x: -20 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.3, delay: idx * 0.05 }}
                        whileHover={{ y: -2 }}
                      >
                        {/* Subtle glow effect */}
                        <div className="absolute inset-0 rounded-lg bg-gradient-to-r from-primary/10 to-accent/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
                        
                        <div className="relative flex items-center gap-3">
                          <motion.div 
                            className="w-7 h-7 rounded-full bg-gradient-to-br from-primary to-accent border-2 border-primary/60 flex items-center justify-center text-xs font-bold text-background shadow-lg shadow-primary/40"
                            animate={{ boxShadow: ["0 0 10px rgba(0, 255, 128, 0.3)", "0 0 20px rgba(0, 255, 128, 0.5)"] }}
                            transition={{ duration: 2, repeat: Infinity }}
                          >
                            {step.number}
                          </motion.div>
                          <h4 className="text-sm font-bold text-white">{step.title}</h4>
                        </div>
                        <p className="text-xs text-muted-foreground ml-10 relative">{step.description}</p>
                        <motion.div 
                          className="ml-10 text-xs text-primary/80 font-mono bg-gradient-to-r from-black/60 to-black/40 p-3 rounded border border-primary/30 relative"
                          whileHover={{ borderColor: 'rgba(0, 255, 128, 0.6)' }}
                        >
                          <span className="text-accent">💡</span> {step.hint}
                        </motion.div>
                      </motion.div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-sm">No steps available</p>
                )}
              </motion.div>
            ) : (
              <div className="prose prose-invert prose-sm prose-p:text-muted-foreground prose-headings:text-white prose-headings:font-display">
                <h3 className="text-primary flex items-center gap-2">
                  <PlayCircle className="w-4 h-4" /> Objective
                </h3>
                <p>{lab.description}</p>
                
                <h4 className="text-white mt-6 mb-2 text-xs uppercase tracking-widest font-bold opacity-70">Scenario Intel</h4>
                <div className="bg-black/30 p-4 rounded-lg border border-white/5 text-xs font-mono leading-relaxed text-gray-400">
                   <p>Our automated scanners detected a misconfiguration in the cloud infrastructure shown in the console.</p>
                   <p className="mt-2 text-primary/80">
                     &gt; TARGET: Identify vulnerable resource.<br/>
                     &gt; ACTION: Use the terminal to patch the vulnerability.<br/>
                     &gt; HINT: Check bucket policies or security group rules.
                   </p>
                </div>
              </div>
            )}
          </div>
        </motion.div>
        )}
        </AnimatePresence>

        {/* Center/Right Panel: Cloud Console & Terminal */}
        <div className={clsx("flex flex-col gap-6 min-h-0", showStepsPanel ? "lg:col-span-9" : "lg:col-span-1")}>
          
          {/* Top: Cloud Console Visualization */}
          <div className="flex-[4] bg-card/50 border border-border/50 rounded-xl p-6 relative overflow-hidden backdrop-blur-sm min-h-[300px]">
             <div className="absolute top-0 left-0 px-4 py-2 bg-black/40 border-r border-b border-white/10 rounded-br-xl text-[10px] font-mono text-muted-foreground uppercase tracking-widest z-20">
               Cloud Infrastructure View
             </div>
             
             {/* Grid Background */}
             <div className="absolute inset-0 opacity-10 pointer-events-none" 
                  style={{ backgroundImage: 'linear-gradient(#fff 1px, transparent 1px), linear-gradient(90deg, #fff 1px, transparent 1px)', backgroundSize: '40px 40px' }} 
             />

             {/* Graph Content */}
             <div className="h-full pt-8 overflow-y-auto pr-2 custom-scrollbar">
                <ResourceGraph labId={labId} />
             </div>
          </div>

          {/* Bottom: Terminal */}
          <div className="flex-[3] min-h-[250px] relative">
             <div className="absolute -top-3 left-4 px-2 bg-background z-10 text-xs font-mono text-primary flex items-center gap-2">
               <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
               LIVE_CONNECTION
             </div>
             <TerminalWindow 
               labId={labId} 
               className="h-full shadow-2xl border-primary/20" 
               onLabComplete={() => setShowCompleteModal(true)}
             />
          </div>
        </div>
      </div>

      <MissionCompleteModal
        isOpen={showCompleteModal}
        onClose={() => setShowCompleteModal(false)}
        labTitle={lab.title}
        labCategory={lab.category}
        difficulty={lab.difficulty}
      />
    </div>
  );
}
