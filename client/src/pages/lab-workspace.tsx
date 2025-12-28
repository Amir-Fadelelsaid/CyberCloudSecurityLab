import { useLab } from "@/hooks/use-labs";
import { useRoute, Link } from "wouter";
import { TerminalWindow } from "@/components/terminal-window";
import { ResourceGraph } from "@/components/resource-graph";
import { Loader2, ArrowLeft, RefreshCw, AlertCircle, PlayCircle, BookOpen } from "lucide-react";
import { useResetLab } from "@/hooks/use-labs";
import { useState } from "react";
import { clsx } from "clsx";
import { motion } from "framer-motion";

export default function LabWorkspace() {
  const [, params] = useRoute("/labs/:id");
  const labId = Number(params?.id);
  const { data: lab, isLoading, error } = useLab(labId);
  const { mutate: resetLab, isPending: isResetting } = useResetLab();
  const [activeTab, setActiveTab] = useState<'console' | 'brief'>('console');

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
      <header className="flex items-center justify-between flex-shrink-0 bg-card/30 p-4 rounded-xl border border-border/50 backdrop-blur-md">
        <div className="flex items-center gap-4">
          <Link href="/labs">
            <button className="p-2 hover:bg-white/5 rounded-lg transition-colors group">
              <ArrowLeft className="w-5 h-5 text-muted-foreground group-hover:text-white" />
            </button>
          </Link>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-lg font-bold font-display tracking-wide">{lab.title}</h1>
              <span className="text-[10px] px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20 font-mono uppercase">
                Active Session
              </span>
            </div>
            <p className="text-xs text-muted-foreground font-mono mt-0.5">ID: LAB-{labId.toString().padStart(4, '0')}</p>
          </div>
        </div>

        <button 
          onClick={() => resetLab(labId)}
          disabled={isResetting}
          className="flex items-center gap-2 px-3 py-1.5 text-xs font-mono text-muted-foreground hover:text-white hover:bg-white/5 rounded-lg transition-colors border border-transparent hover:border-white/10"
        >
          <RefreshCw className={clsx("w-3.5 h-3.5", isResetting && "animate-spin")} />
          {isResetting ? "RESETTING..." : "RESET_ENV"}
        </button>
      </header>

      {/* Main Workspace Layout - Responsive Split */}
      <div className="flex-1 grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-0">
        
        {/* Left Panel: Brief & Info (3 cols) */}
        <div className="lg:col-span-3 bg-card border border-border/50 rounded-xl flex flex-col overflow-hidden shadow-lg">
          <div className="flex border-b border-border/50">
            <button 
              onClick={() => setActiveTab('brief')}
              className={clsx(
                "flex-1 py-3 text-xs font-bold uppercase tracking-wider font-mono border-b-2 transition-colors flex items-center justify-center gap-2",
                activeTab === 'brief' ? "border-primary text-primary bg-primary/5" : "border-transparent text-muted-foreground hover:text-white"
              )}
            >
              <BookOpen className="w-4 h-4" /> Mission Brief
            </button>
          </div>
          
          <div className="flex-1 overflow-y-auto p-6 space-y-6">
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
          </div>
        </div>

        {/* Center/Right Panel: Cloud Console & Terminal (9 cols) */}
        <div className="lg:col-span-9 flex flex-col gap-6 min-h-0">
          
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
             <TerminalWindow labId={labId} className="h-full shadow-2xl border-primary/20" />
          </div>
        </div>
      </div>
    </div>
  );
}
