import { useState, useRef, useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { Loader2, Terminal as TerminalIcon, ShieldCheck, AlertTriangle, Sparkles, Trophy, Zap } from "lucide-react";
import { clsx } from "clsx";
import { motion, AnimatePresence } from "framer-motion";

interface TerminalWindowProps {
  labId: number;
  className?: string;
  onLabComplete?: () => void;
  onCommandSuccess?: () => void;
  onStepComplete?: (stepNumber: number) => void;
}

interface LogEntry {
  type: "command" | "output" | "system" | "success" | "error" | "hint" | "achievement";
  content: string;
}

const COMMAND_SUGGESTIONS: Record<string, string[]> = {
  "aws": ["aws s3", "aws ec2", "aws iam", "aws cloudtrail"],
  "aws s3": ["aws s3 ls", "aws s3 check-", "aws s3 block-", "aws s3 get-policy"],
  "aws ec2": ["aws ec2 describe-", "aws ec2 restrict-", "aws ec2 fix-"],
  "aws iam": ["aws iam list-", "aws iam revoke-", "aws iam check-"],
  "scan": [],
  "help": [],
};

const DISCOVERY_TIPS = [
  "Try 'help' to see available commands",
  "Use 'scan' to identify vulnerabilities",
  "Explore with 'aws s3 ls' or 'aws ec2 describe-'",
  "Check policies with 'get-policy' commands",
];

const ACHIEVEMENTS = [
  { trigger: "scan", title: "Recon Master", desc: "First security scan completed!" },
  { trigger: "fix", title: "Patcher", desc: "Applied your first security fix!" },
  { trigger: "block-public", title: "Access Denied", desc: "Blocked public access!" },
  { trigger: "restrict", title: "Lockdown", desc: "Restricted network access!" },
  { trigger: "revoke", title: "Credential Guardian", desc: "Revoked compromised credentials!" },
];

export function TerminalWindow({ labId, className, onLabComplete, onCommandSuccess, onStepComplete }: TerminalWindowProps) {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<LogEntry[]>([
    { type: "system", content: "CLOUDSHIELD TERMINAL v2.0 - Secure Shell Initialized" },
    { type: "hint", content: "Type 'help' to see commands, or 'scan' to analyze the environment" },
  ]);
  const [commandHistory, setCommandHistory] = useState<string[]>([]);
  const [historyIndex, setHistoryIndex] = useState(-1);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [selectedSuggestion, setSelectedSuggestion] = useState(0);
  const [commandCount, setCommandCount] = useState(0);
  const [earnedAchievements, setEarnedAchievements] = useState<Set<string>>(new Set());
  const [showAchievement, setShowAchievement] = useState<{title: string, desc: string} | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  const { mutate: executeCommand, isPending } = useTerminal();

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  // Update suggestions based on input
  useEffect(() => {
    if (!input.trim()) {
      setSuggestions([]);
      return;
    }
    
    const inputLower = input.toLowerCase().trim();
    const matchingSuggestions: string[] = [];
    
    // Check for prefix matches
    for (const [prefix, subs] of Object.entries(COMMAND_SUGGESTIONS)) {
      if (prefix.startsWith(inputLower) && prefix !== inputLower) {
        matchingSuggestions.push(prefix);
      }
      if (inputLower.startsWith(prefix) && subs.length > 0) {
        subs.forEach(s => {
          if (s.startsWith(inputLower) && s !== inputLower) {
            matchingSuggestions.push(s);
          }
        });
      }
    }
    
    setSuggestions(matchingSuggestions.slice(0, 4));
    setSelectedSuggestion(0);
  }, [input]);

  // Focus input on click
  const handleContainerClick = () => {
    inputRef.current?.focus();
  };

  // Check for achievements
  const checkAchievements = (command: string) => {
    for (const ach of ACHIEVEMENTS) {
      if (command.includes(ach.trigger) && !earnedAchievements.has(ach.trigger)) {
        setEarnedAchievements(prev => new Set(Array.from(prev).concat([ach.trigger])));
        setShowAchievement({ title: ach.title, desc: ach.desc });
        setHistory(prev => [...prev, { type: "achievement", content: `Achievement Unlocked: ${ach.title}` }]);
        setTimeout(() => setShowAchievement(null), 3000);
        break;
      }
    }
  };

  // Show discovery tip periodically
  useEffect(() => {
    if (commandCount > 0 && commandCount % 5 === 0 && commandCount < 20) {
      const tip = DISCOVERY_TIPS[Math.floor(Math.random() * DISCOVERY_TIPS.length)];
      setHistory(prev => [...prev, { type: "hint", content: `TIP: ${tip}` }]);
    }
  }, [commandCount]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    // Tab completion
    if (e.key === "Tab" && suggestions.length > 0) {
      e.preventDefault();
      setInput(suggestions[selectedSuggestion] + " ");
      setSuggestions([]);
    }
    
    // Arrow keys for suggestions or history
    if (e.key === "ArrowDown") {
      if (suggestions.length > 0) {
        e.preventDefault();
        setSelectedSuggestion(prev => Math.min(prev + 1, suggestions.length - 1));
      } else if (historyIndex > 0) {
        // Navigate forward in history (towards more recent commands)
        e.preventDefault();
        const newIndex = historyIndex - 1;
        setHistoryIndex(newIndex);
        setInput(commandHistory[commandHistory.length - 1 - newIndex] || "");
      } else if (historyIndex === 0) {
        // Return to empty input
        e.preventDefault();
        setHistoryIndex(-1);
        setInput("");
      }
    }
    
    if (e.key === "ArrowUp") {
      if (suggestions.length > 0) {
        e.preventDefault();
        setSelectedSuggestion(prev => Math.max(prev - 1, 0));
      } else if (commandHistory.length > 0) {
        // Navigate backward in history (towards older commands)
        e.preventDefault();
        const newIndex = historyIndex < commandHistory.length - 1 ? historyIndex + 1 : historyIndex;
        setHistoryIndex(newIndex);
        setInput(commandHistory[commandHistory.length - 1 - newIndex] || "");
      }
    }
    
    // Escape to clear suggestions and reset history
    if (e.key === "Escape") {
      setSuggestions([]);
      setHistoryIndex(-1);
      setInput("");
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isPending) return;

    const command = input.trim();
    setHistory(prev => [...prev, { type: "command", content: command }]);
    setCommandHistory(prev => [...prev, command]);
    setHistoryIndex(-1);
    setInput("");
    setSuggestions([]);
    setCommandCount(prev => prev + 1);

    // Check for achievements
    checkAchievements(command);

    executeCommand(
      { command, labId },
      {
        onSuccess: (data) => {
          if (data.success) {
            setHistory(prev => [...prev, { type: "success", content: data.output }]);
            onCommandSuccess?.();
            if (data.labCompleted) {
              setHistory(prev => [...prev, { 
                type: "system", 
                content: ">>> MISSION ACCOMPLISHED - ALL VULNERABILITIES PATCHED <<<" 
              }]);
              setTimeout(() => onLabComplete?.(), 1500);
            }
          } else {
            setHistory(prev => [...prev, { type: "output", content: data.output }]);
          }
          // Auto-complete step if server detected a matching command
          if (data.completedStep) {
            onStepComplete?.(data.completedStep);
          }
        },
        onError: (error) => {
          setHistory(prev => [...prev, { type: "error", content: `Error: ${error.message}` }]);
        }
      }
    );
  };

  return (
    <div 
      className={clsx(
        "flex flex-col bg-gradient-to-b from-black to-gray-950 rounded-xl border shadow-2xl overflow-hidden font-mono text-sm h-full relative", 
        className
      )}
      onClick={handleContainerClick}
    >
      {/* Achievement Popup */}
      <AnimatePresence>
        {showAchievement && (
          <motion.div
            className="absolute top-4 right-4 z-50 bg-gradient-to-r from-amber-500/20 to-yellow-500/20 border border-amber-500/50 rounded-lg p-4 shadow-lg shadow-amber-500/20"
            initial={{ opacity: 0, y: -20, scale: 0.9 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -20, scale: 0.9 }}
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-gradient-to-br from-amber-400 to-yellow-500 flex items-center justify-center">
                <Trophy className="w-5 h-5 text-black" />
              </div>
              <div>
                <p className="text-amber-400 font-bold text-sm">{showAchievement.title}</p>
                <p className="text-amber-200/70 text-xs">{showAchievement.desc}</p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-black/60 border-b border-white/10 select-none">
        <div className="flex items-center gap-2 text-muted-foreground">
          <TerminalIcon className="w-4 h-4 text-primary" />
          <span className="text-xs tracking-wider text-primary/80">CLOUDSHIELD_TERMINAL</span>
          <span className="text-[10px] text-muted-foreground">v2.0</span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
            <Zap className="w-3 h-3 text-amber-400" />
            <span>{commandCount} cmds</span>
          </div>
          <div className="flex gap-1.5">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
            <motion.div 
              className="w-2.5 h-2.5 rounded-full bg-green-500"
              animate={{ opacity: [1, 0.5, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
          </div>
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex-1 p-4 overflow-y-auto space-y-1.5 cursor-text" style={{ fontFamily: 'Fira Code, monospace' }}>
        {history.map((entry, i) => (
          <motion.div 
            key={i} 
            className={clsx("break-words leading-relaxed", {
              "text-primary font-bold": entry.type === "command",
              "text-gray-300 pl-2": entry.type === "output",
              "text-blue-400 italic opacity-80 text-xs": entry.type === "system",
              "text-green-400 font-semibold pl-2": entry.type === "success",
              "text-red-400 pl-2": entry.type === "error",
              "text-cyan-400/70 text-xs italic pl-2": entry.type === "hint",
              "text-amber-400 font-bold": entry.type === "achievement",
            })}
            initial={entry.type === "success" || entry.type === "achievement" ? { scale: 0.95, opacity: 0 } : { opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.2 }}
          >
            {entry.type === "command" && (
              <span className="text-muted-foreground mr-2 select-none">
                <span className="text-cyan-500">root</span>
                <span className="text-white">@</span>
                <span className="text-primary">cloud-lab</span>
                <span className="text-white">:~$</span>
              </span>
            )}
            {entry.type === "success" && <ShieldCheck className="w-4 h-4 inline mr-2 -mt-1 text-primary" />}
            {entry.type === "error" && <AlertTriangle className="w-4 h-4 inline mr-2 -mt-1" />}
            {entry.type === "hint" && <Sparkles className="w-3 h-3 inline mr-1 -mt-0.5" />}
            {entry.type === "achievement" && <Trophy className="w-4 h-4 inline mr-2 -mt-1 text-amber-400" />}
            {entry.content}
          </motion.div>
        ))}

        {/* Suggestions Popup */}
        <AnimatePresence>
          {suggestions.length > 0 && (
            <motion.div 
              className="bg-black/90 border border-primary/30 rounded-lg p-1 mb-2 inline-block"
              initial={{ opacity: 0, y: 5 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 5 }}
            >
              <p className="text-[10px] text-muted-foreground px-2 mb-1">Tab to complete, arrows to navigate</p>
              {suggestions.map((s, idx) => (
                <div 
                  key={s}
                  className={clsx(
                    "px-2 py-1 rounded text-xs cursor-pointer",
                    idx === selectedSuggestion ? "bg-primary/20 text-primary" : "text-muted-foreground hover:bg-white/5"
                  )}
                  onClick={() => {
                    setInput(s + " ");
                    setSuggestions([]);
                    inputRef.current?.focus();
                  }}
                >
                  {s}
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Input Line */}
        <div className="flex items-center text-primary group pt-1">
          <span className="mr-2 select-none">
            <span className="text-cyan-500">root</span>
            <span className="text-white">@</span>
            <span className="text-primary">cloud-lab</span>
            <span className="text-white">:~$</span>
          </span>
          <form onSubmit={handleSubmit} className="flex-1 relative">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-full bg-transparent border-none outline-none text-primary placeholder:text-primary/30 caret-primary"
              autoFocus
              spellCheck="false"
              autoComplete="off"
              disabled={isPending}
              placeholder={commandCount === 0 ? "type a command..." : ""}
              data-testid="input-terminal"
            />
            {isPending && (
              <div className="absolute right-0 top-0 flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                <span className="text-xs text-muted-foreground">processing...</span>
              </div>
            )}
          </form>
        </div>
        <div ref={bottomRef} />
      </div>

      {/* Quick Actions Bar */}
      <div className="px-4 py-2 bg-black/40 border-t border-white/5 flex items-center gap-2 overflow-x-auto">
        <span className="text-[10px] text-muted-foreground whitespace-nowrap">Quick:</span>
        {["scan", "help", "aws s3 ls", "aws ec2 describe-"].map(cmd => (
          <button
            key={cmd}
            onClick={() => {
              setInput(cmd);
              inputRef.current?.focus();
            }}
            className="px-2 py-0.5 text-[10px] font-mono bg-primary/10 text-primary/80 rounded border border-primary/20 hover:bg-primary/20 hover:text-primary transition-colors whitespace-nowrap"
            data-testid={`button-quick-${cmd.replace(/\s+/g, '-')}`}
          >
            {cmd}
          </button>
        ))}
      </div>
    </div>
  );
}
