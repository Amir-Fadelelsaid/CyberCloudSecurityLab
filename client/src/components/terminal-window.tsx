import { useState, useRef, useEffect } from "react";
import { useTerminal } from "@/hooks/use-terminal";
import { Loader2, Terminal as TerminalIcon, ShieldCheck, AlertTriangle } from "lucide-react";
import { clsx } from "clsx";

interface TerminalWindowProps {
  labId: number;
  className?: string;
  onLabComplete?: () => void;
}

interface LogEntry {
  type: "command" | "output" | "system" | "success" | "error";
  content: string;
}

export function TerminalWindow({ labId, className, onLabComplete }: TerminalWindowProps) {
  const [input, setInput] = useState("");
  const [history, setHistory] = useState<LogEntry[]>([
    { type: "system", content: "Connected to secure shell..." },
    { type: "system", content: "Authenticating user... Access Granted." },
    { type: "system", content: "Type 'help' for available commands." },
  ]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  const { mutate: executeCommand, isPending } = useTerminal();

  // Auto-scroll to bottom
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [history]);

  // Focus input on click
  const handleContainerClick = () => {
    inputRef.current?.focus();
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isPending) return;

    const command = input.trim();
    setHistory(prev => [...prev, { type: "command", content: command }]);
    setInput("");

    executeCommand(
      { command, labId },
      {
        onSuccess: (data) => {
          if (data.success) {
            setHistory(prev => [...prev, { type: "success", content: data.output }]);
            if (data.labCompleted) {
              setHistory(prev => [...prev, { type: "system", content: ">>> MISSION ACCOMPLISHED: VULNERABILITY PATCHED <<<" }]);
              setTimeout(() => onLabComplete?.(), 1500);
            }
          } else {
             setHistory(prev => [...prev, { type: "output", content: data.output }]);
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
        "flex flex-col bg-black/90 rounded-xl border border-border/50 shadow-2xl overflow-hidden font-mono text-sm h-[500px]", 
        className
      )}
      onClick={handleContainerClick}
    >
      {/* Terminal Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-white/5 border-b border-white/5 select-none">
        <div className="flex items-center gap-2 text-muted-foreground">
          <TerminalIcon className="w-4 h-4" />
          <span className="text-xs tracking-wider">SECURE_SHELL_V2.0</span>
        </div>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/50" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/50" />
          <div className="w-2.5 h-2.5 rounded-full bg-green-500/50" />
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex-1 p-4 overflow-y-auto space-y-2 cursor-text" style={{ fontFamily: 'Fira Code, monospace' }}>
        {history.map((entry, i) => (
          <div key={i} className={clsx("break-words leading-relaxed", {
            "text-primary font-bold": entry.type === "command",
            "text-gray-300": entry.type === "output",
            "text-blue-400 italic opacity-80": entry.type === "system",
            "text-green-400 font-semibold": entry.type === "success",
            "text-red-400": entry.type === "error",
          })}>
            {entry.type === "command" && <span className="text-muted-foreground mr-2 select-none">$</span>}
            {entry.type === "success" && <ShieldCheck className="w-4 h-4 inline mr-2 -mt-1" />}
            {entry.type === "error" && <AlertTriangle className="w-4 h-4 inline mr-2 -mt-1" />}
            {entry.content}
          </div>
        ))}

        {/* Input Line */}
        <div className="flex items-center text-primary group">
          <span className="text-muted-foreground mr-2 select-none">root@cloud-lab:~$</span>
          <form onSubmit={handleSubmit} className="flex-1 relative">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              className="w-full bg-transparent border-none outline-none text-primary placeholder:text-primary/30"
              autoFocus
              spellCheck="false"
              autoComplete="off"
              disabled={isPending}
            />
            {isPending && <Loader2 className="absolute right-0 top-0 w-4 h-4 animate-spin opacity-50" />}
          </form>
        </div>
        <div ref={bottomRef} />
      </div>
    </div>
  );
}
