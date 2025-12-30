import { Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import { Terminal, Shield, BarChart3, LogOut, LayoutDashboard, Award, Trophy, GraduationCap, Users } from "lucide-react";
import { clsx } from "clsx";

type LevelInfo = {
  level: number;
  title: string;
  nextLevel: number | null;
  progress: number;
  completedLabs: number;
};

interface LayoutProps {
  children: React.ReactNode;
}

export function Layout({ children }: LayoutProps) {
  const [location] = useLocation();
  const { user, logout } = useAuth();
  
  const { data: levelInfo } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level"],
    enabled: !!user
  });

  const navItems = [
    { icon: LayoutDashboard, label: "Mission Control", href: "/" },
    { icon: Shield, label: "Active Labs", href: "/labs" },
    { icon: Trophy, label: "Leaderboard", href: "/leaderboard" },
    { icon: Award, label: "Badges", href: "/badges" },
    { icon: GraduationCap, label: "Certificates", href: "/certificates" },
    { icon: BarChart3, label: "My Progress", href: "/progress" },
    { icon: Users, label: "Community", href: "/community" },
  ];

  if (!user) {
    return <div className="min-h-screen bg-background">{children}</div>;
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground font-sans overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 border-r border-border bg-card/50 backdrop-blur-sm hidden md:flex flex-col z-20 shadow-2xl shadow-primary/5">
        <div className="p-6 border-b border-border/50">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-md rounded-full group-hover:bg-primary/40 transition-all"></div>
              <Terminal className="w-8 h-8 text-primary relative z-10" />
            </div>
            <div>
              <h1 className="font-display font-bold text-base tracking-wide text-white">CLOUDSHIELD<span className="text-primary">LAB</span></h1>
              <p className="text-[10px] text-muted-foreground uppercase tracking-widest">Security Training v1.0</p>
            </div>
          </Link>
        </div>

        {/* User info section - moved up for easy access */}
        <div className="px-4 py-4 border-b border-border/50 space-y-2">
          <Link href="/badges">
            <div className="flex items-center gap-3 px-4 py-3 rounded-lg bg-black/20 border border-white/5 hover:border-primary/30 transition-colors cursor-pointer group">
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary font-bold font-mono border border-primary/30 group-hover:bg-primary/30 transition-colors">
                {levelInfo?.level || 0}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-white truncate">{user.firstName || "User"}</p>
                <p className="text-[10px] text-muted-foreground truncate font-mono">Level {levelInfo?.level || 0} {levelInfo?.title || "Recruit"}</p>
              </div>
            </div>
          </Link>
          <button
            onClick={() => logout()}
            className="w-full flex items-center gap-3 px-4 py-2 text-xs font-mono text-destructive hover:bg-destructive/10 rounded-lg transition-colors border border-transparent hover:border-destructive/20"
            data-testid="button-logout"
          >
            <LogOut className="w-4 h-4" />
            <span>TERMINATE_SESSION</span>
          </button>
        </div>

        <nav className="flex-1 px-4 py-6 space-y-2 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = location === item.href || (item.href !== '/' && location.startsWith(item.href));
            const Icon = item.icon;
            return (
              <Link key={item.href} href={item.href}>
                <div
                  className={clsx(
                    "flex items-center gap-3 px-4 py-3 rounded-lg transition-all duration-200 cursor-pointer group border border-transparent",
                    isActive
                      ? "bg-primary/10 text-primary border-primary/20 shadow-[0_0_15px_-3px_rgba(0,255,128,0.2)]"
                      : "text-muted-foreground hover:text-white hover:bg-white/5 hover:border-white/10"
                  )}
                >
                  <Icon className={clsx("w-5 h-5 transition-transform group-hover:scale-110", isActive && "animate-pulse")} />
                  <span className="font-mono text-sm tracking-wide font-medium">{item.label}</span>
                  {isActive && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_2px_rgba(0,255,128,0.6)]" />}
                </div>
              </Link>
            );
          })}
        </nav>

        {/* Creator credit at bottom */}
        <div className="px-4 py-3 border-t border-border/30 text-center">
          <p className="text-[10px] text-muted-foreground font-mono">Created by</p>
          <p className="text-xs text-primary/80 font-medium">Amir Fadelelsaid</p>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto relative">
        {/* Background Grid Pattern */}
        <div className="absolute inset-0 pointer-events-none z-0 opacity-20"
             style={{ 
               backgroundImage: 'radial-gradient(circle at center, #00ff80 1px, transparent 1px)', 
               backgroundSize: '40px 40px' 
             }} 
        />
        <div className="relative z-10 p-6 md:p-12 max-w-7xl mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
