import { Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import { useState } from "react";
import { 
  Terminal, Shield, BarChart3, LogOut, LayoutDashboard, Award, Trophy, 
  GraduationCap, Users, ChevronLeft, ChevronRight, User
} from "lucide-react";
import { clsx } from "clsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

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
  const [isExpanded, setIsExpanded] = useState(false);
  
  const { data: levelInfo } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level"],
    enabled: !!user
  });

  const navItems = [
    { icon: LayoutDashboard, label: "Dashboard", href: "/" },
    { icon: Shield, label: "Labs", href: "/labs" },
    { icon: Trophy, label: "Leaderboard", href: "/leaderboard" },
    { icon: Award, label: "Badges", href: "/badges" },
    { icon: GraduationCap, label: "Certificates", href: "/certificates" },
    { icon: BarChart3, label: "Progress", href: "/progress" },
    { icon: Users, label: "Community", href: "/community" },
  ];

  if (!user) {
    return <div className="min-h-screen bg-background">{children}</div>;
  }

  return (
    <div className="flex min-h-screen bg-background text-foreground font-sans overflow-hidden">
      {/* Slim Icon Sidebar - SentinelOne style */}
      <aside 
        className={clsx(
          "border-r border-border bg-card hidden md:flex flex-col z-20 transition-all duration-200",
          isExpanded ? "w-56" : "w-16"
        )}
      >
        {/* Logo */}
        <div className="h-14 flex items-center justify-center border-b border-border">
          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-primary/20 flex items-center justify-center">
              <Terminal className="w-5 h-5 text-primary" />
            </div>
            {isExpanded && (
              <span className="text-sm font-bold text-foreground">CloudShield</span>
            )}
          </Link>
        </div>

        {/* User Profile - Compact */}
        <div className="p-2 border-b border-border">
          <Link href="/badges">
            <div className={clsx(
              "flex items-center gap-2 p-2 rounded-md hover:bg-secondary/50 transition-colors cursor-pointer",
              isExpanded ? "justify-start" : "justify-center"
            )}>
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center text-primary text-xs font-bold border border-primary/30">
                {levelInfo?.level || 0}
              </div>
              {isExpanded && (
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-foreground truncate">{user.firstName || "User"}</p>
                  <p className="text-[10px] text-muted-foreground truncate">Lv.{levelInfo?.level || 0} {levelInfo?.title || "Recruit"}</p>
                </div>
              )}
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-2 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            const isActive = location === item.href || (item.href !== '/' && location.startsWith(item.href));
            const Icon = item.icon;
            
            const navButton = (
              <Link key={item.href} href={item.href}>
                <div
                  className={clsx(
                    "flex items-center gap-3 p-2 rounded-md transition-all duration-150 cursor-pointer",
                    isExpanded ? "justify-start" : "justify-center",
                    isActive
                      ? "bg-primary/15 text-primary border-l-2 border-primary"
                      : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
                  )}
                  data-testid={`nav-${item.label.toLowerCase()}`}
                >
                  <Icon className="w-5 h-5 flex-shrink-0" />
                  {isExpanded && (
                    <span className="text-sm font-medium">{item.label}</span>
                  )}
                </div>
              </Link>
            );

            if (!isExpanded) {
              return (
                <Tooltip key={item.href} delayDuration={0}>
                  <TooltipTrigger asChild>
                    {navButton}
                  </TooltipTrigger>
                  <TooltipContent side="right" className="bg-popover border-border">
                    {item.label}
                  </TooltipContent>
                </Tooltip>
              );
            }

            return navButton;
          })}
        </nav>

        {/* Bottom Actions */}
        <div className="p-2 border-t border-border space-y-1">
          {/* Logout */}
          <Tooltip delayDuration={0}>
            <TooltipTrigger asChild>
              <button
                onClick={() => logout()}
                className={clsx(
                  "w-full flex items-center gap-3 p-2 rounded-md text-muted-foreground hover:text-destructive hover:bg-destructive/10 transition-colors",
                  isExpanded ? "justify-start" : "justify-center"
                )}
                data-testid="button-logout"
              >
                <LogOut className="w-5 h-5" />
                {isExpanded && <span className="text-sm">Logout</span>}
              </button>
            </TooltipTrigger>
            {!isExpanded && (
              <TooltipContent side="right" className="bg-popover border-border">
                Logout
              </TooltipContent>
            )}
          </Tooltip>

          {/* Expand/Collapse Toggle */}
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className={clsx(
              "w-full flex items-center gap-3 p-2 rounded-md text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors",
              isExpanded ? "justify-start" : "justify-center"
            )}
            data-testid="button-toggle-sidebar"
          >
            {isExpanded ? (
              <>
                <ChevronLeft className="w-5 h-5" />
                <span className="text-sm">Collapse</span>
              </>
            ) : (
              <ChevronRight className="w-5 h-5" />
            )}
          </button>
        </div>

        {/* Creator Credit */}
        {isExpanded && (
          <div className="px-3 py-2 border-t border-border text-center">
            <p className="text-[10px] text-muted-foreground">by Amir Fadelelsaid</p>
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-auto bg-background">
        <div className="p-6 md:p-8 max-w-[1600px] mx-auto">
          {children}
        </div>
      </main>
    </div>
  );
}
