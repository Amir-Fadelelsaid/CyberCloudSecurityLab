import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar";
import { Badge } from "@/components/ui/badge";
import { Trophy, Medal, Award, Users, Zap, TrendingUp, Crown, Shield, Target } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useAuth } from "@/hooks/use-auth";

type LeaderboardEntry = {
  rank: number;
  id: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  profileImageUrl: string | null;
  completedLabs: number;
  level: number;
  levelTitle: string;
};

const getDisplayName = (entry: LeaderboardEntry) => {
  if (entry.displayName) return entry.displayName;
  if (entry.firstName) return `${entry.firstName} ${entry.lastName || ""}`.trim();
  return "Anonymous";
};

export default function Leaderboard() {
  const { user } = useAuth();
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([]);
  const [isLive, setIsLive] = useState(false);

  const { data: initialData, isLoading } = useQuery<LeaderboardEntry[]>({
    queryKey: ["/api/leaderboard"],
  });

  useEffect(() => {
    if (initialData) {
      setLeaderboard(initialData);
    }
  }, [initialData]);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/leaderboard`;
    
    const ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
      setIsLive(true);
    };
    
    ws.onmessage = (event) => {
      try {
        const message = JSON.parse(event.data);
        if (message.type === "leaderboard_update") {
          setLeaderboard(message.data);
        }
      } catch (e) {
        console.error("Failed to parse WebSocket message:", e);
      }
    };
    
    ws.onclose = () => {
      setIsLive(false);
    };
    
    ws.onerror = () => {
      setIsLive(false);
    };
    
    return () => {
      ws.close();
    };
  }, []);

  const getRankIcon = (rank: number) => {
    switch (rank) {
      case 1:
        return <Crown className="w-6 h-6 text-yellow-400" />;
      case 2:
        return <Medal className="w-6 h-6 text-gray-300" />;
      case 3:
        return <Award className="w-6 h-6 text-amber-600" />;
      default:
        return <span className="w-6 h-6 flex items-center justify-center text-muted-foreground font-mono">{rank}</span>;
    }
  };

  const getRankBgClass = (rank: number) => {
    switch (rank) {
      case 1:
        return "bg-gradient-to-r from-yellow-500/20 to-yellow-600/10 border-yellow-500/30";
      case 2:
        return "bg-gradient-to-r from-gray-400/20 to-gray-500/10 border-gray-400/30";
      case 3:
        return "bg-gradient-to-r from-amber-600/20 to-amber-700/10 border-amber-600/30";
      default:
        return "bg-card/50 border-border/50";
    }
  };

  const getLevelIcon = (level: number) => {
    if (level >= 6) return <Crown className="w-4 h-4" />;
    if (level >= 5) return <Shield className="w-4 h-4" />;
    if (level >= 4) return <Target className="w-4 h-4" />;
    return <Zap className="w-4 h-4" />;
  };

  const getLevelColor = (level: number) => {
    if (level >= 6) return "text-yellow-400 bg-yellow-400/20 border-yellow-400/30";
    if (level >= 5) return "text-purple-400 bg-purple-400/20 border-purple-400/30";
    if (level >= 4) return "text-blue-400 bg-blue-400/20 border-blue-400/30";
    if (level >= 3) return "text-green-400 bg-green-400/20 border-green-400/30";
    if (level >= 2) return "text-cyan-400 bg-cyan-400/20 border-cyan-400/30";
    return "text-muted-foreground bg-muted/20 border-muted/30";
  };

  const currentUserRank = leaderboard.find(e => e.id === user?.id);

  if (isLoading) {
    return (
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-display font-bold text-white">Leaderboard</h1>
            <p className="text-muted-foreground mt-1">Loading rankings...</p>
          </div>
        </div>
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map((i) => (
            <div key={i} className="h-20 bg-card/30 rounded-lg animate-pulse" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-display font-bold text-white flex items-center gap-3">
            <Trophy className="w-8 h-8 text-primary" />
            Leaderboard
          </h1>
          <p className="text-muted-foreground mt-1">
            See how you rank against other security professionals
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge 
            variant="outline" 
            className={`${isLive ? 'text-green-400 border-green-400/50 bg-green-400/10' : 'text-muted-foreground'} gap-1.5`}
          >
            <span className={`w-2 h-2 rounded-full ${isLive ? 'bg-green-400 animate-pulse' : 'bg-muted-foreground'}`} />
            {isLive ? "LIVE" : "Offline"}
          </Badge>
          <Badge variant="outline" className="gap-1.5">
            <Users className="w-3.5 h-3.5" />
            {leaderboard.length} Users
          </Badge>
        </div>
      </div>

      {currentUserRank && (
        <Card className="border-primary/30 bg-primary/5">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-mono text-primary flex items-center gap-2">
              <TrendingUp className="w-4 h-4" />
              YOUR RANKING
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div className="text-4xl font-display font-bold text-primary">
                #{currentUserRank.rank}
              </div>
              <div className="flex-1">
                <p className="text-white font-medium">
                  {getDisplayName(currentUserRank)}
                </p>
                <p className="text-sm text-muted-foreground">
                  {currentUserRank.completedLabs} labs completed
                </p>
              </div>
              <Badge className={`${getLevelColor(currentUserRank.level)} gap-1`}>
                {getLevelIcon(currentUserRank.level)}
                {currentUserRank.levelTitle}
              </Badge>
            </div>
          </CardContent>
        </Card>
      )}

      <div className="space-y-3">
        <AnimatePresence>
          {leaderboard.map((entry, index) => (
            <motion.div
              key={entry.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -20 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              layout
            >
              <div
                data-testid={`leaderboard-entry-${entry.rank}`}
                className={`flex items-center gap-4 p-4 rounded-lg border transition-all duration-300 ${getRankBgClass(entry.rank)} ${
                  entry.id === user?.id ? "ring-2 ring-primary/50" : ""
                }`}
              >
                <div className="w-10 h-10 flex items-center justify-center">
                  {getRankIcon(entry.rank)}
                </div>
                
                <Avatar className="h-12 w-12 border-2 border-border/50">
                  <AvatarImage src={entry.profileImageUrl || undefined} alt={entry.firstName || "User"} />
                  <AvatarFallback className="bg-primary/20 text-primary font-bold">
                    {(entry.firstName?.[0] || "U").toUpperCase()}
                  </AvatarFallback>
                </Avatar>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-white truncate">
                      {getDisplayName(entry)}
                    </span>
                    {entry.id === user?.id && (
                      <Badge variant="outline" className="text-xs text-primary border-primary/30">
                        You
                      </Badge>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground font-mono">
                    Level {entry.level}
                  </p>
                </div>
                
                <div className="text-center min-w-[50px]">
                  <div className="text-2xl font-display font-bold text-white">
                    {entry.completedLabs}
                  </div>
                  <p className="text-xs text-muted-foreground">labs</p>
                </div>
                
                <Badge className={`${getLevelColor(entry.level)} gap-1 min-w-[100px] justify-center`}>
                  {getLevelIcon(entry.level)}
                  {entry.levelTitle}
                </Badge>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
        
        {leaderboard.length === 0 && (
          <div className="text-center py-16">
            <Users className="w-16 h-16 text-muted-foreground mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No Rankings Yet</h3>
            <p className="text-muted-foreground">
              Complete labs to appear on the leaderboard!
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
