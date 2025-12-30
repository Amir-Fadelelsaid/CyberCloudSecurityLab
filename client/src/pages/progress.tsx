import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/use-auth";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { 
  Target, 
  TrendingUp, 
  Calendar, 
  Zap, 
  Shield, 
  Activity,
  CheckCircle2,
  Circle,
  Flame,
  Star,
  User,
  Pencil,
  Check,
  X
} from "lucide-react";
import { useProgress } from "@/hooks/use-progress";
import { useLabs } from "@/hooks/use-labs";
import { Progress } from "@/components/ui/progress";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import { apiRequest, queryClient } from "@/lib/queryClient";

type LevelInfo = {
  level: number;
  title: string;
  nextLevel: number | null;
  progress: number;
  completedLabs: number;
};

const levelThresholds = [
  { level: 0, title: "Recruit", min: 0, max: 6 },
  { level: 1, title: "Operator", min: 7, max: 15 },
  { level: 2, title: "Analyst", min: 16, max: 30 },
  { level: 3, title: "Engineer", min: 31, max: 50 },
  { level: 4, title: "Architect", min: 51, max: 96 },
  { level: 5, title: "Elite Defender", min: 97, max: 97 },
];

type UserProfile = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  displayName: string | null;
  profileImageUrl: string | null;
};

export default function MyProgress() {
  const { user, isLoading: authLoading } = useAuth();
  const { data: progress } = useProgress();
  const { data: labs } = useLabs();
  const { toast } = useToast();
  
  const [isEditingName, setIsEditingName] = useState(false);
  const [editedName, setEditedName] = useState("");
  
  const { data: profile } = useQuery<UserProfile>({
    queryKey: ["/api/user/profile"],
    enabled: !!user
  });
  
  const updateNameMutation = useMutation({
    mutationFn: async (displayName: string) => {
      const res = await apiRequest("PATCH", "/api/user/display-name", { displayName });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user/profile"] });
      queryClient.invalidateQueries({ queryKey: ["/api/leaderboard"] });
      setIsEditingName(false);
      toast({ title: "Display name updated", description: "Your name will appear on the leaderboard." });
    },
    onError: () => {
      toast({ title: "Failed to update", description: "Please try again.", variant: "destructive" });
    }
  });
  
  const { data: levelInfo, refetch: refetchLevel } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level"],
    enabled: !!user,
    staleTime: 0,
  });

  const { data: userBadges, refetch: refetchBadges } = useQuery<any[]>({
    queryKey: ["/api/user/badges"],
    enabled: !!user,
    staleTime: 0,
  });
  
  useEffect(() => {
    if (user) {
      refetchLevel();
      refetchBadges();
    }
  }, [user]);
  
  const startEditing = () => {
    setEditedName(profile?.displayName || profile?.firstName || "");
    setIsEditingName(true);
  };
  
  const saveName = () => {
    if (editedName.trim()) {
      updateNameMutation.mutate(editedName.trim());
    }
  };
  
  const cancelEditing = () => {
    setIsEditingName(false);
    setEditedName("");
  };
  
  const currentDisplayName = profile?.displayName || 
    (profile?.firstName ? `${profile.firstName} ${profile.lastName || ""}`.trim() : "Anonymous");

  const completedLabs = progress?.filter(p => p.completed) || [];
  const totalScore = progress?.reduce((acc, p) => acc + (p.score || 0), 0) || 0;
  const totalLabs = labs?.length || 81;

  const categoryStats = labs?.reduce((acc, lab) => {
    const completed = progress?.some(p => p.labId === lab.id && p.completed);
    if (!acc[lab.category]) {
      acc[lab.category] = { total: 0, completed: 0 };
    }
    acc[lab.category].total++;
    if (completed) acc[lab.category].completed++;
    return acc;
  }, {} as Record<string, { total: number; completed: number }>) || {};

  const difficultyStats = labs?.reduce((acc, lab) => {
    const completed = progress?.some(p => p.labId === lab.id && p.completed);
    if (!acc[lab.difficulty]) {
      acc[lab.difficulty] = { total: 0, completed: 0 };
    }
    acc[lab.difficulty].total++;
    if (completed) acc[lab.difficulty].completed++;
    return acc;
  }, {} as Record<string, { total: number; completed: number }>) || {};

  const currentLevel = levelInfo?.level || 0;
  const currentThreshold = levelThresholds[currentLevel];
  const nextThreshold = levelThresholds[currentLevel + 1];
  const labsToNext = nextThreshold ? nextThreshold.min - completedLabs.length : 0;

  const recentCompletions = completedLabs
    .filter(p => p.completedAt)
    .sort((a, b) => new Date(b.completedAt!).getTime() - new Date(a.completedAt!).getTime())
    .slice(0, 5);

  const getCategoryIcon = (category: string) => {
    const icons: Record<string, string> = {
      "Storage Security": "text-blue-400",
      "Network Security": "text-orange-400",
      "SOC Operations": "text-red-400",
      "SOC Engineer": "text-purple-400",
      "Cloud Security Analyst": "text-cyan-400",
      "IAM Security": "text-yellow-400",
      "Cloud Security Engineer": "text-green-400",
    };
    return icons[category] || "text-muted-foreground";
  };

  const getDifficultyColor = (difficulty: string) => {
    const colors: Record<string, string> = {
      "Beginner": "bg-green-500",
      "Intermediate": "bg-yellow-500",
      "Advanced": "bg-red-500",
      "Challenge": "bg-purple-500",
    };
    return colors[difficulty] || "bg-muted";
  };

  // Show login prompt if not authenticated
  if (!authLoading && !user) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-6">
        <div className="p-4 rounded-full bg-primary/20">
          <Shield className="w-12 h-12 text-primary" />
        </div>
        <div className="text-center space-y-2">
          <h2 className="text-2xl font-display font-bold text-white">Sign In Required</h2>
          <p className="text-muted-foreground max-w-md">
            Please log in with Replit to view your training progress and achievements.
          </p>
        </div>
        <Button 
          onClick={() => window.location.href = "/api/login"}
          className="gap-2"
          data-testid="button-login-progress"
        >
          <User className="w-4 h-4" />
          Log in with Replit
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-accent/20 border border-accent/30">
              <Activity className="w-6 h-6 text-accent" />
            </div>
            <div>
              <h1 className="text-3xl font-display font-bold text-white">
                My Progress
              </h1>
              <p className="text-muted-foreground text-sm">
                Track your security training journey
              </p>
            </div>
          </div>
          
          <Card className="bg-card/50 border-border/50">
            <CardContent className="p-3">
              <div className="flex items-center gap-3">
                <User className="w-4 h-4 text-muted-foreground" />
                {isEditingName ? (
                  <div className="flex items-center gap-2">
                    <Input
                      data-testid="input-display-name"
                      value={editedName}
                      onChange={(e) => setEditedName(e.target.value)}
                      placeholder="Your display name"
                      className="h-8 w-40"
                      maxLength={50}
                      onKeyDown={(e) => e.key === "Enter" && saveName()}
                    />
                    <Button 
                      size="icon" 
                      variant="ghost" 
                      onClick={saveName}
                      disabled={updateNameMutation.isPending}
                      data-testid="button-save-name"
                    >
                      <Check className="w-4 h-4 text-green-400" />
                    </Button>
                    <Button 
                      size="icon" 
                      variant="ghost" 
                      onClick={cancelEditing}
                      data-testid="button-cancel-name"
                    >
                      <X className="w-4 h-4 text-red-400" />
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-white font-medium">{currentDisplayName}</span>
                    <Button 
                      size="icon" 
                      variant="ghost" 
                      onClick={startEditing}
                      className="h-7 w-7"
                      data-testid="button-edit-name"
                    >
                      <Pencil className="w-3 h-3" />
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </motion.div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-2"
        >
          <Card className="bg-gradient-to-br from-accent/10 via-card to-card border-accent/20 overflow-hidden relative">
            <div className="absolute top-0 right-0 w-64 h-64 bg-accent/10 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
            <CardHeader className="pb-4">
              <CardTitle className="text-lg flex items-center gap-2">
                <Target className="w-5 h-5 text-accent" />
                Level Progression
              </CardTitle>
            </CardHeader>
            <CardContent className="relative z-10">
              <div className="flex items-center gap-6">
                <div className="relative">
                  <div className="w-24 h-24 rounded-full bg-accent/20 border-4 border-accent flex items-center justify-center">
                    <span className="text-4xl font-display font-bold text-accent">{currentLevel}</span>
                  </div>
                  <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 px-3 py-0.5 bg-accent text-accent-foreground text-xs font-bold rounded-full">
                    {levelInfo?.title || "Recruit"}
                  </div>
                </div>
                
                <div className="flex-1 space-y-4">
                  <div className="flex justify-between items-center">
                    <div>
                      <p className="text-2xl font-bold text-white">{completedLabs.length} / {totalLabs}</p>
                      <p className="text-sm text-muted-foreground">Labs Completed</p>
                    </div>
                    <div className="text-right">
                      <p className="text-2xl font-bold text-primary">{totalScore}</p>
                      <p className="text-sm text-muted-foreground">Total Points</p>
                    </div>
                  </div>
                  
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Progress to next level</span>
                      {nextThreshold && (
                        <span className="text-accent font-mono">{labsToNext} labs to {nextThreshold.title}</span>
                      )}
                    </div>
                    <Progress 
                      value={nextThreshold ? ((completedLabs.length - currentThreshold.min) / (nextThreshold.min - currentThreshold.min)) * 100 : 100} 
                      className="h-3 bg-accent/20"
                    />
                  </div>
                </div>
              </div>

              <div className="mt-6 flex gap-2 flex-wrap">
                {levelThresholds.map((threshold, i) => (
                  <div 
                    key={threshold.level}
                    className={`px-3 py-1.5 rounded-lg text-xs font-mono flex items-center gap-1.5 ${
                      i <= currentLevel 
                        ? "bg-accent/20 text-accent border border-accent/30" 
                        : "bg-muted/20 text-muted-foreground border border-muted/20"
                    }`}
                  >
                    {i <= currentLevel ? <CheckCircle2 className="w-3 h-3" /> : <Circle className="w-3 h-3" />}
                    {threshold.title}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
        >
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <Flame className="w-5 h-5 text-orange-400" />
                Quick Stats
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between p-3 rounded-lg bg-primary/10 border border-primary/20">
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-primary" />
                  <span className="text-sm">Completion Rate</span>
                </div>
                <span className="font-bold text-primary">
                  {totalLabs > 0 ? Math.round((completedLabs.length / totalLabs) * 100) : 0}%
                </span>
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                <div className="flex items-center gap-2">
                  <Star className="w-4 h-4 text-yellow-400" />
                  <span className="text-sm">Badges Earned</span>
                </div>
                <span className="font-bold text-yellow-400">{userBadges?.length || 0}</span>
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm">Avg Score</span>
                </div>
                <span className="font-bold text-cyan-400">
                  {completedLabs.length > 0 ? Math.round(totalScore / completedLabs.length) : 0}
                </span>
              </div>
              
              <div className="flex items-center justify-between p-3 rounded-lg bg-purple-500/10 border border-purple-500/20">
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4 text-purple-400" />
                  <span className="text-sm">Categories</span>
                </div>
                <span className="font-bold text-purple-400">
                  {Object.values(categoryStats).filter(c => c.completed > 0).length} / 7
                </span>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="w-5 h-5 text-primary" />
                Category Breakdown
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {Object.entries(categoryStats).map(([category, stats]) => (
                <div key={category} className="space-y-1.5">
                  <div className="flex justify-between items-center">
                    <span className={`text-sm font-medium ${getCategoryIcon(category)}`}>
                      {category}
                    </span>
                    <span className="text-xs text-muted-foreground font-mono">
                      {stats.completed}/{stats.total}
                    </span>
                  </div>
                  <Progress 
                    value={(stats.completed / stats.total) * 100} 
                    className="h-2"
                  />
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
        >
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-lg flex items-center gap-2">
                <Calendar className="w-5 h-5 text-primary" />
                Recent Completions
              </CardTitle>
            </CardHeader>
            <CardContent>
              {recentCompletions.length > 0 ? (
                <div className="space-y-3">
                  {recentCompletions.map((p, i) => (
                    <div 
                      key={i} 
                      className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border/50"
                    >
                      <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center">
                        <CheckCircle2 className="w-4 h-4 text-primary" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium truncate">{p.lab.title}</p>
                        <p className="text-xs text-muted-foreground">
                          {p.completedAt && new Date(p.completedAt).toLocaleDateString()}
                        </p>
                      </div>
                      <Badge variant="outline" className="text-primary border-primary/30">
                        +{p.score}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="w-12 h-12 mx-auto mb-3 opacity-30" />
                  <p className="text-sm">No completed labs yet</p>
                  <p className="text-xs mt-1">Start training to track your progress!</p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-lg flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-primary" />
              Difficulty Progress
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {["Beginner", "Intermediate", "Advanced", "Challenge"].map((difficulty) => {
                const stats = difficultyStats[difficulty] || { total: 0, completed: 0 };
                const percentage = stats.total > 0 ? Math.round((stats.completed / stats.total) * 100) : 0;
                
                return (
                  <div 
                    key={difficulty}
                    className="p-4 rounded-lg bg-muted/10 border border-border/50 text-center"
                  >
                    <div className="relative w-16 h-16 mx-auto mb-3">
                      <svg className="w-full h-full -rotate-90" viewBox="0 0 36 36">
                        <circle
                          cx="18"
                          cy="18"
                          r="15.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="3"
                          className="text-muted/30"
                        />
                        <circle
                          cx="18"
                          cy="18"
                          r="15.5"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="3"
                          strokeDasharray={`${percentage} 100`}
                          className={getDifficultyColor(difficulty).replace("bg-", "text-")}
                        />
                      </svg>
                      <span className="absolute inset-0 flex items-center justify-center text-sm font-bold">
                        {percentage}%
                      </span>
                    </div>
                    <p className="text-sm font-medium">{difficulty}</p>
                    <p className="text-xs text-muted-foreground">
                      {stats.completed}/{stats.total} labs
                    </p>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
