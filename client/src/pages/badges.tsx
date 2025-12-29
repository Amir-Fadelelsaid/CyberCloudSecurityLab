import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { 
  Shield, Search, Wrench, Building2, Crown, Database, Network, Eye, 
  Activity, Cloud, Flame, Zap, Anchor, Target, Moon, Calendar, Trophy,
  Lock, CheckCircle2
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useEffect } from "react";
import { useAuth } from "@/hooks/use-auth";

type BadgeData = {
  id: number;
  name: string;
  description: string;
  icon: string;
  category: string;
  requirement: string;
  level: number | null;
};

type UserBadgeData = {
  id: number;
  badgeId: number;
  earnedAt: string;
  badge: BadgeData;
};

type LevelInfo = {
  level: number;
  title: string;
  nextLevel: number | null;
  progress: number;
  completedLabs: number;
};

const iconMap: Record<string, any> = {
  Shield, Search, Wrench, Building2, Crown, Database, Network, Eye,
  Activity, Cloud, Flame, Zap, Anchor, Target, Moon, Calendar, Trophy
};

function BadgeCard({ badge, earned, earnedAt }: { badge: BadgeData; earned: boolean; earnedAt?: string }) {
  const IconComponent = iconMap[badge.icon] || Shield;
  
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      whileHover={earned ? { scale: 1.05 } : {}}
      transition={{ duration: 0.2 }}
    >
      <Card className={`relative overflow-hidden ${earned ? 'border-primary/50' : 'border-muted opacity-50'}`}>
        {earned && (
          <div className="absolute top-2 right-2">
            <CheckCircle2 className="h-5 w-5 text-primary" />
          </div>
        )}
        {!earned && (
          <div className="absolute top-2 right-2">
            <Lock className="h-5 w-5 text-muted-foreground" />
          </div>
        )}
        <CardContent className="p-4 flex flex-col items-center text-center">
          <div className={`p-3 rounded-full mb-3 ${earned ? 'bg-primary/20' : 'bg-muted'}`}>
            <IconComponent className={`h-8 w-8 ${earned ? 'text-primary' : 'text-muted-foreground'}`} />
          </div>
          <h3 className={`font-semibold text-sm ${earned ? 'text-foreground' : 'text-muted-foreground'}`}>
            {badge.name}
          </h3>
          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
            {badge.description}
          </p>
          <Badge 
            variant="outline" 
            className={`mt-2 text-xs ${
              badge.category === 'Level' ? 'border-primary/50 text-primary' :
              badge.category === 'Category' ? 'border-accent/50 text-accent-foreground' :
              'border-yellow-500/50 text-yellow-500'
            }`}
          >
            {badge.category}
          </Badge>
          {earned && earnedAt && (
            <p className="text-xs text-muted-foreground mt-2">
              Earned {new Date(earnedAt).toLocaleDateString()}
            </p>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}

export default function BadgesPage() {
  const { user, isLoading: authLoading } = useAuth();

  const { data: allBadges, isLoading: badgesLoading } = useQuery<BadgeData[]>({
    queryKey: ["/api/badges"]
  });

  const { data: userBadges, isLoading: userBadgesLoading, refetch: refetchUserBadges } = useQuery<UserBadgeData[]>({
    queryKey: ["/api/user/badges"],
    enabled: !!user,
    staleTime: 0,
  });

  const { data: levelInfo, isLoading: levelLoading, refetch: refetchLevel } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level"],
    enabled: !!user,
    staleTime: 0,
  });

  const checkBadgesMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch("/api/badges/check", { method: "POST", credentials: "include" });
      return res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/user/badges"] });
      queryClient.invalidateQueries({ queryKey: ["/api/user/level"] });
    }
  });

  useEffect(() => {
    if (user) {
      checkBadgesMutation.mutate();
      refetchUserBadges();
      refetchLevel();
    }
  }, [user]);

  const isLoading = authLoading || badgesLoading || (user && (userBadgesLoading || levelLoading));

  const earnedBadgeIds = new Set(userBadges?.map(ub => ub.badgeId) || []);
  const earnedBadgesMap = new Map(userBadges?.map(ub => [ub.badgeId, ub]) || []);

  const levelBadges = allBadges?.filter(b => b.category === "Level") || [];
  const categoryBadges = allBadges?.filter(b => b.category === "Category") || [];
  const achievementBadges = allBadges?.filter(b => b.category === "Achievement") || [];

  const earnedCount = userBadges?.length || 0;
  const totalCount = allBadges?.length || 0;

  if (isLoading) {
    return (
      <div className="p-6 space-y-6">
        <Skeleton className="h-32 w-full" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[...Array(8)].map((_, i) => (
            <Skeleton key={i} className="h-40" />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-8 overflow-y-auto h-full" data-testid="badges-page">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <Card className="bg-gradient-to-r from-primary/10 to-accent/10 border-primary/20">
          <CardContent className="p-6">
            <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
              <div>
                <h1 className="text-2xl font-bold font-display">Your Achievements</h1>
                <p className="text-muted-foreground mt-1">
                  {earnedCount} of {totalCount} badges earned
                </p>
              </div>
              <div className="flex items-center gap-4">
                <div className="text-right">
                  <p className="text-sm text-muted-foreground">Current Level</p>
                  <p className="text-xl font-bold text-primary">
                    Level {levelInfo?.level || 0} - {levelInfo?.title || "Recruit"}
                  </p>
                </div>
                <div className="h-16 w-16 rounded-full bg-primary/20 flex items-center justify-center">
                  <span className="text-2xl font-bold text-primary">{levelInfo?.level || 0}</span>
                </div>
              </div>
            </div>
            {levelInfo?.nextLevel && (
              <div className="mt-4">
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Progress to next level</span>
                  <span className="text-primary">{levelInfo.completedLabs} / {levelInfo.nextLevel} labs</span>
                </div>
                <Progress value={levelInfo.progress} className="h-2" />
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      <section>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Crown className="h-5 w-5 text-primary" />
          Level Badges
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-4">
          {levelBadges.sort((a, b) => (a.level || 0) - (b.level || 0)).map(badge => (
            <BadgeCard 
              key={badge.id} 
              badge={badge} 
              earned={earnedBadgeIds.has(badge.id)}
              earnedAt={earnedBadgesMap.get(badge.id)?.earnedAt}
            />
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Database className="h-5 w-5 text-accent-foreground" />
          Category Mastery
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-4">
          {categoryBadges.map(badge => (
            <BadgeCard 
              key={badge.id} 
              badge={badge} 
              earned={earnedBadgeIds.has(badge.id)}
              earnedAt={earnedBadgesMap.get(badge.id)?.earnedAt}
            />
          ))}
        </div>
      </section>

      <section>
        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
          <Trophy className="h-5 w-5 text-yellow-500" />
          Special Achievements
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-4">
          {achievementBadges.map(badge => (
            <BadgeCard 
              key={badge.id} 
              badge={badge} 
              earned={earnedBadgeIds.has(badge.id)}
              earnedAt={earnedBadgesMap.get(badge.id)?.earnedAt}
            />
          ))}
        </div>
      </section>
    </div>
  );
}
