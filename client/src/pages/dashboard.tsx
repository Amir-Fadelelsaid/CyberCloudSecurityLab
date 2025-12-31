import { useAuth } from "@/hooks/use-auth";
import { Link } from "wouter";
import { motion } from "framer-motion";
import { ArrowRight, Shield, CheckCircle, Clock, Activity, AlertTriangle, Server, Lock, Users, Database } from "lucide-react";
import { useLabs } from "@/hooks/use-labs";
import { useProgress } from "@/hooks/use-progress";
import { useQuery } from "@tanstack/react-query";
import { clsx } from "clsx";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip } from "recharts";

type LevelInfo = {
  level: number;
  title: string;
  nextLevel: number | null;
  progress: number;
  completedLabs: number;
};

const CATEGORY_ICONS: Record<string, any> = {
  "Storage Security": Database,
  "Network Security": Server,
  "SOC Operations": Activity,
  "SOC Engineer": AlertTriangle,
  "Cloud Security Analyst": Shield,
  "IAM Security": Lock,
  "Cloud Security Engineer": Server,
};

export default function Dashboard() {
  const { user } = useAuth();
  const { data: labs, isLoading: labsLoading } = useLabs();
  const { data: progress } = useProgress();
  
  const { data: levelInfo } = useQuery<LevelInfo>({
    queryKey: ["/api/user/level", user?.id],
    enabled: !!user,
    staleTime: 0,
  });
  
  const { data: userBadges } = useQuery<any[]>({
    queryKey: ["/api/user/badges", user?.id],
    enabled: !!user,
    staleTime: 0,
  });

  const completedCount = progress?.filter(p => p.completed).length || 0;
  const totalLabs = labs?.length || 97;
  const totalScore = progress?.reduce((acc, p) => acc + (p.score || 0), 0) || 0;
  const badgeCount = userBadges?.length || 0;

  const categoryStats = labs ? Object.entries(
    labs.reduce((acc, lab) => {
      const cat = lab.category;
      if (!acc[cat]) acc[cat] = { total: 0, completed: 0 };
      acc[cat].total++;
      if (progress?.some(p => p.labId === lab.id && p.completed)) {
        acc[cat].completed++;
      }
      return acc;
    }, {} as Record<string, { total: number; completed: number }>)
  ) : [];

  const donutData = [
    { name: "Completed", value: completedCount, color: "#22c55e" },
    { name: "Remaining", value: totalLabs - completedCount, color: "#374151" },
  ];

  const difficultyData = [
    { name: "Beginner", count: labs?.filter(l => l.difficulty === "Beginner").length || 0, color: "#22c55e" },
    { name: "Intermediate", count: labs?.filter(l => l.difficulty === "Intermediate").length || 0, color: "#eab308" },
    { name: "Advanced", count: labs?.filter(l => l.difficulty === "Advanced").length || 0, color: "#f97316" },
    { name: "Challenge", count: labs?.filter(l => l.difficulty === "Challenge").length || 0, color: "#a855f7" },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">Dashboard</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Welcome back, {user?.firstName || "Operator"}
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Clock className="w-4 h-4" />
          Last updated: {new Date().toLocaleTimeString()}
        </div>
      </div>

      {/* Top Stats Row - SentinelOne style */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Completion Donut */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="bg-card border border-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Lab Status</span>
          </div>
          <div className="flex items-center gap-4">
            <div className="w-20 h-20">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={donutData}
                    innerRadius={25}
                    outerRadius={35}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {donutData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div>
              <div className="text-2xl font-bold text-foreground">{completedCount}</div>
              <div className="text-xs text-muted-foreground">of {totalLabs} completed</div>
            </div>
          </div>
        </motion.div>

        {/* Score */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.05 }}
          className="bg-card border border-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Total Score</span>
          </div>
          <div className="text-3xl font-bold text-primary">{totalScore.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground mt-1">points earned</div>
        </motion.div>

        {/* Level */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="bg-card border border-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Current Level</span>
          </div>
          <div className="text-3xl font-bold text-foreground">Level {levelInfo?.level || 0}</div>
          <div className="text-xs text-muted-foreground mt-1">{levelInfo?.title || "Recruit"}</div>
        </motion.div>

        {/* Badges */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.15 }}
          className="bg-card border border-border rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Badges Earned</span>
          </div>
          <div className="text-3xl font-bold text-foreground">{badgeCount}</div>
          <div className="text-xs text-muted-foreground mt-1">of 24 available</div>
        </motion.div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        {/* Category Breakdown - Left column */}
        <motion.div
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.2 }}
          className="lg:col-span-2 bg-card border border-border rounded-lg"
        >
          <div className="px-4 py-3 border-b border-border flex items-center justify-between">
            <h2 className="text-sm font-medium text-foreground">Category Progress</h2>
            <Link href="/labs" className="text-xs text-primary hover:underline flex items-center gap-1">
              View all labs <ArrowRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="divide-y divide-border">
            {categoryStats.map(([category, stats], i) => {
              const Icon = CATEGORY_ICONS[category] || Shield;
              const percentage = stats.total > 0 ? Math.round((stats.completed / stats.total) * 100) : 0;
              return (
                <div key={category} className="flex items-center gap-4 px-4 py-3 hover:bg-secondary/30 transition-colors">
                  <div className="w-8 h-8 rounded bg-primary/10 flex items-center justify-center">
                    <Icon className="w-4 h-4 text-primary" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-foreground truncate">{category}</span>
                      <span className="text-xs text-muted-foreground">{stats.completed}/{stats.total}</span>
                    </div>
                    <div className="h-1.5 bg-secondary rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-primary transition-all duration-500"
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  </div>
                  <span className={clsx(
                    "text-xs font-medium px-2 py-0.5 rounded",
                    percentage === 100 ? "bg-green-500/20 text-green-400" :
                    percentage > 0 ? "bg-yellow-500/20 text-yellow-400" :
                    "bg-secondary text-muted-foreground"
                  )}>
                    {percentage}%
                  </span>
                </div>
              );
            })}
          </div>
        </motion.div>

        {/* Labs by Difficulty */}
        <motion.div
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.25 }}
          className="bg-card border border-border rounded-lg"
        >
          <div className="px-4 py-3 border-b border-border">
            <h2 className="text-sm font-medium text-foreground">Labs by Difficulty</h2>
          </div>
          <div className="p-4">
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={difficultyData} layout="vertical">
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="name" width={80} tick={{ fontSize: 12, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#1f2937', border: '1px solid #374151', borderRadius: '6px' }}
                    labelStyle={{ color: '#f3f4f6' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {difficultyData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </motion.div>
      </div>

      {/* Recent Labs */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="bg-card border border-border rounded-lg"
      >
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <h2 className="text-sm font-medium text-foreground">Recent Activity</h2>
        </div>
        <div className="divide-y divide-border">
          {progress?.slice(0, 5).map((p, i) => (
            <Link key={i} href={`/labs/${p.labId}`}>
              <div className="flex items-center gap-4 px-4 py-3 hover:bg-secondary/30 transition-colors cursor-pointer">
                <div className={clsx(
                  "w-2 h-2 rounded-full",
                  p.completed ? "bg-green-500" : "bg-yellow-500"
                )} />
                <div className="flex-1 min-w-0">
                  <span className="text-sm font-medium text-foreground truncate block">{p.lab.title}</span>
                  <span className="text-xs text-muted-foreground">{p.lab.category}</span>
                </div>
                <span className={clsx(
                  "text-xs px-2 py-0.5 rounded",
                  p.completed ? "bg-green-500/20 text-green-400" : "bg-yellow-500/20 text-yellow-400"
                )}>
                  {p.completed ? "Completed" : "In Progress"}
                </span>
                {p.completed && (
                  <span className="text-xs text-muted-foreground">+{p.score} pts</span>
                )}
              </div>
            </Link>
          )) || (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No activity yet. <Link href="/labs" className="text-primary hover:underline">Start your first lab</Link>
            </div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
