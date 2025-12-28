// Badge Definitions for CloudShieldLab
// Categories: Level (progression), Category (mastery), Achievement (special)

export interface BadgeDefinition {
  name: string;
  description: string;
  icon: string; // Lucide icon name
  category: "Level" | "Category" | "Achievement";
  requirement: string; // JSON string describing how to earn
  level?: number; // For level-based badges (1-5)
}

// Level-based badges (earned by completing X total labs)
export const levelBadges: BadgeDefinition[] = [
  {
    name: "Operator",
    description: "Complete your first 5 labs and begin your security journey",
    icon: "Shield",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 5 }),
    level: 1
  },
  {
    name: "Analyst",
    description: "Complete 12 labs and demonstrate security analysis skills",
    icon: "Search",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 12 }),
    level: 2
  },
  {
    name: "Engineer",
    description: "Complete 20 labs and show engineering expertise",
    icon: "Wrench",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 20 }),
    level: 3
  },
  {
    name: "Architect",
    description: "Complete 35 labs and master security architecture",
    icon: "Building2",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 35 }),
    level: 4
  },
  {
    name: "Elite Defender",
    description: "Complete all 57 labs and achieve elite status",
    icon: "Crown",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 57 }),
    level: 5
  }
];

// Category mastery badges (earned by completing all labs in a category)
export const categoryBadges: BadgeDefinition[] = [
  {
    name: "Storage Guardian",
    description: "Master all Storage Security labs",
    icon: "Database",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "Storage Security" })
  },
  {
    name: "Network Sentinel",
    description: "Master all Network Security labs",
    icon: "Network",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "Network Security" })
  },
  {
    name: "SOC Commander",
    description: "Master all SOC Operations labs",
    icon: "Eye",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "SOC Operations" })
  },
  {
    name: "SIEM Master",
    description: "Master all SOC Engineer labs",
    icon: "Activity",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "SOC Engineer" })
  },
  {
    name: "Cloud Protector",
    description: "Master all Cloud Security Analyst labs",
    icon: "Cloud",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "Cloud Security Analyst" })
  }
];

// Achievement badges (special accomplishments)
export const achievementBadges: BadgeDefinition[] = [
  {
    name: "First Blood",
    description: "Complete your very first lab",
    icon: "Flame",
    category: "Achievement",
    requirement: JSON.stringify({ type: "total_labs", count: 1 })
  },
  {
    name: "Speed Runner",
    description: "Complete 3 beginner labs",
    icon: "Zap",
    category: "Achievement",
    requirement: JSON.stringify({ type: "difficulty_count", difficulty: "Beginner", count: 3 })
  },
  {
    name: "Deep Diver",
    description: "Complete 5 intermediate labs",
    icon: "Anchor",
    category: "Achievement",
    requirement: JSON.stringify({ type: "difficulty_count", difficulty: "Intermediate", count: 5 })
  },
  {
    name: "Expert Hunter",
    description: "Complete 3 advanced labs",
    icon: "Target",
    category: "Achievement",
    requirement: JSON.stringify({ type: "difficulty_count", difficulty: "Advanced", count: 3 })
  },
  {
    name: "Lone Wolf",
    description: "Complete a challenge lab without any guidance",
    icon: "Moon",
    category: "Achievement",
    requirement: JSON.stringify({ type: "difficulty_count", difficulty: "Challenge", count: 1 })
  },
  {
    name: "Perfect Week",
    description: "Complete 7 labs in 7 days",
    icon: "Calendar",
    category: "Achievement",
    requirement: JSON.stringify({ type: "streak", days: 7, labs: 7 })
  },
  {
    name: "Completionist",
    description: "Complete every single lab in CloudShieldLab",
    icon: "Trophy",
    category: "Achievement",
    requirement: JSON.stringify({ type: "total_labs", count: 57 })
  }
];

export const allBadgeDefinitions = [
  ...levelBadges,
  ...categoryBadges,
  ...achievementBadges
];

// Helper to calculate user level based on completed labs
export function calculateLevel(completedLabsCount: number): { level: number; title: string; nextLevel: number | null; progress: number } {
  if (completedLabsCount >= 57) {
    return { level: 5, title: "Elite Defender", nextLevel: null, progress: 100 };
  } else if (completedLabsCount >= 35) {
    return { level: 4, title: "Architect", nextLevel: 57, progress: Math.round(((completedLabsCount - 35) / (57 - 35)) * 100) };
  } else if (completedLabsCount >= 20) {
    return { level: 3, title: "Engineer", nextLevel: 35, progress: Math.round(((completedLabsCount - 20) / (35 - 20)) * 100) };
  } else if (completedLabsCount >= 12) {
    return { level: 2, title: "Analyst", nextLevel: 20, progress: Math.round(((completedLabsCount - 12) / (20 - 12)) * 100) };
  } else if (completedLabsCount >= 5) {
    return { level: 1, title: "Operator", nextLevel: 12, progress: Math.round(((completedLabsCount - 5) / (12 - 5)) * 100) };
  } else {
    return { level: 0, title: "Recruit", nextLevel: 5, progress: Math.round((completedLabsCount / 5) * 100) };
  }
}
