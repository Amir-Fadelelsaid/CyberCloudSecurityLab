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
// Thresholds match calculateLevel: Recruit(0-6), Operator(7-15), Analyst(16-30), Engineer(31-50), Architect(51-80), Elite Defender(81)
export const levelBadges: BadgeDefinition[] = [
  {
    name: "Operator",
    description: "Complete 7 labs and begin your security journey",
    icon: "Shield",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 7 }),
    level: 1
  },
  {
    name: "Analyst",
    description: "Complete 16 labs and demonstrate security analysis skills",
    icon: "Search",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 16 }),
    level: 2
  },
  {
    name: "Engineer",
    description: "Complete 31 labs and show engineering expertise",
    icon: "Wrench",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 31 }),
    level: 3
  },
  {
    name: "Architect",
    description: "Complete 51 labs and master security architecture",
    icon: "Building2",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 51 }),
    level: 4
  },
  {
    name: "Elite Defender",
    description: "Complete all 81 labs and achieve elite status",
    icon: "Crown",
    category: "Level",
    requirement: JSON.stringify({ type: "total_labs", count: 81 }),
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
  },
  {
    name: "IAM Enforcer",
    description: "Master all IAM Security labs",
    icon: "Users",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "IAM Security" })
  },
  {
    name: "Security Architect",
    description: "Master all Cloud Security Engineer labs",
    icon: "Shield",
    category: "Category",
    requirement: JSON.stringify({ type: "category_complete", category: "Cloud Security Engineer" })
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
    requirement: JSON.stringify({ type: "total_labs", count: 81 })
  }
];

export const allBadgeDefinitions = [
  ...levelBadges,
  ...categoryBadges,
  ...achievementBadges
];

// Helper to calculate user level based on completed labs
export function calculateLevel(completedLabsCount: number): { level: number; title: string; nextLevel: number | null; progress: number } {
  if (completedLabsCount >= 81) {
    return { level: 5, title: "Elite Defender", nextLevel: null, progress: 100 };
  } else if (completedLabsCount >= 51) {
    return { level: 4, title: "Architect", nextLevel: 81, progress: Math.round(((completedLabsCount - 51) / (81 - 51)) * 100) };
  } else if (completedLabsCount >= 31) {
    return { level: 3, title: "Engineer", nextLevel: 51, progress: Math.round(((completedLabsCount - 31) / (51 - 31)) * 100) };
  } else if (completedLabsCount >= 16) {
    return { level: 2, title: "Analyst", nextLevel: 31, progress: Math.round(((completedLabsCount - 16) / (31 - 16)) * 100) };
  } else if (completedLabsCount >= 7) {
    return { level: 1, title: "Operator", nextLevel: 16, progress: Math.round(((completedLabsCount - 7) / (16 - 7)) * 100) };
  } else {
    return { level: 0, title: "Recruit", nextLevel: 7, progress: Math.round((completedLabsCount / 7) * 100) };
  }
}
