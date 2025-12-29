import { db } from "./db";
import {
  labs, resources, userProgress, terminalLogs, badges, userBadges, users, certificates,
  type Lab, type Resource, type UserProgress, type InsertLab, type InsertResource, type Badge, type UserBadge, type User, type Certificate
} from "@shared/schema";
import { eq, and, sql, desc } from "drizzle-orm";

export type LeaderboardEntry = {
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

export interface IStorage {
  // Labs
  getLabs(): Promise<Lab[]>;
  getLab(id: number): Promise<Lab | undefined>;
  createLab(lab: InsertLab): Promise<Lab>;
  updateLab(id: number, updates: Partial<Lab>): Promise<Lab>;
  deleteLab(id: number): Promise<void>;
  
  // Resources
  getResources(labId: number, userId?: string): Promise<Resource[]>;
  updateResource(id: number, updates: Partial<Resource>): Promise<Resource>;
  createResource(resource: InsertResource): Promise<Resource>;
  resetLabResources(labId: number, userId: string): Promise<void>;
  
  // Progress
  getUserProgress(userId: string): Promise<(UserProgress & { lab: Lab })[]>;
  updateProgress(userId: string, labId: number, completed: boolean): Promise<UserProgress>;
  
  // Logs
  logCommand(userId: string, labId: number, command: string, output: string, isCorrect: boolean): Promise<void>;
  
  // Badges
  getBadges(): Promise<Badge[]>;
  getBadge(id: number): Promise<Badge | undefined>;
  createBadge(badge: Omit<Badge, 'id'>): Promise<Badge>;
  getUserBadges(userId: string): Promise<(UserBadge & { badge: Badge })[]>;
  awardBadge(userId: string, badgeId: number): Promise<UserBadge>;
  hasBadge(userId: string, badgeId: number): Promise<boolean>;
  
  // Leaderboard
  getLeaderboard(): Promise<LeaderboardEntry[]>;
  
  // User profile
  updateUserDisplayName(userId: string, displayName: string): Promise<void>;
  getUser(userId: string): Promise<User | undefined>;
  
  // Certificates
  getUserCertificates(userId: string): Promise<Certificate[]>;
  getCertificate(userId: string, category: string): Promise<Certificate | undefined>;
  createCertificate(userId: string, category: string, labsCompleted: number, totalScore: number): Promise<Certificate>;
  getCategoryCompletion(userId: string, category: string): Promise<{ completed: number; total: number }>;
}

export class DatabaseStorage implements IStorage {
  async getLabs(): Promise<Lab[]> {
    return await db.select().from(labs);
  }

  async getLab(id: number): Promise<Lab | undefined> {
    const [lab] = await db.select().from(labs).where(eq(labs.id, id));
    return lab;
  }

  async createLab(lab: InsertLab): Promise<Lab> {
    const [newLab] = await db.insert(labs).values(lab).returning();
    return newLab;
  }

  async updateLab(id: number, updates: Partial<Lab>): Promise<Lab> {
    const [updated] = await db.update(labs).set(updates).where(eq(labs.id, id)).returning();
    return updated;
  }

  async deleteLab(id: number): Promise<void> {
    await db.delete(resources).where(eq(resources.labId, id));
    await db.delete(labs).where(eq(labs.id, id));
  }

  async getResources(labId: number, userId?: string): Promise<Resource[]> {
    // In a real multi-tenant app, we'd filter by userId too for instantiated labs
    // For this simplified version, we'll just get resources for the lab
    return await db.select().from(resources).where(eq(resources.labId, labId));
  }

  async updateResource(id: number, updates: Partial<Resource>): Promise<Resource> {
    const [updated] = await db.update(resources)
      .set(updates)
      .where(eq(resources.id, id))
      .returning();
    return updated;
  }

  async createResource(resource: InsertResource): Promise<Resource> {
    const [newRes] = await db.insert(resources).values(resource).returning();
    return newRes;
  }

  async resetLabResources(labId: number, userId: string): Promise<void> {
    // Reset logic: Delete current resources and re-instantiate from lab.initialState
    // Simplified: Just mark all as vulnerable for now
    await db.update(resources)
      .set({ isVulnerable: true, status: 'active' })
      .where(eq(resources.labId, labId));
  }

  async getUserProgress(userId: string): Promise<(UserProgress & { lab: Lab })[]> {
    const result = await db.select()
      .from(userProgress)
      .innerJoin(labs, eq(userProgress.labId, labs.id))
      .where(eq(userProgress.userId, userId));
    
    return result.map(row => ({
      ...row.user_progress,
      lab: row.labs
    }));
  }

  async updateProgress(userId: string, labId: number, completed: boolean): Promise<UserProgress> {
    // Calculate score based on lab difficulty if completing
    let score = 0;
    if (completed) {
      const lab = await this.getLab(labId);
      if (lab) {
        score = this.calculateScore(lab.difficulty);
      }
    }

    // Check if progress already exists
    const existing = await db.select()
      .from(userProgress)
      .where(and(eq(userProgress.userId, userId), eq(userProgress.labId, labId)))
      .limit(1);
    
    if (existing.length > 0) {
      // Update existing record
      const [updated] = await db
        .update(userProgress)
        .set({ completed, score, completedAt: new Date() })
        .where(and(eq(userProgress.userId, userId), eq(userProgress.labId, labId)))
        .returning();
      return updated;
    } else {
      // Insert new record
      const [progress] = await db
        .insert(userProgress)
        .values({ userId, labId, completed, score, completedAt: new Date() })
        .returning();
      return progress;
    }
  }

  private calculateScore(difficulty: string): number {
    const scores: Record<string, number> = {
      'Beginner': 10,
      'Intermediate': 25,
      'Advanced': 50,
      'Challenge': 100
    };
    return scores[difficulty] || 10;
  }

  async logCommand(userId: string, labId: number, command: string, output: string, isCorrect: boolean): Promise<void> {
    await db.insert(terminalLogs).values({
      userId,
      labId,
      command,
      output,
      isCorrect
    });
  }

  async getBadges(): Promise<Badge[]> {
    return await db.select().from(badges);
  }

  async getBadge(id: number): Promise<Badge | undefined> {
    const [badge] = await db.select().from(badges).where(eq(badges.id, id));
    return badge;
  }

  async createBadge(badge: Omit<Badge, 'id'>): Promise<Badge> {
    const [newBadge] = await db.insert(badges).values(badge).returning();
    return newBadge;
  }

  async getUserBadges(userId: string): Promise<(UserBadge & { badge: Badge })[]> {
    const result = await db.select()
      .from(userBadges)
      .innerJoin(badges, eq(userBadges.badgeId, badges.id))
      .where(eq(userBadges.userId, userId));
    
    return result.map(row => ({
      ...row.user_badges,
      badge: row.badges
    }));
  }

  async awardBadge(userId: string, badgeId: number): Promise<UserBadge> {
    const [awarded] = await db.insert(userBadges)
      .values({ userId, badgeId })
      .returning();
    return awarded;
  }

  async hasBadge(userId: string, badgeId: number): Promise<boolean> {
    const existing = await db.select()
      .from(userBadges)
      .where(and(eq(userBadges.userId, userId), eq(userBadges.badgeId, badgeId)))
      .limit(1);
    return existing.length > 0;
  }

  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    const result = await db
      .select({
        id: users.id,
        firstName: users.firstName,
        lastName: users.lastName,
        displayName: users.displayName,
        profileImageUrl: users.profileImageUrl,
        completedLabs: sql<number>`COALESCE(COUNT(CASE WHEN ${userProgress.completed} = true THEN 1 END), 0)::int`
      })
      .from(users)
      .leftJoin(userProgress, eq(users.id, userProgress.userId))
      .groupBy(users.id)
      .orderBy(desc(sql`COUNT(CASE WHEN ${userProgress.completed} = true THEN 1 END)`));

    const calculateLevelInfo = (completed: number) => {
      if (completed >= 81) return { level: 6, title: "Elite Defender" };
      if (completed >= 51) return { level: 5, title: "Architect" };
      if (completed >= 31) return { level: 4, title: "Engineer" };
      if (completed >= 16) return { level: 3, title: "Analyst" };
      if (completed >= 7) return { level: 2, title: "Operator" };
      return { level: 1, title: "Recruit" };
    };

    return result.map((row, index) => {
      const levelInfo = calculateLevelInfo(row.completedLabs);
      return {
        rank: index + 1,
        id: row.id,
        firstName: row.firstName,
        lastName: row.lastName,
        displayName: row.displayName,
        profileImageUrl: row.profileImageUrl,
        completedLabs: row.completedLabs,
        level: levelInfo.level,
        levelTitle: levelInfo.title
      };
    });
  }

  async updateUserDisplayName(userId: string, displayName: string): Promise<void> {
    await db.update(users)
      .set({ displayName, updatedAt: new Date() })
      .where(eq(users.id, userId));
  }

  async getUser(userId: string): Promise<User | undefined> {
    const [user] = await db.select().from(users).where(eq(users.id, userId));
    return user;
  }

  async getUserCertificates(userId: string): Promise<Certificate[]> {
    return await db.select()
      .from(certificates)
      .where(eq(certificates.userId, userId))
      .orderBy(desc(certificates.completedAt));
  }

  async getCertificate(userId: string, category: string): Promise<Certificate | undefined> {
    const [cert] = await db.select()
      .from(certificates)
      .where(and(eq(certificates.userId, userId), eq(certificates.category, category)));
    return cert;
  }

  async createCertificate(userId: string, category: string, labsCompleted: number, totalScore: number): Promise<Certificate> {
    const [cert] = await db.insert(certificates)
      .values({ userId, category, labsCompleted, totalScore })
      .returning();
    return cert;
  }

  async getCategoryCompletion(userId: string, category: string): Promise<{ completed: number; total: number }> {
    const categoryLabs = await db.select({ id: labs.id })
      .from(labs)
      .where(eq(labs.category, category));
    
    const labIds = categoryLabs.map(l => l.id);
    if (labIds.length === 0) return { completed: 0, total: 0 };

    const completedProgress = await db.select()
      .from(userProgress)
      .where(and(
        eq(userProgress.userId, userId),
        eq(userProgress.completed, true)
      ));

    const completedLabIds = new Set(completedProgress.map(p => p.labId));
    const completed = labIds.filter(id => completedLabIds.has(id)).length;

    return { completed, total: labIds.length };
  }
}

export const storage = new DatabaseStorage();
