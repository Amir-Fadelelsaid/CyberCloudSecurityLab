import { pgTable, text, serial, integer, boolean, timestamp, jsonb } from "drizzle-orm/pg-core";
import { relations } from "drizzle-orm";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { users } from "./models/auth"; // Import auth users

export * from "./models/auth"; // Re-export auth models

// === LABS (SCENARIOS) ===
export const labs = pgTable("labs", {
  id: serial("id").primaryKey(),
  title: text("title").notNull(),
  description: text("description").notNull(),
  briefing: text("briefing"), // Mission alert/urgency text
  scenario: text("scenario"), // Threat context/backstory
  successMessage: text("success_message"), // Message shown on completion
  difficulty: text("difficulty").notNull(), // 'Beginner', 'Intermediate', 'Advanced'
  category: text("category").notNull(), // 'IAM', 'Storage', 'Network'
  estimatedTime: text("estimated_time"), // '5-10 minutes', '15-25 minutes', '30-45 minutes'
  initialState: jsonb("initial_state").notNull(), // Config for resources
  steps: jsonb("steps").notNull().default(JSON.stringify([])), // Step-by-step instructions with intel
  createdAt: timestamp("created_at").defaultNow(),
});

// === RESOURCES (Mock Cloud Resources) ===
export const resources = pgTable("resources", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id), // Can be null for template resources
  labId: integer("lab_id").references(() => labs.id),
  type: text("type").notNull(), // 's3', 'ec2', 'iam_role', 'security_group'
  name: text("name").notNull(),
  config: jsonb("config").notNull(), // Specifics: bucket policy, ingress rules, etc.
  isVulnerable: boolean("is_vulnerable").default(true),
  status: text("status").default("active"), // 'active', 'fixed', 'terminated'
});

// === USER PROGRESS ===
export const userProgress = pgTable("user_progress", {
  id: serial("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  labId: integer("lab_id").notNull().references(() => labs.id),
  completed: boolean("completed").default(false),
  score: integer("score").default(0),
  completedAt: timestamp("completed_at"),
});

// === TERMINAL LOGS ===
export const terminalLogs = pgTable("terminal_logs", {
  id: serial("id").primaryKey(),
  userId: text("user_id").references(() => users.id),
  labId: integer("lab_id").references(() => labs.id),
  command: text("command").notNull(),
  output: text("output"),
  isCorrect: boolean("is_correct").default(false),
  createdAt: timestamp("created_at").defaultNow(),
});

// === BADGES ===
export const badges = pgTable("badges", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  description: text("description").notNull(),
  icon: text("icon").notNull(), // Lucide icon name
  category: text("category").notNull(), // Level, Category, Achievement
  requirement: text("requirement").notNull(), // JSON string describing how to earn
  level: integer("level"), // For level-based badges (1-5)
});

// === USER BADGES ===
export const userBadges = pgTable("user_badges", {
  id: serial("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  badgeId: integer("badge_id").notNull().references(() => badges.id),
  earnedAt: timestamp("earned_at").defaultNow(),
});

// === RELATIONS ===
export const labsRelations = relations(labs, ({ many }) => ({
  resources: many(resources),
  progress: many(userProgress),
}));

export const resourcesRelations = relations(resources, ({ one }) => ({
  lab: one(labs, {
    fields: [resources.labId],
    references: [labs.id],
  }),
}));

export const userProgressRelations = relations(userProgress, ({ one }) => ({
  user: one(users, {
    fields: [userProgress.userId],
    references: [users.id],
  }),
  lab: one(labs, {
    fields: [userProgress.labId],
    references: [labs.id],
  }),
}));

// === BADGE RELATIONS ===
export const badgesRelations = relations(badges, ({ many }) => ({
  userBadges: many(userBadges),
}));

export const userBadgesRelations = relations(userBadges, ({ one }) => ({
  user: one(users, {
    fields: [userBadges.userId],
    references: [users.id],
  }),
  badge: one(badges, {
    fields: [userBadges.badgeId],
    references: [badges.id],
  }),
}));

// === SCHEMAS ===
export const insertLabSchema = createInsertSchema(labs);
export const insertResourceSchema = createInsertSchema(resources);
export const insertProgressSchema = createInsertSchema(userProgress);
export const insertLogSchema = createInsertSchema(terminalLogs);
export const insertBadgeSchema = createInsertSchema(badges);
export const insertUserBadgeSchema = createInsertSchema(userBadges);

// === TYPES ===
export type Lab = typeof labs.$inferSelect;
export type Resource = typeof resources.$inferSelect;
export type UserProgress = typeof userProgress.$inferSelect;
export type TerminalLog = typeof terminalLogs.$inferSelect;
export type Badge = typeof badges.$inferSelect;
export type UserBadge = typeof userBadges.$inferSelect;

export type InsertLab = z.infer<typeof insertLabSchema>;
export type InsertResource = z.infer<typeof insertResourceSchema>;

// API Types
export type CommandRequest = {
  command: string;
  labId: number;
};

export type CommandResponse = {
  output: string;
  success: boolean;
  newState?: Partial<Resource>;
  labCompleted?: boolean;
  completedStep?: number;
};
