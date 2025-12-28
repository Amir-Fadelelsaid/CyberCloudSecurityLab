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
  difficulty: text("difficulty").notNull(), // 'Beginner', 'Intermediate', 'Advanced'
  category: text("category").notNull(), // 'IAM', 'Storage', 'Network'
  initialState: jsonb("initial_state").notNull(), // Config for resources
  steps: jsonb("steps").notNull().default(JSON.stringify([])), // Step-by-step instructions
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

// === SCHEMAS ===
export const insertLabSchema = createInsertSchema(labs);
export const insertResourceSchema = createInsertSchema(resources);
export const insertProgressSchema = createInsertSchema(userProgress);
export const insertLogSchema = createInsertSchema(terminalLogs);

// === TYPES ===
export type Lab = typeof labs.$inferSelect;
export type Resource = typeof resources.$inferSelect;
export type UserProgress = typeof userProgress.$inferSelect;
export type TerminalLog = typeof terminalLogs.$inferSelect;

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
};
