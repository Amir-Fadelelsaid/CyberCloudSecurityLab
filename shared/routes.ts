import { z } from 'zod';
import { insertLabSchema, insertResourceSchema, labs, resources, userProgress } from './schema';

export const errorSchemas = {
  validation: z.object({
    message: z.string(),
    field: z.string().optional(),
  }),
  notFound: z.object({
    message: z.string(),
  }),
  internal: z.object({
    message: z.string(),
  }),
};

export const api = {
  labs: {
    list: {
      method: 'GET' as const,
      path: '/api/labs',
      responses: {
        200: z.array(z.custom<typeof labs.$inferSelect>()),
      },
    },
    get: {
      method: 'GET' as const,
      path: '/api/labs/:id',
      responses: {
        200: z.custom<typeof labs.$inferSelect & { resources: typeof resources.$inferSelect[] }>(),
        404: errorSchemas.notFound,
      },
    },
    reset: {
      method: 'POST' as const,
      path: '/api/labs/:id/reset',
      responses: {
        200: z.object({ message: z.string() }),
      },
    },
  },
  resources: {
    list: {
      method: 'GET' as const,
      path: '/api/labs/:labId/resources',
      responses: {
        200: z.array(z.custom<typeof resources.$inferSelect>()),
      },
    },
  },
  terminal: {
    execute: {
      method: 'POST' as const,
      path: '/api/terminal/execute',
      input: z.object({
        command: z.string(),
        labId: z.number(),
      }),
      responses: {
        200: z.object({
          output: z.string(),
          success: z.boolean(),
          labCompleted: z.boolean().optional(),
        }),
      },
    },
  },
  progress: {
    get: {
      method: 'GET' as const,
      path: '/api/progress',
      responses: {
        200: z.array(z.custom<typeof userProgress.$inferSelect & { lab: typeof labs.$inferSelect }>()),
      },
    },
  },
};

export function buildUrl(path: string, params?: Record<string, string | number>): string {
  let url = path;
  if (params) {
    Object.entries(params).forEach(([key, value]) => {
      if (url.includes(`:${key}`)) {
        url = url.replace(`:${key}`, String(value));
      }
    });
  }
  return url;
}
