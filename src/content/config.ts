import { defineCollection, z } from 'astro:content';

const blogCollection = defineCollection({
    type: 'content',
    schema: z.object({
        title: z.string(),
        description: z.string().optional(),
        date: z.string().transform((str) => new Date(str)),
        categories: z.array(z.string()).optional(),
        category: z.string().default('Security Writeup'),
    }),
});

export const collections = {
    'blog': blogCollection,
};
