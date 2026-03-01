// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import remarkMath from 'remark-math';
import rehypeMathjax from 'rehype-mathjax';
import rehypeKatex from 'rehype-katex';
// https://astro.build/config
export default defineConfig({
    vite: {
        plugins: [tailwindcss()],
    },
    markdown: {
        remarkPlugins: [[remarkMath, { singleDollarTextMath: true }]],
        rehypePlugins: [rehypeKatex]
    }
});
