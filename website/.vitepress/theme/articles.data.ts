import { createContentLoader } from 'vitepress';

export interface ArticleEntry {
  url: string;
  title: string;
  description: string;
  date: string;
  tags: string[];
}

declare const data: ArticleEntry[];
export { data };

export default createContentLoader(['articles/*.md', '!articles/index.md'], {
  transform(raw): ArticleEntry[] {
    return raw
      .map(({ url, frontmatter }) => ({
        url,
        title: String(frontmatter['title'] ?? url),
        description: String(frontmatter['description'] ?? ''),
        date: frontmatter['date'] ? new Date(frontmatter['date']).toISOString().slice(0, 10) : '',
        tags: Array.isArray(frontmatter['tags']) ? frontmatter['tags'].map(String) : [],
      }))
      .sort((a, b) => b.date.localeCompare(a.date) || a.title.localeCompare(b.title));
  },
});
