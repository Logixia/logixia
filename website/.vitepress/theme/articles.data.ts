import { createContentLoader } from 'vitepress';
import { compareArticles, readDate } from '../meta';

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
        date: readDate(frontmatter['date'], `${url.replace(/^\//, '').replace(/\/$/, '')}.md`),
        tags: Array.isArray(frontmatter['tags']) ? frontmatter['tags'].map(String) : [],
      }))
      .sort(compareArticles);
  },
});
