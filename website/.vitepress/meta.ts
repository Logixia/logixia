/** Shared frontmatter helpers so sidebar, article list and head tags agree on dates and ordering. */

/** Returns `YYYY-MM-DD` for a frontmatter `date`, `''` when absent; throws naming the file when invalid. */
export function readDate(value: unknown, file: string): string {
  if (value === undefined || value === null || value === '') return '';
  const date = value instanceof Date ? value : new Date(String(value));
  if (Number.isNaN(date.getTime())) {
    throw new Error(
      `Invalid frontmatter date ${JSON.stringify(value)} in ${file} (expected YYYY-MM-DD)`
    );
  }
  return date.toISOString().slice(0, 10);
}

export interface ArticleMeta {
  title: string;
  date: string;
}

/** Newest first, then alphabetical by title. */
export function compareArticles(a: ArticleMeta, b: ArticleMeta): number {
  return b.date.localeCompare(a.date) || a.title.localeCompare(b.title);
}
