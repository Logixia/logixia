import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import matter from 'gray-matter';
import type { DefaultTheme } from 'vitepress';
import { compareArticles, readDate } from './meta';

interface PageInfo {
  title: string;
  order: number;
  date: string;
  link: string;
}

function titleCase(slug: string): string {
  return slug.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function readPage(file: string, link: string, fallback: string): PageInfo {
  const { data } = matter(readFileSync(file, 'utf8'));
  return {
    title: String(data['title'] ?? fallback),
    order: typeof data['order'] === 'number' ? data['order'] : Number.POSITIVE_INFINITY,
    date: readDate(data['date'], file),
    link,
  };
}

function toItems(pages: PageInfo[]): DefaultTheme.SidebarItem[] {
  return pages.map((p) => ({ text: p.title, link: p.link }));
}

const byOrderThenTitle = (a: PageInfo, b: PageInfo) =>
  a.order - b.order || a.title.localeCompare(b.title);

/** Pages directly inside `dir` (index.md becomes the section root, listed first). */
function pagesIn(srcDir: string, dir: string, base: string): PageInfo[] {
  const abs = join(srcDir, dir);
  return readdirSync(abs)
    .filter((f) => f.endsWith('.md'))
    .map((f) => {
      const slug = f.slice(0, -3);
      const link = slug === 'index' ? `${base}/` : `${base}/${slug}`;
      const page = readPage(join(abs, f), link, titleCase(slug));
      if (slug === 'index' && !Number.isFinite(page.order)) page.order = Number.NEGATIVE_INFINITY;
      return page;
    });
}

function subDirs(srcDir: string, dir: string): string[] {
  const abs = join(srcDir, dir);
  return readdirSync(abs)
    .filter((f) => statSync(join(abs, f)).isDirectory())
    .sort();
}

/** Sidebar for guide/: top-level pages, then one collapsible group per subfolder. */
export function guideSidebar(srcDir: string): DefaultTheme.SidebarItem[] {
  const items = toItems(pagesIn(srcDir, 'guide', '/guide').sort(byOrderThenTitle));
  for (const sub of subDirs(srcDir, 'guide')) {
    const pages = pagesIn(srcDir, `guide/${sub}`, `/guide/${sub}`);
    if (pages.length === 0) continue;
    items.push({
      text: titleCase(sub),
      collapsed: false,
      items: toItems(pages.sort(byOrderThenTitle)),
    });
  }
  return items;
}

/** Sidebar for articles/: the index first, then articles newest first. */
export function articlesSidebar(srcDir: string): DefaultTheme.SidebarItem[] {
  const pages = pagesIn(srcDir, 'articles', '/articles');
  const index = pages.filter((p) => p.link === '/articles/');
  const rest = pages.filter((p) => p.link !== '/articles/').sort(compareArticles);
  return toItems([...index, ...rest]);
}
