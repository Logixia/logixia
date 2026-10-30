import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, type HeadConfig } from 'vitepress';
import { readDate } from './meta';
import { articlesSidebar, guideSidebar } from './sidebar';

const BASE = '/logixia/';
const HOST = 'https://logixia.github.io';
const SITE = `${HOST}${BASE}`;
const REPO = 'https://github.com/Logixia/logixia';
const SITE_DESCRIPTION =
  'Structured logging, request tracing and multi-destination export for Node.js, NestJS and the edge, in one TypeScript-first library.';
const srcDir = fileURLToPath(new URL('..', import.meta.url));

const pageUrl = (relativePath: string): string =>
  SITE + relativePath.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '');

const jsonLd = (data: unknown): HeadConfig => [
  'script',
  { type: 'application/ld+json' },
  JSON.stringify(data).replace(/</g, '\\u003c'),
];

function breadcrumbs(relativePath: string, title: string) {
  const parts = relativePath
    .replace(/(^|\/)index\.md$/, '')
    .replace(/\.md$/, '')
    .split('/');
  const trail = [{ name: 'Home', url: SITE }];
  let acc = '';
  parts.forEach((part, i) => {
    acc += `${part}/`;
    const last = i === parts.length - 1;
    if (!last && !existsSync(`${srcDir}${acc}index.md`)) return;
    trail.push({
      name: last ? title : part.charAt(0).toUpperCase() + part.slice(1),
      url: last ? pageUrl(relativePath) : SITE + acc,
    });
  });
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: trail.map((t, i) => ({
      '@type': 'ListItem',
      position: i + 1,
      name: t.name,
      item: t.url,
    })),
  };
}

export default defineConfig({
  lang: 'en-US',
  title: 'logixia',
  titleTemplate: ':title | logixia',
  description: SITE_DESCRIPTION,
  base: BASE,
  cleanUrls: true,
  appearance: 'dark',
  srcExclude: ['README.md'],
  lastUpdated: true,
  sitemap: { hostname: SITE },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${BASE}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#0b0b0f' }],
    ['meta', { name: 'author', content: 'logixia contributors' }],
  ],

  markdown: { theme: { light: 'github-light', dark: 'github-dark' } },

  themeConfig: {
    logo: { src: '/logo.svg', alt: '' },
    siteTitle: 'logixia',
    nav: [
      { text: 'Guide', link: '/guide/getting-started', activeMatch: '/guide/' },
      { text: 'Articles', link: '/articles/', activeMatch: '/articles/' },
      { text: 'Changelog', link: `${REPO}/blob/main/CHANGELOG.md` },
    ],
    sidebar: {
      '/guide/': guideSidebar(srcDir),
      '/articles/': articlesSidebar(srcDir),
    },
    socialLinks: [
      { icon: 'github', link: REPO },
      { icon: 'npm', link: 'https://www.npmjs.com/package/logixia' },
    ],
    search: { provider: 'local' },
    editLink: {
      pattern: 'https://github.com/Logixia/logixia/edit/main/website/:path',
      text: 'Edit this page on GitHub',
    },
    lastUpdated: { text: 'Last updated' },
    outline: { level: [2, 3] },
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © logixia contributors',
    },
  },

  transformHead({ pageData }) {
    const { relativePath, frontmatter, title, description } = pageData;
    if (relativePath === '404.md') return [];

    const url = pageUrl(relativePath);
    const isHome = relativePath === 'index.md';
    const isArticle = /^articles\/(?!index\.md$)/.test(relativePath);
    const pageTitle = isHome ? String(title) : `${title} | logixia`;
    const pageDescription = description || SITE_DESCRIPTION;
    const image = String(frontmatter['image'] ?? `${SITE}og.png`);
    const absImage = image.startsWith('http') ? image : SITE + image.replace(/^\//, '');
    const modified = pageData.lastUpdated
      ? new Date(pageData.lastUpdated).toISOString()
      : undefined;
    const publishedDay = readDate(frontmatter['date'], relativePath);
    const published = publishedDay ? `${publishedDay}T00:00:00.000Z` : modified;
    const dateModified = modified ?? published;

    const head: HeadConfig[] = [
      ['link', { rel: 'canonical', href: url }],
      ['meta', { property: 'og:site_name', content: 'logixia' }],
      ['meta', { property: 'og:type', content: isArticle ? 'article' : 'website' }],
      ['meta', { property: 'og:title', content: pageTitle }],
      ['meta', { property: 'og:description', content: pageDescription }],
      ['meta', { property: 'og:url', content: url }],
      ['meta', { property: 'og:image', content: absImage }],
      ['meta', { property: 'og:image:width', content: '1200' }],
      ['meta', { property: 'og:image:height', content: '630' }],
      ['meta', { name: 'twitter:card', content: 'summary_large_image' }],
      ['meta', { name: 'twitter:title', content: pageTitle }],
      ['meta', { name: 'twitter:description', content: pageDescription }],
      ['meta', { name: 'twitter:image', content: absImage }],
    ];

    if (isArticle) {
      if (published)
        head.push(['meta', { property: 'article:published_time', content: published }]);
      if (modified) head.push(['meta', { property: 'article:modified_time', content: modified }]);
      for (const tag of Array.isArray(frontmatter['tags']) ? frontmatter['tags'] : []) {
        head.push(['meta', { property: 'article:tag', content: String(tag) }]);
      }
    }

    if (isHome) {
      head.push(
        jsonLd({
          '@context': 'https://schema.org',
          '@type': 'SoftwareSourceCode',
          name: 'logixia',
          description: SITE_DESCRIPTION,
          url: SITE,
          codeRepository: REPO,
          programmingLanguage: 'TypeScript',
          runtimePlatform: 'Node.js',
          license: 'https://opensource.org/licenses/MIT',
          author: { '@type': 'Organization', name: 'logixia contributors' },
        }),
        jsonLd({
          '@context': 'https://schema.org',
          '@type': 'SoftwareApplication',
          name: 'logixia',
          description: SITE_DESCRIPTION,
          url: SITE,
          applicationCategory: 'DeveloperApplication',
          operatingSystem: 'Any',
          offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
        })
      );
    } else if (isArticle) {
      head.push(
        jsonLd({
          '@context': 'https://schema.org',
          '@type': 'TechArticle',
          headline: String(title),
          description: pageDescription,
          url,
          mainEntityOfPage: url,
          image: absImage,
          ...(published ? { datePublished: published } : {}),
          ...(dateModified ? { dateModified } : {}),
          author: { '@type': 'Organization', name: 'logixia contributors' },
          publisher: { '@type': 'Organization', name: 'logixia', url: SITE },
          ...(Array.isArray(frontmatter['tags'])
            ? { keywords: frontmatter['tags'].join(', ') }
            : {}),
        }),
        jsonLd(breadcrumbs(relativePath, String(title)))
      );
    } else if (relativePath.startsWith('guide/')) {
      head.push(jsonLd(breadcrumbs(relativePath, String(title))));
    }

    return head;
  },
});
