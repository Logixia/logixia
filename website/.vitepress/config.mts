import { existsSync, readFileSync } from 'node:fs';
import llmstxt from 'vitepress-plugin-llms';
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

const VERSION = process.env['LOGIXIA_VERSION'];
const NPM = 'https://www.npmjs.com/package/logixia';
const ORG_ID = `${SITE}#organization`;
const SITE_ID = `${SITE}#website`;
const SOFTWARE_ID = `${SITE}#software`;
const organization = {
  '@type': 'Organization',
  '@id': ORG_ID,
  name: 'logixia',
  url: SITE,
  logo: { '@type': 'ImageObject', url: `${SITE}logo.svg` },
  sameAs: [REPO, NPM, 'https://github.com/Logixia'],
};
const website = {
  '@type': 'WebSite',
  '@id': SITE_ID,
  url: SITE,
  name: 'logixia',
  description: SITE_DESCRIPTION,
  inLanguage: 'en-US',
  publisher: { '@id': ORG_ID },
};
const software = {
  '@type': ['SoftwareApplication', 'SoftwareSourceCode'],
  '@id': SOFTWARE_ID,
  name: 'logixia',
  alternateName: 'logixia logger',
  description: SITE_DESCRIPTION,
  url: SITE,
  sameAs: [REPO, NPM],
  codeRepository: REPO,
  downloadUrl: NPM,
  installUrl: `${SITE}guide/getting-started`,
  programmingLanguage: { '@type': 'ComputerLanguage', name: 'TypeScript' },
  runtimePlatform: ['Node.js', 'Cloudflare Workers', 'Web browsers'],
  applicationCategory: 'DeveloperApplication',
  applicationSubCategory: 'Logging library',
  operatingSystem: 'Cross-platform',
  softwareRequirements: 'Node.js 16 or later',
  keywords:
    'TypeScript logger, Node.js logging, NestJS logger, structured logging, request tracing, log redaction, OpenTelemetry, OTLP',
  license: 'https://opensource.org/licenses/MIT',
  isAccessibleForFree: true,
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
  author: { '@id': ORG_ID },
  publisher: { '@id': ORG_ID },
  ...(VERSION ? { softwareVersion: VERSION } : {}),
};
const graph = (...nodes: unknown[]): HeadConfig =>
  jsonLd({ '@context': 'https://schema.org', '@graph': nodes });
const stripContext = (n: object) => {
  const { '@context': _c, ...rest } = n as Record<string, unknown>;
  return rest;
};
function authorOf(frontmatter: Record<string, unknown>) {
  const a = frontmatter['author'] as { name?: string; url?: string } | undefined;
  return a?.name
    ? { '@type': 'Person', name: a.name, ...(a.url ? { url: a.url } : {}) }
    : { '@id': ORG_ID };
}
const plain = (s: string) =>
  s
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/[*_`]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
function faqPairs(relativePath: string): { q: string; a: string }[] {
  const md = readFileSync(`${srcDir}${relativePath}`, 'utf8').replace(/^---[\s\S]*?\n---\n/, '');
  if (relativePath === 'guide/faq.md') {
    return md
      .split(/^## /m)
      .slice(1)
      .map((block) => {
        const [q = '', ...rest] = block.split('\n');
        return { q: plain(q), a: plain(rest.join('\n').split(/\n```/)[0] ?? '') };
      })
      .filter((p) => p.q && p.a);
  }
  const section = md.split(/^## FAQ\s*$/m)[1]?.split(/^## /m)[0] ?? '';
  return [...section.matchAll(/^\*\*(.+?\?)\*\*\s*(.+)$/gm)].map((m) => ({
    q: plain(m[1] ?? ''),
    a: plain(m[2] ?? ''),
  }));
}
const faqNode = (url: string, pairs: { q: string; a: string }[]) => ({
  '@type': 'FAQPage',
  '@id': `${url}#faq`,
  url,
  mainEntity: pairs.map((p) => ({
    '@type': 'Question',
    name: p.q,
    acceptedAnswer: { '@type': 'Answer', text: p.a },
  })),
});

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
  vite: {
    plugins: [
      llmstxt({
        domain: 'https://logixia.github.io',
        generateLLMsTxt: false,
        generateLLMsFullTxt: true,
        generateLLMFriendlyDocsForEachPage: true,
        injectLLMHint: false,
        ignoreFiles: ['README.md', '404.md'],
      }),
    ],
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${BASE}favicon.svg` }],
    ['meta', { name: 'theme-color', content: '#0b0b0f' }],
    ['meta', { name: 'author', content: 'logixia contributors' }],
    ['link', { rel: 'describedby', href: `${BASE}llms.txt` }],
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

    const isGuide = relativePath.startsWith('guide/');
    if (isHome) {
      head.push(graph(organization, website, software));
    } else if (isArticle || isGuide) {
      const nodes: object[] = [
        {
          '@type': 'TechArticle',
          '@id': `${url}#article`,
          headline: String(title).slice(0, 110),
          description: pageDescription,
          url,
          mainEntityOfPage: url,
          image: absImage,
          inLanguage: 'en-US',
          isPartOf: { '@id': SITE_ID },
          about: { '@id': SOFTWARE_ID },
          ...(published ? { datePublished: published } : {}),
          ...(dateModified ? { dateModified } : {}),
          author: authorOf(frontmatter),
          publisher: { '@id': ORG_ID },
          ...(Array.isArray(frontmatter['tags'])
            ? { keywords: frontmatter['tags'].join(', ') }
            : {}),
        },
        stripContext(breadcrumbs(relativePath, String(title))),
        organization,
        { '@type': 'WebSite', '@id': SITE_ID, url: SITE, name: 'logixia' },
        {
          '@type': 'SoftwareSourceCode',
          '@id': SOFTWARE_ID,
          name: 'logixia',
          url: SITE,
          codeRepository: REPO,
        },
      ];
      const pairs = faqPairs(relativePath);
      if (pairs.length) nodes.push(faqNode(url, pairs));
      head.push(graph(...nodes));
    } else if (relativePath === 'articles/index.md') {
      head.push(
        graph(
          {
            '@type': 'CollectionPage',
            '@id': `${url}#page`,
            url,
            name: String(title),
            isPartOf: { '@id': SITE_ID },
            about: { '@id': SOFTWARE_ID },
          },
          stripContext(breadcrumbs(relativePath, String(title)))
        )
      );
    }

    return head;
  },
});
