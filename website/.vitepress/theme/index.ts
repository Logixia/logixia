import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';

import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';
import { h } from 'vue';

import ArticleList from './components/ArticleList.vue';
// Loaded after the default theme so these brand tokens override its variables.
import './custom.css';

export default {
  extends: DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      'home-hero-info-before': () =>
        h('div', { class: 'lx-eyebrow' }, 'Async-first TypeScript logger'),
    }),
  enhanceApp({ app }) {
    app.component('ArticleList', ArticleList);
  },
} satisfies Theme;
