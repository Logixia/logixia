import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';

import type { Theme } from 'vitepress';
import DefaultTheme from 'vitepress/theme';

import ArticleList from './components/ArticleList.vue';
import HomeBento from './components/HomeBento.vue';
import HomeHero from './components/HomeHero.vue';
import HomeIntegrations from './components/HomeIntegrations.vue';
// Loaded after the default theme so these brand tokens override its variables.
import './custom.css';

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ArticleList', ArticleList);
    app.component('HomeHero', HomeHero);
    app.component('HomeIntegrations', HomeIntegrations);
    app.component('HomeBento', HomeBento);
  },
} satisfies Theme;
