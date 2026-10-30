import DefaultTheme from 'vitepress/theme';
import type { Theme } from 'vitepress';
import ArticleList from './components/ArticleList.vue';
import './custom.css';

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('ArticleList', ArticleList);
  },
} satisfies Theme;
