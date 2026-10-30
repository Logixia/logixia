<script setup lang="ts">
import { withBase } from 'vitepress';
import { data as articles } from '../articles.data';
</script>

<template>
  <p v-if="articles.length === 0">No articles yet.</p>
  <ul v-else class="article-list">
    <li v-for="a in articles" :key="a.url" class="article-card">
      <h2 class="article-title">
        <a :href="withBase(a.url)">{{ a.title }}</a>
      </h2>
      <p class="article-meta">
        <time v-if="a.date" :datetime="a.date">{{ a.date }}</time>
        <span v-for="t in a.tags" :key="t" class="article-tag">{{ t }}</span>
      </p>
      <p class="article-desc">{{ a.description }}</p>
    </li>
  </ul>
</template>

<style scoped>
.article-list {
  list-style: none;
  padding: 0;
  margin: 24px 0 0;
  display: grid;
  gap: 16px;
}
.article-card {
  margin: 0;
  padding: 16px 20px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--vp-c-bg-soft);
}
.article-card:focus-within,
.article-card:hover {
  border-color: var(--vp-c-brand-1);
}
.article-title {
  margin: 0;
  padding: 0;
  border: 0;
  font-size: 1.15rem;
  line-height: 1.4;
}
.article-meta {
  margin: 6px 0;
  font-size: 0.85rem;
  color: var(--vp-c-text-2);
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.article-tag {
  padding: 0 8px;
  border-radius: 999px;
  background: var(--vp-c-brand-soft);
  color: var(--vp-c-brand-1);
}
.article-desc {
  margin: 0;
  color: var(--vp-c-text-2);
}
</style>
