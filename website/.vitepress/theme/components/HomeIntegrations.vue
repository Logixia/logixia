<script setup lang="ts">
import { ref } from 'vue';

const targets = [
  'Console',
  'Rotating files',
  'PostgreSQL',
  'MySQL',
  'MongoDB',
  'SQLite',
  'AWS CloudWatch',
  'Google Cloud Logging',
  'Azure Monitor',
  'Datadog',
  'OTLP',
  'Mixpanel',
  'Segment',
  'Google Analytics',
  'Slack',
  'Discord',
  'Worker threads',
];

// WCAG 2.2.2: moving content needs a control to pause it, not only hover.
const paused = ref(false);
</script>

<template>
  <section class="band" :class="{ paused }" aria-labelledby="integrations-title">
    <h2 id="integrations-title" class="label">Ships logs to</h2>
    <div class="viewport">
      <ul class="track">
        <li v-for="t in targets" :key="t">{{ t }}</li>
      </ul>
      <ul class="track dup" aria-hidden="true">
        <li v-for="t in targets" :key="`dup-${t}`">{{ t }}</li>
      </ul>
    </div>
    <button
      type="button"
      class="toggle"
      :aria-pressed="paused"
      :aria-label="paused ? 'Resume scrolling list' : 'Pause scrolling list'"
      @click="paused = !paused"
    >
      <svg v-if="paused" viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
        <path d="M7 5v14l11-7z" fill="currentColor" />
      </svg>
      <svg v-else viewBox="0 0 24 24" width="14" height="14" aria-hidden="true">
        <path d="M7 5h3v14H7zM14 5h3v14h-3z" fill="currentColor" />
      </svg>
    </button>
  </section>
</template>

<style scoped>
.band {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 24px;
  max-width: 1200px;
  margin: 0 auto;
  padding: 18px 24px;
  border-top: 1px solid var(--vp-c-divider);
  border-bottom: 1px solid var(--vp-c-divider);
}

.label {
  margin: 0;
  padding: 0;
  border: 0;
  font-family: var(--vp-font-family-mono);
  font-size: 11.5px;
  font-weight: 500;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--vp-c-text-3);
  white-space: nowrap;
}

.viewport {
  display: flex;
  overflow: hidden;
  mask-image: linear-gradient(90deg, transparent, #000 8%, #000 92%, transparent);
}

.track {
  display: flex;
  flex: none;
  gap: 36px;
  margin: 0;
  padding: 0 18px;
  list-style: none;
  animation: scroll 48s linear infinite;
}

.track li {
  margin: 0;
  font-size: 14px;
  font-weight: 500;
  white-space: nowrap;
  color: var(--vp-c-text-2);
}

.viewport:hover .track,
.paused .track {
  animation-play-state: paused;
}

.toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  color: var(--vp-c-text-2);
  background: var(--vp-c-bg-alt);
  cursor: pointer;
}

.toggle:hover {
  color: var(--vp-c-text-1);
  border-color: var(--vp-c-text-3);
}

.toggle:focus-visible {
  outline: 2px solid var(--vp-c-brand-1);
  outline-offset: 2px;
}

@keyframes scroll {
  to {
    transform: translateX(-100%);
  }
}

@media (max-width: 768px) {
  .band {
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 12px;
    padding: 16px;
  }

  .viewport {
    grid-column: 1 / -1;
    grid-row: 2;
  }
}

@media (prefers-reduced-motion: reduce) {
  .band {
    grid-template-columns: auto minmax(0, 1fr);
  }

  .viewport {
    overflow: visible;
    mask-image: none;
  }

  .track {
    flex: 1 1 100%;
    flex-wrap: wrap;
    gap: 8px 24px;
    padding: 0;
    animation: none;
  }

  .track li {
    white-space: normal;
  }

  .dup,
  .toggle {
    display: none;
  }
}
</style>
