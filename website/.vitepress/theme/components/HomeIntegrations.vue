<script setup lang="ts">
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
</script>

<template>
  <section class="band" aria-labelledby="integrations-title">
    <h2 id="integrations-title" class="label">Ships logs to</h2>
    <div class="viewport">
      <ul class="track">
        <li v-for="t in targets" :key="t">{{ t }}</li>
      </ul>
      <ul class="track" aria-hidden="true">
        <li v-for="t in targets" :key="`dup-${t}`">{{ t }}</li>
      </ul>
    </div>
  </section>
</template>

<style scoped>
.band {
  display: grid;
  grid-template-columns: auto minmax(0, 1fr);
  align-items: center;
  gap: 32px;
  max-width: 1200px;
  margin: 0 auto;
  padding: 20px 24px;
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

.viewport:hover .track {
  animation-play-state: paused;
}

@keyframes scroll {
  to {
    transform: translateX(-100%);
  }
}

@media (max-width: 768px) {
  .band {
    grid-template-columns: minmax(0, 1fr);
    gap: 12px;
    padding: 16px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .viewport {
    mask-image: none;
  }

  .track {
    flex-wrap: wrap;
    gap: 8px 20px;
    animation: none;
  }

  .track[aria-hidden='true'] {
    display: none;
  }
}
</style>
