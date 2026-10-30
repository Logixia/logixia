<script setup lang="ts">
import { ref } from 'vue';
import { withBase } from 'vitepress';

import Icon from './Icon.vue';

const INSTALL = 'npm i logixia';
const copied = ref(false);
let timer: ReturnType<typeof setTimeout> | undefined;

async function copyInstall(): Promise<void> {
  try {
    await navigator.clipboard.writeText(INSTALL);
    copied.value = true;
    clearTimeout(timer);
    timer = setTimeout(() => (copied.value = false), 1600);
  } catch {
    copied.value = false;
  }
}

const runtimes = ['MIT', 'TypeScript', 'Node', 'Bun', 'Deno', 'Edge'];
</script>

<template>
  <section class="hero" aria-labelledby="hero-title">
    <div class="copy">
      <p class="eyebrow"><span class="dot" aria-hidden="true" />Async-first TypeScript logger</p>
      <h1 id="hero-title">
        One install. <span class="accent">Every transport.</span><br />
        Never blocks the event loop.
      </h1>
      <p class="lede">
        Structured logs, request tracing, redaction and export to files, databases, clouds and OTLP,
        for Node.js, NestJS and the edge. One TypeScript-first library instead of five glued
        together.
      </p>

      <div class="actions">
        <button
          type="button"
          class="install"
          :aria-label="copied ? 'Copied install command' : 'Copy install command'"
          @click="copyInstall"
        >
          <span class="prompt" aria-hidden="true">$</span>
          <code>{{ INSTALL }}</code>
          <Icon :name="copied ? 'check' : 'copy'" :size="16" class="copy-icon" />
        </button>
        <a class="btn primary" :href="withBase('/guide/getting-started')">
          Get started <Icon name="arrow-right" :size="16" />
        </a>
        <a class="btn ghost" href="https://github.com/Logixia/logixia" rel="noopener">GitHub</a>
      </div>

      <ul class="runtimes" aria-label="License and runtimes">
        <li v-for="r in runtimes" :key="r">{{ r }}</li>
      </ul>
    </div>

    <figure class="panel" aria-label="Example: creating a logger, with illustrative output">
      <div class="panel-bar">
        <span class="lights" aria-hidden="true"><i /><i /><i /></span>
        <span class="file">server.ts</span>
      </div>
      <pre
        class="code"
      ><code><span class="k">const</span> logger = <span class="f">createLogger</span>({
  appName: <span class="s">'api'</span>,
  traceId: <span class="k">true</span>,
  redact: { paths: [<span class="s">'**.password'</span>, <span class="s">'**.token'</span>] },
  transports: {
    console:  { format: <span class="s">'text'</span> },
    file:     { filename: <span class="s">'app.log'</span>, maxSize: <span class="s">'50MB'</span> },
    database: { type: <span class="s">'postgresql'</span>, database: <span class="s">'app'</span> },
  },
});

<span class="k">await</span> logger.<span class="f">info</span>(<span class="s">'Server started'</span>, { port: <span class="n">3000</span> });
<span class="k">await</span> logger.<span class="f">warn</span>(<span class="s">'slow query'</span>, { ms: <span class="n">812</span> });
<span class="k">await</span> logger.<span class="f">error</span>(<span class="s">'charge failed'</span>, { password: <span class="s">'hunter2'</span> });</code></pre>
      <div class="output" aria-label="Log output">
        <p class="line" style="--i: 0">
          <span class="lvl info">INFO</span><span class="t">12:04:11</span>Server started
          <span class="kv">port=3000 trace=4bf92f35</span>
        </p>
        <p class="line" style="--i: 1">
          <span class="lvl warn">WARN</span><span class="t">12:04:12</span>slow query
          <span class="kv">ms=812</span>
        </p>
        <p class="line" style="--i: 2">
          <span class="lvl error">ERROR</span><span class="t">12:04:13</span>charge failed
          <span class="kv">password=[REDACTED]</span><span class="caret" aria-hidden="true" />
        </p>
      </div>
    </figure>
  </section>
</template>

<style scoped>
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr);
  gap: 56px;
  align-items: center;
  max-width: 1200px;
  margin: 0 auto;
  padding: 72px 24px 56px;
}

.eyebrow {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  margin: 0 0 24px;
  padding: 6px 14px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 999px;
  background: var(--vp-c-bg-alt);
  font-family: var(--vp-font-family-mono);
  font-size: 11.5px;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--vp-c-text-2);
}

.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--lx-green);
  animation: pulse 2.4s ease-in-out infinite;
}

h1 {
  margin: 0;
  font-size: clamp(36px, 5vw, 58px);
  line-height: 1.04;
  font-weight: 700;
  letter-spacing: -0.045em;
  color: var(--vp-c-text-1);
}

.accent {
  color: var(--vp-c-brand-1);
}

.lede {
  max-width: 56ch;
  margin: 24px 0 0;
  font-size: 17px;
  line-height: 1.65;
  color: var(--vp-c-text-2);
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin-top: 32px;
}

.install,
.btn {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  height: 44px;
  padding: 0 18px;
  border-radius: 10px;
  font-size: 14px;
  font-weight: 600;
  text-decoration: none;
  transition:
    transform 0.2s cubic-bezier(0.16, 1, 0.3, 1),
    background-color 0.2s,
    border-color 0.2s,
    color 0.2s;
}

.install {
  border: 1px solid var(--vp-c-divider);
  background: var(--vp-c-bg-alt);
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-mono);
  cursor: pointer;
}

.install code {
  padding: 0;
  border: 0;
  background: none;
  font-size: 14px;
  color: inherit;
}

.prompt {
  color: var(--vp-c-text-3);
}

.copy-icon {
  color: var(--vp-c-text-3);
}

.install:hover {
  border-color: var(--vp-c-brand-2);
}

.install:hover .copy-icon {
  color: var(--vp-c-brand-1);
}

.btn.primary {
  background: var(--vp-c-brand-3);
  color: #fff;
}

.btn.primary:hover {
  background: var(--vp-c-brand-2);
}

.btn.ghost {
  border: 1px solid var(--vp-c-divider);
  color: var(--vp-c-text-1);
}

.btn.ghost:hover {
  border-color: var(--vp-c-text-3);
}

.install:active,
.btn:active {
  transform: translateY(1px);
}

.runtimes {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px 0;
  margin: 24px 0 0;
  padding: 0;
  list-style: none;
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
  color: var(--vp-c-text-3);
}

.runtimes li {
  margin: 0;
  line-height: 1.4;
}

.runtimes li + li::before {
  content: '·';
  margin: 0 10px;
  color: var(--vp-c-text-3);
}

/* ── Terminal panel ─────────────────────────────────────────────────── */

.panel {
  margin: 0;
  overflow: hidden;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  background: var(--lx-panel-bg);
  box-shadow:
    inset 0 1px 0 rgba(255, 255, 255, 0.04),
    0 30px 60px -30px rgba(10, 6, 20, 0.6);
}

.panel-bar {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 12px 16px;
  border-bottom: 1px solid var(--vp-c-divider);
}

.lights {
  display: inline-flex;
  gap: 6px;
}

.lights i {
  width: 9px;
  height: 9px;
  border-radius: 50%;
  background: var(--vp-c-divider);
}

.file {
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
  color: var(--vp-c-text-3);
}

.code {
  margin: 0;
  padding: 18px 20px;
  overflow-x: auto;
  font-family: var(--vp-font-family-mono);
  font-size: 13px;
  line-height: 1.7;
  color: var(--vp-c-text-1);
}

.code code {
  padding: 0;
  background: none;
  font-size: inherit;
  color: inherit;
}

.k {
  color: var(--vp-c-brand-1);
}

.f {
  color: var(--vp-c-text-1);
  font-weight: 500;
}

.s {
  color: var(--lx-code-str);
}

.n {
  color: var(--lx-code-num);
}

.output {
  padding: 14px 20px 18px;
  border-top: 1px solid var(--vp-c-divider);
  font-family: var(--vp-font-family-mono);
  font-size: 12.5px;
}

.line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 4px 12px;
  margin: 0;
  padding: 4px 0;
  line-height: 1.5;
  color: var(--vp-c-text-1);
  opacity: 0;
  transform: translateY(4px);
  animation: line-in 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards;
  animation-delay: calc(0.6s + var(--i) * 0.45s);
}

.lvl {
  min-width: 48px;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  text-align: center;
}

.lvl.info {
  color: var(--lx-code-str);
  background: rgba(74, 222, 128, 0.12);
}

.lvl.warn {
  color: var(--lx-code-num);
  background: rgba(251, 191, 36, 0.12);
}

.lvl.error {
  color: var(--lx-code-err);
  background: rgba(248, 113, 113, 0.12);
}

.t,
.kv {
  color: var(--vp-c-text-3);
}

.caret {
  width: 7px;
  height: 14px;
  background: var(--vp-c-brand-1);
  animation: blink 1.1s steps(1) infinite;
}

@keyframes line-in {
  to {
    opacity: 1;
    transform: none;
  }
}

@keyframes blink {
  50% {
    opacity: 0;
  }
}

@keyframes pulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(74, 222, 128, 0.45);
  }
  50% {
    box-shadow: 0 0 0 5px rgba(74, 222, 128, 0);
  }
}

@media (max-width: 960px) {
  .hero {
    grid-template-columns: minmax(0, 1fr);
    gap: 40px;
    padding: 48px 16px 40px;
  }
}

@media (prefers-reduced-motion: reduce) {
  .line {
    opacity: 1;
    transform: none;
    animation: none;
  }

  .dot,
  .caret {
    animation: none;
  }
}
</style>
