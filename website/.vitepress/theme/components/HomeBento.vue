<script setup lang="ts">
import { withBase } from 'vitepress';

import Icon from './Icon.vue';

const transports = [
  ['Console', 'pretty or JSON'],
  ['File', 'size and date rotation'],
  ['PostgreSQL · MySQL · MongoDB', 'batched inserts'],
  ['CloudWatch · GCP · Azure', 'signed, batched'],
  ['Datadog · OTLP', 'batched export'],
  ['Slack · Discord', 'throttled alerts'],
];

const extras = [
  {
    icon: 'sliders-horizontal',
    title: 'Sampling and runtime levels',
    text: 'Rate-limit noisy logs, set levels per namespace, change them at runtime.',
    link: '/guide/sampling',
  },
  {
    icon: 'chart-line',
    title: 'Prometheus metrics',
    text: 'Turn log events into counters and histograms in the text exposition format.',
    link: '/guide/metrics',
  },
  {
    icon: 'power',
    title: 'Graceful shutdown',
    text: 'flushOnExit drains buffered entries on SIGTERM and SIGINT.',
    link: '/guide/graceful-shutdown',
  },
  {
    icon: 'terminal',
    title: 'CLI and log search',
    text: 'Tail, query, analyze and export logs from the terminal or from code.',
    link: '/guide/cli',
  },
  {
    icon: 'braces',
    title: 'Typed log schemas',
    text: 'defineLogSchema gives you compile-time checked events and fields.',
    link: '/guide/typed-logger',
  },
  {
    icon: 'package-check',
    title: 'Supply-chain conscious',
    text: 'npm provenance, no install scripts, three runtime dependencies.',
    link: '/guide/security',
  },
];
</script>

<template>
  <section class="features" aria-labelledby="features-title">
    <header class="head">
      <p class="kicker">What you get</p>
      <h2 id="features-title">Everything a production logger needs, in one package.</h2>
    </header>

    <div class="bento">
      <!-- Tracing -->
      <article class="tile span-7">
        <div class="tile-head">
          <Icon name="waypoints" />
          <h3>Request tracing across async calls</h3>
        </div>
        <p class="desc">
          Express, Fastify and NestJS helpers read <code>traceparent</code> or
          <code>x-trace-id</code> and put the trace ID on every log line in the request, without
          passing a logger around.
        </p>
        <div class="demo trace" aria-label="Three log lines sharing one trace ID">
          <p class="req">
            <span class="method">GET</span> /orders/42
            <span class="hdr">traceparent: 00-4bf92f35…-01</span>
          </p>
          <p v-for="l in ['auth ok', 'orders.find 38ms', 'response 200']" :key="l" class="tl">
            <span class="tid">4bf92f35</span><span class="msg">{{ l }}</span>
          </p>
        </div>
        <a class="more" :href="withBase('/guide/tracing')"
          >Tracing guide <Icon name="arrow-right" :size="14"
        /></a>
      </article>

      <!-- Redaction -->
      <article class="tile span-5">
        <div class="tile-head">
          <Icon name="shield-check" />
          <h3>Redaction before anything is written</h3>
        </div>
        <p class="desc">
          Paths with wildcards, regex patterns or <code>autoDetect</code>. Nested errors and URLs
          included.
        </p>
        <div class="demo redact" aria-label="A password field before and after redaction">
          <pre><code>{ <span class="key">"user"</span>: <span class="str">"ada"</span>,
  <span class="key">"password"</span>: <span class="str strike">"hunter2"</span> }</code></pre>
          <span class="arrow" aria-hidden="true"><Icon name="arrow-right" :size="16" /></span>
          <pre><code>{ <span class="key">"user"</span>: <span class="str">"ada"</span>,
  <span class="key">"password"</span>: <span class="ok">"[REDACTED]"</span> }</code></pre>
        </div>
        <a class="more" :href="withBase('/guide/redaction')"
          >Redaction guide <Icon name="arrow-right" :size="14"
        /></a>
      </article>

      <!-- Transports -->
      <article class="tile span-5">
        <div class="tile-head">
          <Icon name="send" />
          <h3>One call, many destinations</h3>
        </div>
        <p class="desc">
          Transports batch and retry off the hot path, so a slow sink never blocks a request.
        </p>
        <ul class="demo sinks">
          <li v-for="[name, note] in transports" :key="name">
            <span class="status" aria-hidden="true" /><span class="sink">{{ name }}</span
            ><span class="note">{{ note }}</span>
          </li>
        </ul>
        <a class="more" :href="withBase('/guide/transports/')"
          >All transports <Icon name="arrow-right" :size="14"
        /></a>
      </article>

      <!-- OpenTelemetry -->
      <article class="tile span-7">
        <div class="tile-head">
          <Icon name="telescope" />
          <h3>OpenTelemetry correlation and OTLP export</h3>
        </div>
        <p class="desc">
          Stamp entries with the active span and ship them to any OTLP collector, so logs link
          straight to their traces.
        </p>
        <pre class="demo otel" aria-label="A JSON log entry carrying trace and span IDs"><code>{
  <span class="key">"level"</span>: <span class="str">"info"</span>,
  <span class="key">"message"</span>: <span class="str">"Order created"</span>,
  <span class="key">"traceId"</span>: <span class="hl">"4bf92f3577b34da6a3ce929d0e0e4736"</span>,
  <span class="key">"spanId"</span>: <span class="hl">"00f067aa0ba902b7"</span>,
  <span class="key">"orderId"</span>: <span class="str">"ord_42"</span>
}</code></pre>
        <a class="more" :href="withBase('/guide/opentelemetry')"
          >OpenTelemetry guide <Icon name="arrow-right" :size="14"
        /></a>
      </article>

      <!-- NestJS -->
      <article class="tile span-8">
        <div class="tile-head">
          <Icon name="boxes" />
          <h3>First-class NestJS</h3>
        </div>
        <p class="desc">
          A global module, an injectable service, an exception filter and <code>@LogMethod</code>,
          all from <code>logixia/nest</code>.
        </p>
        <pre
          class="demo snippet"
        ><code><span class="kw">import</span> { LogixiaLoggerModule } <span class="kw">from</span> <span class="str">'logixia/nest'</span>;

<span class="dec">@Module</span>({
  imports: [LogixiaLoggerModule.<span class="fn">forRoot</span>({ appName: <span class="str">'api'</span>, traceId: <span class="kw">true</span> })],
})
<span class="kw">export class</span> AppModule {}</code></pre>
        <a class="more" :href="withBase('/guide/nestjs')"
          >NestJS guide <Icon name="arrow-right" :size="14"
        /></a>
      </article>

      <!-- Edge -->
      <article class="tile span-4">
        <div class="tile-head">
          <Icon name="globe" />
          <h3>Browser and edge</h3>
        </div>
        <p class="desc">
          <code>logixia/browser</code> has no Node globals. It runs in browsers and Cloudflare
          Workers, with a batching remote transport.
        </p>
        <pre class="demo snippet"><code><span class="kw">import</span> { createBrowserLogger }
  <span class="kw">from</span> <span class="str">'logixia/browser'</span>;</code></pre>
        <a class="more" :href="withBase('/guide/browser-and-edge')"
          >Edge guide <Icon name="arrow-right" :size="14"
        /></a>
      </article>
    </div>

    <ul class="extras">
      <li v-for="e in extras" :key="e.title">
        <a :href="withBase(e.link)">
          <Icon :name="e.icon" />
          <span>
            <strong>{{ e.title }}</strong>
            <span>{{ e.text }}</span>
          </span>
        </a>
      </li>
    </ul>
  </section>
</template>

<style scoped>
.features {
  max-width: 1200px;
  margin: 0 auto;
  padding: 96px 24px 24px;
}

.head {
  max-width: 640px;
  margin-bottom: 40px;
}

.kicker {
  margin: 0 0 12px;
  font-family: var(--vp-font-family-mono);
  font-size: 12px;
  letter-spacing: 0.16em;
  text-transform: uppercase;
  color: var(--vp-c-brand-1);
}

.head h2 {
  margin: 0;
  padding: 0;
  border: 0;
  font-size: clamp(26px, 3.4vw, 38px);
  line-height: 1.12;
  font-weight: 700;
  letter-spacing: -0.035em;
  color: var(--vp-c-text-1);
}

.bento {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 16px;
}

.span-4 {
  grid-column: span 4;
}

.span-5 {
  grid-column: span 5;
}

.span-7 {
  grid-column: span 7;
}

.span-8 {
  grid-column: span 8;
}

.tile {
  display: flex;
  flex-direction: column;
  gap: 14px;
  padding: 28px;
  border: 1px solid var(--lx-card-border);
  border-radius: 20px;
  background: var(--lx-card-bg);
  transition: border-color 0.3s cubic-bezier(0.16, 1, 0.3, 1);
}

.tile:hover {
  border-color: color-mix(in srgb, var(--vp-c-brand-2) 55%, var(--lx-card-border));
}

.tile-head {
  display: flex;
  align-items: center;
  gap: 10px;
  color: var(--vp-c-brand-1);
}

.tile h3 {
  margin: 0;
  font-size: 17px;
  font-weight: 650;
  letter-spacing: -0.015em;
  color: var(--vp-c-text-1);
}

.desc {
  margin: 0;
  max-width: 60ch;
  font-size: 14.5px;
  line-height: 1.6;
  color: var(--vp-c-text-2);
}

.desc code {
  font-size: 13px;
}

.demo {
  margin: 4px 0 0;
  padding: 16px 18px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 12px;
  background: var(--lx-panel-bg);
  font-family: var(--vp-font-family-mono);
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--vp-c-text-1);
}

.demo code {
  padding: 0;
  background: none;
  font-size: inherit;
  color: inherit;
}

pre.demo {
  overflow-x: auto;
}

.more {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  margin-top: auto;
  padding-top: 4px;
  font-size: 13.5px;
  font-weight: 600;
  color: var(--vp-c-brand-1);
  text-decoration: none;
}

.more:hover {
  text-decoration: underline;
  text-underline-offset: 3px;
}

/* Tracing demo */
.trace p {
  margin: 0;
}

.req {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 10px;
  padding-bottom: 8px;
  margin-bottom: 6px !important;
  border-bottom: 1px dashed var(--vp-c-divider);
  color: var(--vp-c-text-2);
}

.method {
  color: var(--lx-code-str);
  font-weight: 600;
}

.hdr {
  color: var(--vp-c-text-3);
}

.tl {
  display: flex;
  gap: 12px;
  padding: 3px 0;
}

.tid {
  padding: 0 6px;
  border-radius: 4px;
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
}

.msg {
  color: var(--vp-c-text-1);
}

/* Redaction demo */
.redact {
  display: grid;
  grid-template-columns: minmax(0, 1fr);
  gap: 6px;
}

.redact pre {
  margin: 0;
  overflow-x: auto;
  white-space: pre;
}

.arrow {
  justify-self: start;
  margin-left: 4px;
  color: var(--vp-c-text-3);
  transform: rotate(90deg);
}

.key {
  color: var(--vp-c-text-2);
}

.str {
  color: var(--vp-c-text-1);
}

.strike {
  text-decoration: line-through;
  text-decoration-color: #f87171;
  color: var(--vp-c-text-3);
}

.ok {
  color: var(--lx-code-str);
}

.hl {
  padding: 0 3px;
  border-radius: 3px;
  color: var(--vp-c-brand-1);
  background: var(--vp-c-brand-soft);
}

/* Transports demo */
.sinks {
  list-style: none;
  display: grid;
  gap: 2px;
}

.sinks li {
  margin: 0;
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  align-items: center;
  gap: 10px;
  padding: 5px 0;
}

.sinks li + li {
  border-top: 1px solid var(--vp-c-divider);
}

.status {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--lx-green);
}

.sink {
  color: var(--vp-c-text-1);
  font-family: var(--vp-font-family-base);
  font-size: 13.5px;
  font-weight: 500;
}

.note {
  color: var(--vp-c-text-3);
  font-size: 11.5px;
}

/* Code snippets */
.kw {
  color: var(--vp-c-brand-1);
}

.dec {
  color: var(--lx-code-num);
}

.fn {
  font-weight: 600;
}

/* Extras list */
.extras {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin: 56px 0 0;
  padding: 0;
  list-style: none;
  border-top: 1px solid var(--vp-c-divider);
}

.extras li {
  margin: 0;
  border-bottom: 1px solid var(--vp-c-divider);
}

.extras li:not(:nth-child(3n)) {
  border-right: 1px solid var(--vp-c-divider);
}

.extras a {
  display: flex;
  gap: 14px;
  height: 100%;
  padding: 24px;
  color: var(--vp-c-brand-1);
  text-decoration: none;
  transition: background-color 0.2s;
}

.extras a:hover {
  background: var(--vp-c-bg-alt);
}

.extras strong {
  display: block;
  margin-bottom: 4px;
  font-size: 15px;
  font-weight: 600;
  color: var(--vp-c-text-1);
}

.extras a > span > span {
  display: block;
  font-size: 13.5px;
  line-height: 1.55;
  color: var(--vp-c-text-2);
}

@media (max-width: 960px) {
  .span-4,
  .span-5,
  .span-7,
  .span-8 {
    grid-column: span 12;
  }

  .extras {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .extras li:not(:nth-child(3n)) {
    border-right: 0;
  }

  .extras li:nth-child(odd) {
    border-right: 1px solid var(--vp-c-divider);
  }
}

@media (max-width: 640px) {
  .features {
    padding: 64px 16px 16px;
  }

  .tile {
    padding: 20px;
  }

  .extras {
    grid-template-columns: minmax(0, 1fr);
  }

  .extras li:nth-child(odd) {
    border-right: 0;
  }
}

@media (prefers-reduced-motion: reduce) {
}
</style>
