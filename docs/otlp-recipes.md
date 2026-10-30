# OTLP recipes

`OtlpLogTransport` posts logs as **OTLP/HTTP with a JSON body** (`Content-Type: application/json`). Only the endpoint URL and the auth headers differ between backends. The URLs and header names below come from each vendor's documentation (linked per section). Their docs often use placeholders for host names, so copy the real value from your own account.

```ts
import { createLogger } from 'logixia';
import { OtlpLogTransport } from 'logixia/transports';
```

> **JSON support.** None of the vendor pages below state whether their logs endpoint accepts OTLP/HTTP JSON (they show protobuf SDKs and Collector examples). If a backend rejects the JSON body, send to a local OpenTelemetry Collector (first recipe) and let the Collector forward in protobuf.

## Local OpenTelemetry Collector

`otel-collector.yaml`, which prints every log record to stdout:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
```

Run it with `docker run --rm -p 4318:4318 -v "$PWD/otel-collector.yaml:/etc/otelcol-contrib/config.yaml" otel/opentelemetry-collector-contrib`, then:

```ts
const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new OtlpLogTransport({
        url: 'http://localhost:4318/v1/logs',
        serviceName: 'api',
        environment: 'development',
      }),
    ],
  },
});
```

Docs: [OTLP receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver), [debug exporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/debugexporter).

## Grafana Loki

Loki 3.x accepts OTLP natively at `POST /otlp/v1/logs`. The transport needs the full URL: Loki's docs say a Collector `otlphttp` exporter takes only `http://<LOKI_ADDR>/otlp`, but this transport does not append `/v1/logs` for you.

```ts
new OtlpLogTransport({
  url: 'http://loki:3100/otlp/v1/logs',
  serviceName: 'api',
});
```

Self-hosted Loki with multi-tenancy also needs the usual `X-Scope-OrgID` tenant header.

**Grafana Cloud** uses the OTLP gateway with Basic auth. Copy the endpoint and credentials from the **OpenTelemetry** tile of your stack: the endpoint looks like `https://otlp-gateway-<REGION>.grafana.net/otlp`, and the logs URL is that plus `/v1/logs`. Grafana's docs do not spell out which half of the Basic credential is which, so use what the tile generates (in practice the instance ID and the access token).

```ts
const basic = Buffer.from(
  `${process.env.GRAFANA_INSTANCE_ID}:${process.env.GRAFANA_TOKEN}`
).toString('base64');

new OtlpLogTransport({
  url: 'https://otlp-gateway-<REGION>.grafana.net/otlp/v1/logs',
  headers: { Authorization: `Basic ${basic}` },
  serviceName: 'api',
});
```

Docs: [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/), [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/), [Grafana Cloud OTLP](https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/).

## Axiom

Endpoint `https://AXIOM_DOMAIN/v1/logs`, where `AXIOM_DOMAIN` is the base domain of your edge deployment (see Axiom's edge deployments page). Headers: `Authorization: Bearer <API token with ingest permission>` and `X-Axiom-Dataset: <dataset>`. Use a dedicated dataset created with the **Events** option.

```ts
new OtlpLogTransport({
  url: `https://${process.env.AXIOM_DOMAIN}/v1/logs`,
  headers: {
    Authorization: `Bearer ${process.env.AXIOM_TOKEN}`,
    'X-Axiom-Dataset': process.env.AXIOM_DATASET!,
  },
  serviceName: 'api',
});
```

Docs: [Axiom OpenTelemetry](https://axiom.co/docs/send-data/opentelemetry).

## Better Stack

Endpoint `https://<INGESTING_HOST>/v1/logs` with `Authorization: Bearer <source token>`. The ingesting host and source token are shown on your source's page in Better Stack.

```ts
new OtlpLogTransport({
  url: `https://${process.env.BETTERSTACK_INGESTING_HOST}/v1/logs`,
  headers: { Authorization: `Bearer ${process.env.BETTERSTACK_SOURCE_TOKEN}` },
  serviceName: 'api',
});
```

Docs: [Better Stack OpenTelemetry](https://betterstack.com/docs/logs/open-telemetry/).
