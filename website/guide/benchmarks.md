---
title: Benchmarks
description: How logixia compares with pino and winston on throughput, with the harness explained line by line, the full results including where pino wins, and how to reproduce them.
order: 25
---

# Benchmarks

This page describes the benchmark harness in the repository, shows how logixia compares with pino and winston on Node 26, and explains the results, including the cases where logixia is slower. **The maintainer of logixia wrote the harness.** That is a conflict of interest, so the methodology is documented in full and you can run it yourself.

## Results

Higher throughput is better. The table shows logixia in JSON mode compared with pino's throughput in the same scenario (Node 26):

| Scenario             | logixia (JSON) vs pino |
| -------------------- | ---------------------- |
| Simple string        | -61%                   |
| Structured, 5 fields | +19%                   |
| Error object         | +53%                   |
| Child logger         | +33%                   |
| Deep nested object   | -22%                   |
| 12-field object      | +111%                  |

winston was slower than both pino and logixia in every scenario.

Read these as ratios from one harness, not as promises about your service. Absolute operations per second depend on the machine, Node version, payload shape and load, and the ratios move between runs. Two cautions on specific rows:

- **Child logger.** pino and winston create the child inside the timed function on every call, while the logixia child is created once outside it (see the harness below). That favours logixia in that row, so the +33% overstates what you would see if you create a child per request in both libraries.
- **Error object.** The three libraries are not given identical work: pino receives `{ err }`, logixia receives the `Error`, and winston receives only `err.message`. The row compares behavior on the harness's inputs, not like-for-like serialization of stack traces.

## What does the harness do?

The harness is [`benchmarks/run.mjs`](https://github.com/Logixia/logixia/blob/main/benchmarks/run.mjs). It uses [tinybench](https://github.com/tinylibs/tinybench) and runs six scenarios against pino, winston, logixia in its default text mode, logixia in JSON mode, and bunyan when it is installed (bunyan is optional and its rows are skipped if it is not).

How it keeps the comparison as even as it can:

- **Same sink, no real I/O.** Every library writes to something that drops the line, so the benchmark measures serialization and logger overhead, not disk or terminal speed. pino and bunyan write to an object with a bare `write()` that returns `true`. winston uses a synchronous transport that reads the formatted message and calls back. logixia's console output is swallowed by replacing `process.stdout.write` and `process.stderr.write` while timing.
- **Same call style.** Every call is made without awaiting. logixia methods return a promise; awaiting it would add a microtask hop that pino never pays, so the harness calls them the way most application code does.
- **JSON mode is the apples-to-apples row.** logixia is measured both in its default text mode and in JSON mode (`format: { json: true }`); the head-to-head summary compares JSON mode with pino's JSON.
- **Time per task.** Each task runs for 3 seconds by default (`BENCH_TIME_MS` overrides it). The runner reports throughput and p99 latency.

The scenarios:

| Scenario                   | What is logged                                                          |
| -------------------------- | ----------------------------------------------------------------------- |
| Simple string              | `'User logged in'`                                                      |
| Structured log (5 fields)  | message plus a 5-field object                                           |
| Error object               | an `Error` plus a message (see the caution above)                       |
| Child / per-request logger | pino and winston: `child()` inside the call; logixia: a pre-built child |
| Deep nested object         | a 3-level object with headers, query and user data                      |
| High-cardinality metadata  | a 12-field object                                                       |

What the harness does **not** measure: real I/O (files, network, a log collector), redaction, sampling, plugins or any logixia transport other than the intercepted console output, multi-process behavior, memory use, or startup time. Turning on `redact` adds work to logixia's per-line cost, and none of that is in these numbers.

## Why does pino win on simple strings?

Pino's design goal is to do as little as possible per call, and a plain string message is where that shows most. logixia does extra work on every line that pino skips by default:

1. It reads **two `AsyncLocalStorage` stores**, the request context and the trace-ID scope, to merge request fields into the entry.
2. It **writes a trace ID** onto the entry (`traceId: false` removes this).
3. It **formats an ISO timestamp string**, where pino writes an epoch number.

Each is small, but on a call that does almost nothing else, they dominate. That is the price of the features they support: a trace ID on every line without passing a logger around, and timestamps people can read.

As payloads get larger, fixed per-line costs matter less and serialization dominates, which is why the structured, error and 12-field rows go the other way. The deep nested object row is a loss for logixia (-22%), and I have not profiled it, so I will not guess at the cause.

## How do I reproduce the benchmarks?

From a checkout of the repository:

```sh
npm ci
npm run build && node benchmarks/run.mjs
```

`npm run benchmark` runs the same two steps. The output lists operations per second, p99 latency and the difference from pino for each scenario, then a head-to-head summary of logixia (JSON) against pino. Set `BENCH_TIME_MS` to shorten the run on a constrained machine. The harness keeps one latency sample per call, so memory grows with run time.

When you run it, close other work, run it more than once and look at the spread. Better still, adapt the scenarios in the file to the payloads your service really logs, and write to the sink you really use.

## What should I take from this?

- If your hot path is millions of plain string logs per second, use pino. It is faster, and the harness shows it.
- If your logs are structured objects, the gap narrows or reverses in this harness, but your destination, serialization of your own data and I/O will usually matter more than logger overhead.
- Treat any logger benchmark, including this one, as a starting point. See also [the best Node.js logging libraries](/articles/best-nodejs-logging-libraries) and [pino vs winston vs logixia](/articles/pino-vs-winston-vs-logixia), which publishes an earlier run on Node 22 with a different machine.
