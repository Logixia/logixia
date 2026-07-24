/**
 * Tests for the OpenTelemetry bridge.
 *
 * @opentelemetry/api is an optional dependency and is not installed in this
 * project, so these tests pin the graceful-degradation contract: every helper
 * must return undefined / {} (never throw) when the API is absent, and the
 * bridge state (init/disable) must behave correctly. The hot-path helper
 * _getOtelPayloadIfEnabled must never throw — it runs on every log call.
 */

import {
  _getOtelPayloadIfEnabled,
  disableOtelBridge,
  getActiveOtelContext,
  getOtelMetaFields,
  initOtelBridge,
} from '../otel';

afterEach(() => {
  disableOtelBridge();
});

describe('OTel bridge — graceful degradation (API absent)', () => {
  it('getActiveOtelContext returns undefined without @opentelemetry/api', () => {
    expect(getActiveOtelContext()).toBeUndefined();
  });

  it('getActiveOtelContext never throws', () => {
    expect(() => getActiveOtelContext({ sampledOnly: true })).not.toThrow();
  });

  it('getOtelMetaFields returns an empty object when no span is active', () => {
    expect(getOtelMetaFields()).toEqual({});
  });
});

describe('OTel bridge — init/disable state', () => {
  it('_getOtelPayloadIfEnabled returns {} when the bridge is not initialised', () => {
    expect(_getOtelPayloadIfEnabled()).toEqual({});
  });

  it('_getOtelPayloadIfEnabled returns {} after init when no span is active (API absent)', () => {
    initOtelBridge();
    expect(_getOtelPayloadIfEnabled()).toEqual({});
  });

  it('_getOtelPayloadIfEnabled never throws even after init', () => {
    initOtelBridge({ traceIdField: 'trace_id', sampledOnly: true });
    expect(() => _getOtelPayloadIfEnabled()).not.toThrow();
  });

  it('disableOtelBridge returns the bridge to the not-initialised state', () => {
    initOtelBridge();
    disableOtelBridge();
    expect(_getOtelPayloadIfEnabled()).toEqual({});
  });
});
