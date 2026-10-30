import { internalWarn } from '../utils/internal-log';

export const DEFAULT_BUFFER_CAP = 10_000;
const DROP_WARN_INTERVAL_MS = 5000;

/**
 * Keeps an in-memory retry buffer bounded. Past `max` the oldest items are
 * dropped, counted, and reported through internalWarn at most every few seconds.
 *
 * `requested` must be an integer of at least 1, otherwise the default is used.
 * A cap below `batchSize` is raised to `batchSize` so one batch always fits.
 */
export class BufferCap {
  public readonly max: number;
  private dropped = 0;
  private lastWarning = 0;

  constructor(
    private readonly name: string,
    requested: number | undefined,
    batchSize: number,
    fallback = DEFAULT_BUFFER_CAP
  ) {
    let max = fallback;
    if (requested !== undefined) {
      if (Number.isInteger(requested) && requested >= 1) {
        max = requested;
      } else {
        internalWarn(
          `${name}: maxBufferSize ${String(requested)} is not a positive integer; using ${fallback}`
        );
      }
    }
    this.max = Math.max(max, batchSize);
  }

  /** Drops the oldest items beyond the cap, in place. */
  enforce(items: unknown[]): void {
    const excess = items.length - this.max;
    if (excess <= 0) return;
    items.splice(0, excess);
    this.note(excess);
  }

  note(count: number): void {
    this.dropped += count;
    this.report(DROP_WARN_INTERVAL_MS);
  }

  report(minGapMs: number): void {
    const now = Date.now();
    if (this.dropped === 0 || now - this.lastWarning < minGapMs) return;
    internalWarn(
      `${this.name}: buffer full (${this.max}), dropped ${this.dropped} oldest entr${this.dropped === 1 ? 'y' : 'ies'}`
    );
    this.dropped = 0;
    this.lastWarning = now;
  }
}
