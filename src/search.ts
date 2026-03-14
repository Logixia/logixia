/**
 * logixia/search — log search and aggregation
 *
 * @example
 * import { SearchManager } from 'logixia/search';
 *
 * const searcher = new SearchManager({ ... });
 * const results = await searcher.search({ query: 'payment failed', levels: ['error'] });
 */

export * from './search';
