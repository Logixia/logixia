/**
 * logixia/search — log search and aggregation
 *
 * @example
 * import { SearchManager } from 'logixia/search';
 *
 * const searcher = new SearchManager();
 * await searcher.indexLogs(logEntries);
 * const results = await searcher.search('payment failed', { levels: ['error'] }, { limit: 50 });
 */

export * from './search/index';
