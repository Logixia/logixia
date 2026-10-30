import * as main from '../index';
import * as searchEntry from '../search';
import { SearchManager } from '../search';

describe('logixia/search entry', () => {
  it('exports the search API', () => {
    expect(Object.keys(searchEntry).length).toBeGreaterThan(0);
    expect(typeof SearchManager).toBe('function');
  });

  it('exposes the same SearchManager from the main entry', () => {
    expect(main.SearchManager).toBe(SearchManager);
  });
});
