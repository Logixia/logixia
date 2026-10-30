const STOPWORDS = new Set([
  'is',
  'was',
  'are',
  'the',
  'a',
  'an',
  'of',
  'for',
  'do',
  'did',
  'does',
  'in',
  'on',
  'at',
  'with',
  'who',
  'what',
  'from',
  'that',
  'and',
  'or',
  'to',
  'has',
  'have',
  'had',
  'by',
  'as',
  'my',
  'me',
  'all',
  'any',
  'it',
  'be',
  'not',
  'no',
  'when',
  'where',
  'which',
  'logs',
]);

// "user id u42", "user id is u42", "userId: u42", "user_id=u42"
const EXPLICIT = /\buser[\s_]?id(?:\s+is|\s*[:=])?\s*["']?([\w-]+)/i;
// "user u42" / "user 42": the token must contain a digit
const WITH_DIGIT = /\buser\s+["']?([\w-]*\d[\w-]*)/i;

export interface UserIdMatch {
  id: string;
  /** Exact span of the query that expressed the id, for removal from free text. */
  span: string;
}

/**
 * Extract a user id from natural-language text. An id must either contain a digit
 * or follow explicit "user id" / "userId:" syntax and not be a stopword, so phrases
 * like "what did user do yesterday" never produce a filter.
 */
export function extractUserId(query: string): UserIdMatch | undefined {
  const explicit = EXPLICIT.exec(query);
  if (explicit?.[1] && !STOPWORDS.has(explicit[1].toLowerCase())) {
    return { id: explicit[1], span: explicit[0] };
  }
  const digit = WITH_DIGIT.exec(query);
  if (digit?.[1]) return { id: digit[1], span: digit[0] };
  return undefined;
}
