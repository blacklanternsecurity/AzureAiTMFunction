/**
 * Shared store for device code sessions
 * In production, use Redis or a database instead of in-memory storage
 */

const pendingCodes = new Map();

function setSession(sessionId, data) {
  const existing = pendingCodes.get(sessionId) || {};
  pendingCodes.set(sessionId, {
    ...existing,
    ...data,
    updated: Date.now(),
    created: existing.created || Date.now(),
  });
  
  // Clean up old sessions (older than 15 minutes)
  const now = Date.now();
  for (const [key, value] of pendingCodes) {
    if (now - value.created > 15 * 60 * 1000) {
      pendingCodes.delete(key);
    }
  }
}

function getSession(sessionId) {
  return pendingCodes.get(sessionId);
}

function deleteSession(sessionId) {
  pendingCodes.delete(sessionId);
}

module.exports = { setSession, getSession, deleteSession };

