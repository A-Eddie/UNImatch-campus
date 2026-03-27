'use strict';

const functions = require('firebase-functions');
const admin = require('firebase-admin');
const sanitizeHtml = require('sanitize-html');
const validator = require('validator');

admin.initializeApp();

const db = admin.firestore();

// ── Sanitisation helper ────────────────────────────────────────────────────

/**
 * Strip all HTML tags from a string.
 * @param {string} str Raw user input.
 * @return {string} Sanitised string.
 */
function sanitize(str) {
  return sanitizeHtml(str, { allowedTags: [], allowedAttributes: {} });
}

// ── Rate-limiting helper (Firestore-backed) ────────────────────────────────

const MSG_RATE_LIMIT = 30; // max messages per minute per user

/**
 * Returns true when the user has exceeded the message rate limit.
 * Uses a Firestore counter document that resets every minute.
 * @param {string} uid Sender UID.
 * @return {Promise<boolean>}
 */
async function isRateLimited(uid) {
  const ref = db.collection('_rateLimits').doc(uid);
  const now = Date.now();
  const windowMs = 60 * 1000;

  return db.runTransaction(async (txn) => {
    const doc = await txn.get(ref);
    if (!doc.exists) {
      txn.set(ref, { count: 1, windowStart: now });
      return false;
    }
    const { count, windowStart } = doc.data();
    if (now - windowStart > windowMs) {
      txn.set(ref, { count: 1, windowStart: now });
      return false;
    }
    if (count >= MSG_RATE_LIMIT) return true;
    txn.update(ref, { count: count + 1 });
    return false;
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. onSwipeCreated — server-side match creation
// Triggered whenever a swipe document is written to /swipes/{swipeId}.
// Checks for a reciprocal "right" swipe; if found, creates a match document.
// This replaces ALL client-side match creation (the Math.random() approach).
// ══════════════════════════════════════════════════════════════════════════════

exports.onSwipeCreated = functions.firestore
  .document('swipes/{swipeId}')
  .onCreate(async (snap) => {
    const { swiperId, swipedId, direction } = snap.data();

    // Only process right/super swipes
    if (direction !== 'right' && direction !== 'super') return null;

    // Look for a reciprocal right swipe
    const reciprocalId = `${swipedId}_${swiperId}`;
    const reciprocal = await db.collection('swipes').doc(reciprocalId).get();

    if (!reciprocal.exists) return null;
    const reciprocalDir = reciprocal.data().direction;
    if (reciprocalDir !== 'right' && reciprocalDir !== 'super') return null;

    // Construct a deterministic match document ID (sorted UIDs)
    const sortedIds = [swiperId, swipedId].sort();
    const matchId = sortedIds.join('_');

    // Avoid duplicate match documents
    const existing = await db.collection('matches').doc(matchId).get();
    if (existing.exists) return null;

    await db.collection('matches').doc(matchId).set({
      users: sortedIds,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return null;
  });

// ══════════════════════════════════════════════════════════════════════════════
// 2. onUserWrite — sanitise user profile fields on every write
// ══════════════════════════════════════════════════════════════════════════════

exports.onUserWrite = functions.firestore
  .document('users/{userId}')
  .onWrite(async (change, context) => {
    // Ignore deletes
    if (!change.after.exists) return null;

    const data = change.after.data();
    const fieldsToSanitize = ['name', 'bio', 'dept', 'uni', 'username'];
    const updates = {};

    fieldsToSanitize.forEach((field) => {
      if (typeof data[field] === 'string') {
        const clean = sanitize(data[field]);
        if (clean !== data[field]) updates[field] = clean;
      }
    });

    if (Object.keys(updates).length === 0) return null;

    return change.after.ref.update(updates);
  });

// ══════════════════════════════════════════════════════════════════════════════
// 3. onMessageCreated — sanitise messages, verify participants, enforce rate
//    limit, and check blocks
// ══════════════════════════════════════════════════════════════════════════════

exports.onMessageCreated = functions.firestore
  .document('chats/{chatId}/messages/{msgId}')
  .onCreate(async (snap, context) => {
    const { chatId } = context.params;
    const data = snap.data();
    const senderId = data.senderId;

    // Verify sender is a chat participant (chatId = "uid1_uid2")
    const participants = chatId.split('_');
    if (!participants.includes(senderId)) {
      await snap.ref.delete();
      return null;
    }

    const recipientId = participants.find((id) => id !== senderId);

    // Check if either party has blocked the other
    const blockQuery1 = db.collection('blocks')
      .where('blockerId', '==', senderId)
      .where('blockedId', '==', recipientId)
      .limit(1)
      .get();

    const blockQuery2 = db.collection('blocks')
      .where('blockerId', '==', recipientId)
      .where('blockedId', '==', senderId)
      .limit(1)
      .get();

    const [blocked1, blocked2] = await Promise.all([blockQuery1, blockQuery2]);
    if (!blocked1.empty || !blocked2.empty) {
      await snap.ref.delete();
      return null;
    }

    // Rate limiting
    const limited = await isRateLimited(senderId);
    if (limited) {
      await snap.ref.delete();
      return null;
    }

    // Sanitise text
    const cleanText = sanitize(data.text || '');
    if (cleanText !== data.text) {
      await snap.ref.update({ text: cleanText });
    }

    return null;
  });

// ══════════════════════════════════════════════════════════════════════════════
// 4. deleteUserAccount — callable; deletes Firestore doc, Storage files, and
//    the Firebase Auth account for the calling user
// ══════════════════════════════════════════════════════════════════════════════

exports.deleteUserAccount = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be signed in.');
  }

  const uid = context.auth.uid;
  const bucket = admin.storage().bucket();

  // Delete Storage files under profiles/{uid}/
  try {
    await bucket.deleteFiles({ prefix: `profiles/${uid}/` });
  } catch (err) {
    // Non-fatal — files may not exist yet; log for diagnostics
    functions.logger.warn(`Storage cleanup failed for uid ${uid}:`, err.message);
  }

  // Delete Firestore user document
  await db.collection('users').doc(uid).delete();

  // Delete the Auth account last
  await admin.auth().deleteUser(uid);

  return { success: true };
});

// ══════════════════════════════════════════════════════════════════════════════
// 5. checkUsername — callable; verifies a username is available
// ══════════════════════════════════════════════════════════════════════════════

exports.checkUsername = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be signed in.');
  }

  const username = (data.username || '').trim();
  if (!username.match(/^[a-zA-Z0-9_]{3,20}$/)) {
    throw new functions.https.HttpsError(
      'invalid-argument',
      'Username must be 3–20 characters and contain only letters, numbers, or underscores.',
    );
  }

  const snap = await db.collection('users')
    .where('username', '==', username)
    .limit(1)
    .get();

  return { available: snap.empty };
});

// ══════════════════════════════════════════════════════════════════════════════
// 6. submitReport — callable; validates and persists a user report
// ══════════════════════════════════════════════════════════════════════════════

exports.submitReport = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be signed in.');
  }

  const reporterId = context.auth.uid;
  const { reportedId, reason, details } = data;

  if (!reportedId || typeof reportedId !== 'string') {
    throw new functions.https.HttpsError('invalid-argument', 'reportedId is required.');
  }
  if (!reason || typeof reason !== 'string' || reason.length > 1000) {
    throw new functions.https.HttpsError('invalid-argument', 'reason must be a string ≤ 1000 chars.');
  }

  const cleanDetails = details ? sanitize(String(details)).substring(0, 1000) : '';

  await db.collection('reports').add({
    reporterId,
    reportedId,
    reason: sanitize(reason),
    details: cleanDetails,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    status: 'open',
  });

  return { success: true };
});

// ══════════════════════════════════════════════════════════════════════════════
// 7. unmatchUser — callable; verifies the caller is a participant, then
//    deletes the match document
// ══════════════════════════════════════════════════════════════════════════════

exports.unmatchUser = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be signed in.');
  }

  const callerId = context.auth.uid;
  const { matchedUserId } = data;

  if (!matchedUserId || typeof matchedUserId !== 'string') {
    throw new functions.https.HttpsError('invalid-argument', 'matchedUserId is required.');
  }

  const sortedIds = [callerId, matchedUserId].sort();
  const matchId = sortedIds.join('_');
  const matchRef = db.collection('matches').doc(matchId);
  const matchDoc = await matchRef.get();

  if (!matchDoc.exists) {
    throw new functions.https.HttpsError('not-found', 'Match not found.');
  }

  const matchData = matchDoc.data();
  if (!matchData.users.includes(callerId)) {
    throw new functions.https.HttpsError('permission-denied', 'You are not a participant in this match.');
  }

  await matchRef.delete();
  return { success: true };
});

// ══════════════════════════════════════════════════════════════════════════════
// 8. blockUser — callable; creates the block record, removes any existing
//    match, and prevents future interactions
// ══════════════════════════════════════════════════════════════════════════════

exports.blockUser = functions.https.onCall(async (data, context) => {
  if (!context.auth) {
    throw new functions.https.HttpsError('unauthenticated', 'Must be signed in.');
  }

  const blockerId = context.auth.uid;
  const { blockedId } = data;

  if (!blockedId || typeof blockedId !== 'string') {
    throw new functions.https.HttpsError('invalid-argument', 'blockedId is required.');
  }
  if (blockerId === blockedId) {
    throw new functions.https.HttpsError('invalid-argument', 'Cannot block yourself.');
  }

  const batch = db.batch();

  // Create block record
  const blockRef = db.collection('blocks').doc(`${blockerId}_${blockedId}`);
  batch.set(blockRef, {
    blockerId,
    blockedId,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  // Remove existing match (if any)
  const sortedIds = [blockerId, blockedId].sort();
  const matchId = sortedIds.join('_');
  const matchRef = db.collection('matches').doc(matchId);
  const matchDoc = await matchRef.get();
  if (matchDoc.exists) {
    batch.delete(matchRef);
  }

  await batch.commit();
  return { success: true };
});
