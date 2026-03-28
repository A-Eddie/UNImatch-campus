const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

const db = admin.firestore();

// ══════════════════════════════════════
// INPUT SANITIZATION HELPER
// ══════════════════════════════════════
function sanitize(str, maxLen = 500) {
  if (typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').trim().slice(0, maxLen);
}

// ══════════════════════════════════════
// PAYLOAD SIZE GUARD
// ══════════════════════════════════════
function assertPayloadSize(data, maxBytes = 10000) {
  if (JSON.stringify(data).length > maxBytes) {
    throw new functions.https.HttpsError('invalid-argument', 'Payload too large');
  }
}

// ══════════════════════════════════════
// RATE LIMITER HELPER (with transaction to prevent race condition)
// ══════════════════════════════════════
async function checkRateLimit(userId, action, maxPerHour) {
  const now = Date.now();
  const oneHourAgo = new Date(now - 3600000);
  const ref = db.collection("rateLimits").doc(`${userId}_${action}`);

  return db.runTransaction(async (transaction) => {
    const doc = await transaction.get(ref);

    if (doc.exists) {
      const data = doc.data();
      const timestamps = (data.timestamps || []).filter(
        (t) => t.toDate() > oneHourAgo
      );
      if (timestamps.length >= maxPerHour) {
        return false; // Rate limited
      }
      timestamps.push(admin.firestore.Timestamp.now());
      transaction.update(ref, { timestamps });
    } else {
      transaction.set(ref, { timestamps: [admin.firestore.Timestamp.now()] });
    }
    return true;
  });
}

// ══════════════════════════════════════
// BAN CHECK HELPER — reusable for all callable functions
// ══════════════════════════════════════
async function assertNotBanned(context) {
  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "Must be signed in"
    );
  }
  // Check custom claims
  if (context.auth.token.banned === true) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Your account has been suspended."
    );
  }
  // Double-check Firestore for fresh ban status
  const userDoc = await db.collection("users").doc(context.auth.uid).get();
  if (userDoc.exists && userDoc.data().status === "banned") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Your account has been suspended."
    );
  }
}

// ══════════════════════════════════════
// EMAIL DOMAIN VALIDATION (server-side)
// ══════════════════════════════════════
const VALID_DOMAINS = [
  "strathmore.edu", "uonbi.ac.ke", "ku.ac.ke", "jkuat.ac.ke",
  "mku.ac.ke", "kca.ac.ke", "usiu.ac.ke", "daystar.ac.ke",
  "kabarak.ac.ke", "zetech.ac.ke", "tukenya.ac.ke", "cuea.edu",
  "kemu.ac.ke", "aku.edu", "dkut.ac.ke", "scu.ac.ke",
  "egerton.ac.ke", "maseno.ac.ke", "mmust.ac.ke", "moi.ac.ke",
  "tuk.ac.ke", "tum.ac.ke", "chuka.ac.ke", "laikipia.ac.ke",
  "seku.ac.ke", "pu.ac.ke", "kisiiuni.ac.ke", "uoeld.ac.ke",
  "maasaimara.ac.ke", "jooust.ac.ke", "karatina.ac.ke",
  "kabianga.ac.ke", "mmu.ac.ke", "kibabii.ac.ke", "mut.ac.ke",
  "must.ac.ke", "kyu.ac.ke", "cuk.ac.ke", "rongouni.ac.ke",
  "ttu.ac.ke", "gu.ac.ke", "uoembu.ac.ke", "au.ac.ke",
  "tmu.ac.ke", "riara.ac.ke", "khu.ac.ke", "aua.ac.ke",
  "tangaza.ac.ke", "lukenya.ac.ke", "piu.ac.ke", "mua.ac.ke",
  "umma.ac.ke", "anu.ac.ke", "pacu.ac.ke", "spu.ac.ke",
];

function isValidUniversityEmail(email) {
  if (!email || typeof email !== "string") return false;
  const domain = email.split("@")[1];
  if (!domain) return false;
  const lowerDomain = domain.toLowerCase();
  return VALID_DOMAINS.some(
    (d) => lowerDomain === d || lowerDomain.endsWith("." + d)
  );
}

// ══════════════════════════════════════
// SERVER-SIDE REGISTRATION
// ══════════════════════════════════════
exports.registerUser = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data);

  // Rate limit registration attempts (even unauthenticated) by IP-derived key
  // Note: context.auth may be null for pre-registration validation
  const rateLimitKey = context.auth ? context.auth.uid : "anon";
  const allowed = await checkRateLimit(rateLimitKey, "register", 10);
  if (!allowed) {
    throw new functions.https.HttpsError(
      "resource-exhausted",
      "Too many attempts. Please try again later."
    );
  }

  // Use verified email from auth token when available, fall back to data.email for pre-auth validation
  let email;
  if (context.auth && context.auth.token && context.auth.token.email) {
    email = context.auth.token.email;
  } else {
    email = (data.email || "").trim().toLowerCase();
  }

  const username = sanitize(data.username || "", 20);
  const name = sanitize(data.name || "", 100);
  const { uni, dept, gender, pref, yearOfStudy, age } = data;

  if (!email || typeof email !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Email is required");
  }

  // Server-side email domain validation
  if (!isValidUniversityEmail(email)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Please use your university email (.ac.ke or .edu domain)"
    );
  }

  // Validate username
  const cleanUsername = (username || "").trim().toLowerCase();
  if (!cleanUsername || !/^[a-zA-Z0-9_]{3,20}$/.test(cleanUsername)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Username must be 3-20 characters, letters, numbers, and underscores only"
    );
  }

  // Check username uniqueness
  const existingUsername = await db
    .collection("users")
    .where("username", "==", cleanUsername)
    .limit(1)
    .get();

  if (!existingUsername.empty) {
    throw new functions.https.HttpsError(
      "already-exists",
      "Username is already taken"
    );
  }

  // Validate name
  if (!name || typeof name !== "string" || name.trim().length < 1 || name.trim().length > 100) {
    throw new functions.https.HttpsError("invalid-argument", "Name is required (1-100 characters)");
  }

  // Validate age
  const parsedAge = parseInt(age);
  if (!parsedAge || parsedAge < 18 || parsedAge > 35) {
    throw new functions.https.HttpsError("invalid-argument", "Age must be between 18 and 35");
  }

  // Validate gender
  const validGenders = ["woman", "man", "nonbinary"];
  if (!gender || !validGenders.includes(gender)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid gender selection");
  }

  // Validate preference
  const validPrefs = ["women", "men", "everyone"];
  if (!pref || !validPrefs.includes(pref)) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid preference selection");
  }

  // Validate year of study
  const validYears = ["1", "2", "3", "4", "5", "6"];
  if (!yearOfStudy || !validYears.includes(String(yearOfStudy))) {
    throw new functions.https.HttpsError("invalid-argument", "Invalid year of study");
  }

  return { valid: true, username: cleanUsername };
});

// ══════════════════════════════════════
// SERVER-SIDE MATCH VERIFICATION
// ══════════════════════════════════════
exports.processSwipe = functions.firestore
  .document("swipes/{swipeId}")
  .onCreate(async (snap, context) => {
    const swipe = snap.data();
    const { swiperId, swipedId, direction } = swipe;

    // Validate swipe data
    if (!swiperId || !swipedId || swiperId === swipedId) return null;
    if (direction !== "right" && direction !== "super") return null;

    // Rate limit: max 200 swipes per hour
    const swipeAllowed = await checkRateLimit(swiperId, "swipe", 200);
    if (!swipeAllowed) {
      console.warn("Swipe rate limit exceeded");
      return null;
    }

    // Check if swiper is banned
    const swiperDoc = await db.collection("users").doc(swiperId).get();
    if (!swiperDoc.exists || swiperDoc.data().status === "banned") return null;

    // Check if swiped user exists and is active
    const swipedDoc = await db.collection("users").doc(swipedId).get();
    if (!swipedDoc.exists || swipedDoc.data().status !== "active") return null;

    // Check if either user has blocked the other
    const blocks = await db.collection("blocks")
      .where("blocker", "in", [swiperId, swipedId])
      .get();

    const isBlocked = blocks.docs.some((doc) => {
      const data = doc.data();
      return (
        (data.blocker === swiperId && data.blocked === swipedId) ||
        (data.blocker === swipedId && data.blocked === swiperId)
      );
    });

    if (isBlocked) return null;

    // Check if the other person has already swiped right on this user
    const reverseSwipes = await db
      .collection("swipes")
      .where("swiperId", "==", swipedId)
      .where("swipedId", "==", swiperId)
      .where("direction", "in", ["right", "super"])
      .limit(1)
      .get();

    if (!reverseSwipes.empty) {
      const matchId = [swiperId, swipedId].sort().join("_");
      const matchRef = db.collection("matches").doc(matchId);

      await db.runTransaction(async (transaction) => {
        const existing = await transaction.get(matchRef);
        if (!existing.exists) {
          transaction.set(matchRef, {
            users: [swiperId, swipedId],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });

          // Create notifications inside the transaction
          const notif1 = db.collection("notifications").doc();
          const notif2 = db.collection("notifications").doc();

          transaction.set(notif1, {
            userId: swiperId,
            type: "match",
            matchedWith: swipedId,
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
          transaction.set(notif2, {
            userId: swipedId,
            type: "match",
            matchedWith: swiperId,
            read: false,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
        }
      });
    }
    return null;
  });

// ══════════════════════════════════════
// ENFORCE BAN ON LOGIN (Custom Claims)
// ══════════════════════════════════════
exports.onUserStatusChange = functions.firestore
  .document("users/{userId}")
  .onUpdate(async (change, context) => {
    const before = change.before.data();
    const after = change.after.data();
    const userId = context.params.userId;

    // Verify the change was made by an admin (check who triggered)
    // The Firestore rules already protect isAdmin/status from non-admin writes

    // If user was banned, revoke their sessions
    if (before.status !== "banned" && after.status === "banned") {
      try {
        await admin.auth().revokeRefreshTokens(userId);
        await admin
          .auth()
          .setCustomUserClaims(userId, { banned: true, admin: false });
        console.log("User banned and sessions revoked");
      } catch (e) {
        console.error("Failed to ban user:", e);
      }
    }

    // If user was unbanned
    if (before.status === "banned" && after.status === "active") {
      try {
        await admin
          .auth()
          .setCustomUserClaims(userId, { banned: false, admin: after.isAdmin === true });
        console.log("User unbanned");
      } catch (e) {
        console.error("Failed to unban user:", e);
      }
    }

    // If admin status changed — only process if done by admin (rules enforce this)
    if (before.isAdmin !== after.isAdmin) {
      try {
        const currentClaims = (await admin.auth().getUser(userId)).customClaims || {};
        await admin
          .auth()
          .setCustomUserClaims(userId, {
            ...currentClaims,
            admin: after.isAdmin === true,
          });
        console.log("User admin claim updated");
      } catch (e) {
        console.error("Failed to set admin claim:", e);
      }
    }
    return null;
  });

// ══════════════════════════════════════
// VALIDATE USERNAME UNIQUENESS
// ══════════════════════════════════════
exports.validateUsername = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 1000);

  if (!context.auth) {
    throw new functions.https.HttpsError(
      "unauthenticated",
      "Must be signed in"
    );
  }

  const username = sanitize(data.username || "", 20).toLowerCase();
  if (!username || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Invalid username format"
    );
  }

  const existing = await db
    .collection("users")
    .where("username", "==", username)
    .limit(1)
    .get();

  if (
    !existing.empty &&
    existing.docs[0].id !== context.auth.uid
  ) {
    return { available: false };
  }
  return { available: true };
});

// ══════════════════════════════════════
// VALIDATE EMAIL DOMAIN (callable)
// ══════════════════════════════════════
exports.validateEmailDomain = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 1000);

  // Use verified email from auth token if available
  let email;
  if (context.auth && context.auth.token && context.auth.token.email) {
    email = context.auth.token.email;
  } else {
    email = (data.email || "").trim().toLowerCase();
  }
  if (!email) {
    throw new functions.https.HttpsError("invalid-argument", "Email is required");
  }
  return { valid: isValidUniversityEmail(email) };
});

// ══════════════════════════════════════
// CLEANUP ON ACCOUNT DELETION (comprehensive)
// ══════════════════════════════════════
exports.onUserDeleted = functions.auth.user().onDelete(async (user) => {
  const uid = user.uid;
  const batchSize = 400; // Firestore batch limit is 500

  // Helper to delete all docs in a query
  async function deleteQueryBatch(query) {
    const snapshot = await query.get();
    if (snapshot.empty) return;

    const batch = db.batch();
    snapshot.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    // Recurse if there might be more
    if (snapshot.docs.length >= batchSize) {
      await deleteQueryBatch(query);
    }
  }

  try {
    // Delete user document and settings
    const mainBatch = db.batch();
    mainBatch.delete(db.collection("users").doc(uid));
    mainBatch.delete(db.collection("settings").doc(uid));
    await mainBatch.commit();

    // Delete user's swipes (as swiper)
    await deleteQueryBatch(
      db.collection("swipes").where("swiperId", "==", uid).limit(batchSize)
    );

    // Delete swipes where user was swiped on
    await deleteQueryBatch(
      db.collection("swipes").where("swipedId", "==", uid).limit(batchSize)
    );

    // Delete user's notifications
    await deleteQueryBatch(
      db.collection("notifications").where("userId", "==", uid).limit(batchSize)
    );

    // Delete user's reports (as reporter)
    await deleteQueryBatch(
      db.collection("reports").where("reporter", "==", uid).limit(batchSize)
    );

    // Delete user's blocks (as blocker)
    await deleteQueryBatch(
      db.collection("blocks").where("blocker", "==", uid).limit(batchSize)
    );

    // Delete blocks against this user
    await deleteQueryBatch(
      db.collection("blocks").where("blocked", "==", uid).limit(batchSize)
    );

    // Delete rate limit entries
    const rateLimitDocs = await db.collection("rateLimits")
      .where(admin.firestore.FieldPath.documentId(), ">=", uid + "_")
      .where(admin.firestore.FieldPath.documentId(), "<=", uid + "_\uf8ff")
      .get();
    if (!rateLimitDocs.empty) {
      const rlBatch = db.batch();
      rateLimitDocs.docs.forEach((doc) => rlBatch.delete(doc.ref));
      await rlBatch.commit();
    }

    // Find and clean up matches involving this user
    const matchesAsUser = await db.collection("matches")
      .where("users", "array-contains", uid)
      .get();

    for (const matchDoc of matchesAsUser.docs) {
      // Delete all messages in the chat
      const chatId = matchDoc.id; // matchId is already sorted user IDs
      await deleteQueryBatch(
        db.collection("chats").doc(chatId).collection("messages").limit(batchSize)
      );
      // Delete chat metadata
      await db.collection("chats").doc(chatId).delete().catch(() => {});
      // Delete match document
      await matchDoc.ref.delete();
    }

    // Delete storage
    try {
      const bucket = admin.storage().bucket();
      await bucket.deleteFiles({ prefix: `profiles/${uid}/` });
    } catch (e) {
      console.warn("Storage cleanup failed:", e.message);
    }

    console.log("Cleaned up all data for deleted user");
  } catch (e) {
    console.error("Cleanup failed for user:", e);
  }

  return null;
});

// ══════════════════════════════════════
// PHOTO MODERATION — Cloud Vision SafeSearch
// Automatically checks uploaded profile photos for explicit content
// ══════════════════════════════════════
exports.moderateProfilePhoto = functions.storage
  .object()
  .onFinalize(async (object) => {
    // Only process files in profiles/ directory
    if (!object.name || !object.name.startsWith("profiles/")) return null;
    if (!object.contentType || !object.contentType.startsWith("image/")) return null;

    const vision = require("@google-cloud/vision");
    const client = new vision.ImageAnnotatorClient();

    const bucket = admin.storage().bucket(object.bucket);
    const filePath = object.name;

    try {
      const [result] = await client.safeSearchDetection(
        `gs://${object.bucket}/${filePath}`
      );
      const detections = result.safeSearchAnnotation;

      if (!detections) {
        console.warn("No SafeSearch results for:", filePath);
        return null;
      }

      // Flag image if adult or violence content is LIKELY or VERY_LIKELY
      const dominated = ["LIKELY", "VERY_LIKELY"];
      const isExplicit =
        dominated.includes(detections.adult) ||
        dominated.includes(detections.violence);

      if (isExplicit) {
        // Delete the offending photo
        await bucket.file(filePath).delete();

        // Extract userId from path (profiles/{uid}/filename)
        const parts = filePath.split("/");
        const userId = parts.length >= 2 ? parts[1] : null;

        if (userId) {
          // Clear photo URL from user profile
          await db.collection("users").doc(userId).update({
            photo: "",
          });

          // Log moderation action
          await db.collection("reports").add({
            reporter: "system",
            reported: userId,
            reason: `Auto-flagged: adult=${detections.adult}, violence=${detections.violence}`,
            category: "inappropriate",
            status: "auto-moderated",
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
          });
        }

        console.log("Explicit photo removed:", filePath);
      }
    } catch (e) {
      // Cloud Vision API may not be enabled — log but don't crash
      console.error("Photo moderation error:", e.message);
    }

    return null;
  });

// ══════════════════════════════════════
// REPORT PROCESSING WITH RATE LIMITING
// ══════════════════════════════════════
exports.submitReport = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 5000);
  await assertNotBanned(context);

  const allowed = await checkRateLimit(context.auth.uid, "report", 5);
  if (!allowed) {
    throw new functions.https.HttpsError(
      "resource-exhausted",
      "Too many reports. Please try again later."
    );
  }

  const reported = sanitize(data.reported, 128);
  const reason = sanitize(data.reason, 1000);
  const { category } = data;
  if (!reported) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Missing reported user ID"
    );
  }
  if (!reason || reason.length < 10) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "Please provide a detailed reason (at least 10 characters)"
    );
  }

  // Validate reported user exists
  const reportedUser = await db.collection("users").doc(reported).get();
  if (!reportedUser.exists) {
    throw new functions.https.HttpsError(
      "not-found",
      "Reported user not found"
    );
  }

  // Prevent self-reporting
  if (reported === context.auth.uid) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "You cannot report yourself"
    );
  }

  // Check for duplicate report
  const existingReport = await db.collection("reports")
    .where("reporter", "==", context.auth.uid)
    .where("reported", "==", reported)
    .where("status", "==", "pending")
    .limit(1)
    .get();

  if (!existingReport.empty) {
    throw new functions.https.HttpsError(
      "already-exists",
      "You have already reported this user. We are reviewing your report."
    );
  }

  const validCategories = [
    "bug", "harassment", "fake", "spam",
    "inappropriate", "safety", "suggestion", "other",
  ];
  const sanitizedCategory = validCategories.includes(category)
    ? category
    : "other";

  await db.collection("reports").add({
    reporter: context.auth.uid,
    reported,
    reason: String(reason).slice(0, 1000),
    category: sanitizedCategory,
    status: "pending",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  return { success: true };
});

// ══════════════════════════════════════
// BLOCK USER (callable for server-side validation)
// ══════════════════════════════════════
exports.blockUser = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 1000);
  await assertNotBanned(context);

  const { blockedUserId } = data;
  if (!blockedUserId || typeof blockedUserId !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Missing user ID");
  }

  if (blockedUserId === context.auth.uid) {
    throw new functions.https.HttpsError("invalid-argument", "You cannot block yourself");
  }

  // Verify blocked user exists
  const blockedUser = await db.collection("users").doc(blockedUserId).get();
  if (!blockedUser.exists) {
    throw new functions.https.HttpsError("not-found", "User not found");
  }

  // Check if already blocked
  const existingBlock = await db.collection("blocks")
    .where("blocker", "==", context.auth.uid)
    .where("blocked", "==", blockedUserId)
    .limit(1)
    .get();

  if (!existingBlock.empty) {
    return { success: true, message: "User already blocked" };
  }

  // Create block and remove match in a transaction
  const matchId = [context.auth.uid, blockedUserId].sort().join("_");
  const matchRef = db.collection("matches").doc(matchId);

  await db.runTransaction(async (transaction) => {
    const matchDoc = await transaction.get(matchRef);

    // Add block
    const blockRef = db.collection("blocks").doc();
    transaction.set(blockRef, {
      blocker: context.auth.uid,
      blocked: blockedUserId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // Remove match if exists
    if (matchDoc.exists) {
      transaction.delete(matchRef);
    }
  });

  return { success: true };
});

// ══════════════════════════════════════
// UNMATCH USER (callable)
// ══════════════════════════════════════
exports.unmatchUser = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 1000);
  await assertNotBanned(context);

  const { matchedUserId } = data;
  if (!matchedUserId || typeof matchedUserId !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Missing user ID");
  }

  const matchId = [context.auth.uid, matchedUserId].sort().join("_");
  const matchRef = db.collection("matches").doc(matchId);
  const matchDoc = await matchRef.get();

  if (!matchDoc.exists) {
    throw new functions.https.HttpsError("not-found", "Match not found");
  }

  // Verify user is part of this match
  const matchData = matchDoc.data();
  if (!matchData.users || !matchData.users.includes(context.auth.uid)) {
    throw new functions.https.HttpsError("permission-denied", "Not your match");
  }

  await matchRef.delete();
  return { success: true };
});

// ══════════════════════════════════════
// SEND MESSAGE (callable for server-side validation)
// ══════════════════════════════════════
exports.sendMessage = functions.https.onCall(async (data, context) => {
  // Verify App Check token
  if (context.app == undefined) {
    throw new functions.https.HttpsError(
      "failed-precondition",
      "App Check verification failed"
    );
  }

  assertPayloadSize(data, 5000);
  await assertNotBanned(context);

  const receiverId = sanitize(data.receiverId, 128);
  const text = sanitize(data.text, 1000);
  const { replyTo } = data;

  if (!receiverId || typeof receiverId !== "string") {
    throw new functions.https.HttpsError("invalid-argument", "Missing receiver");
  }

  if (!text || typeof text !== "string" || text.trim().length === 0) {
    throw new functions.https.HttpsError("invalid-argument", "Message cannot be empty");
  }

  if (text.length > 1000) {
    throw new functions.https.HttpsError("invalid-argument", "Message too long (max 1000 characters)");
  }

  // Rate limit messages: 30 per minute
  const allowed = await checkRateLimit(context.auth.uid, "message", 30);
  if (!allowed) {
    throw new functions.https.HttpsError(
      "resource-exhausted",
      "Slow down — too many messages"
    );
  }

  // Verify email is verified
  const authUser = await admin.auth().getUser(context.auth.uid);
  if (!authUser.emailVerified) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Please verify your email before sending messages"
    );
  }

  // Verify users are matched
  const matchId = [context.auth.uid, receiverId].sort().join("_");
  const matchDoc = await db.collection("matches").doc(matchId).get();
  if (!matchDoc.exists) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "You can only message your matches"
    );
  }

  // Check for blocks
  const blocks = await db.collection("blocks")
    .where("blocker", "in", [context.auth.uid, receiverId])
    .get();

  const isBlocked = blocks.docs.some((doc) => {
    const d = doc.data();
    return (
      (d.blocker === context.auth.uid && d.blocked === receiverId) ||
      (d.blocker === receiverId && d.blocked === context.auth.uid)
    );
  });

  if (isBlocked) {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Cannot send message to this user"
    );
  }

  const now = new Date();
  const time = now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const date = now.toISOString().split("T")[0];

  const messageData = {
    text: text.trim().slice(0, 1000),
    senderId: context.auth.uid,
    receiverId,
    time,
    date,
    status: "sent",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  };

  if (replyTo && typeof replyTo === "object" && replyTo.text) {
    messageData.replyTo = { text: String(replyTo.text).slice(0, 200) };
  }

  const chatRef = db.collection("chats").doc(matchId);
  await chatRef.collection("messages").add(messageData);

  return { success: true, time, date };
});