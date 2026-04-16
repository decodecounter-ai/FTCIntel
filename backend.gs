// FTCIntel — Google Apps Script Backend (Secured)
// Paste the entire contents of this file into your GAS project editor.
// IMPORTANT: Change APP_KEY to a unique random string and redeploy.

const SS = SpreadsheetApp.getActiveSpreadsheet();

// Must match APP_KEY in config.js
const APP_KEY = "FTCI-2026-S3CR3T-Ro2D2";

// Gemini AI — store the key in GAS: Project Settings → Script Properties → GEMINI_API_KEY
const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=";

// ─── SUPER-ADMIN SECRETS ─────────────────────────────────────────────────────
// CHANGE all of these before deploying. Never expose in any frontend file.
const SUPER_ADMIN_PASS  = "SU-FTCI-MASTER-2026";  // master password
const SUPER_Q1_ANSWER   = "17962";                 // team number question
const SUPER_Q2_ANSWER   = "matei";                 // security question 2 (compared lowercase)
const SUPER_Q2_BLOCKED  = "daria";                 // triggers instant 5-min block + alert
const SUPER_OWNER_EMAIL = "decodero2counter@gmail.com";
const SUPER_SESSION_TTL = 14400;                   // session lifetime: 4 hours (seconds)
const SUPER_OTP_TTL     = 120;                     // OTP lifetime: 2 minutes (seconds)

// ─── SECURITY HELPERS ────────────────────────────────────────────────────────

function sha256(val) {
  const digest = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256,
    val.toString(),
    Utilities.Charset.UTF_8
  );
  return digest.map(function(b) {
    return ('0' + (b & 0xFF).toString(16)).slice(-2);
  }).join('');
}

function sanitize(val, maxLen) {
  maxLen = maxLen || 200;
  if (val === undefined || val === null) return '';
  return val.toString().replace(/[<>]/g, '').trim().substring(0, maxLen);
}

function checkRateLimit(identifier, maxReqs, windowSecs) {
  maxReqs  = maxReqs  || 30;
  windowSecs = windowSecs || 60;
  const cache = CacheService.getScriptCache();
  const key   = 'rl_' + sha256(identifier.toString());
  const count = parseInt(cache.get(key) || '0');
  if (count >= maxReqs) return false;
  cache.put(key, String(count + 1), windowSecs);
  return true;
}

function verifyRequest(p) {
  if (!p.appKey || p.appKey !== APP_KEY) return false;
  const ts = parseInt(p.ts || '0');
  if (!ts || Math.abs(Date.now() - ts) > 300000) return false;
  if (!p.sig) return false;
  const canonical = Object.keys(p)
    .filter(function(k) { return k !== 'sig'; })
    .sort()
    .map(function(k) { return k + '=' + p[k]; })
    .join('&');
  return sha256(canonical + APP_KEY) === p.sig;
}

function isTokenExpired(expiryVal) {
  if (!expiryVal) return true;
  const expiry = new Date(expiryVal);
  return isNaN(expiry.getTime()) || new Date() > expiry;
}

// Verify an active super-admin session token stored in CacheService
function verifySuperSession(sessionToken) {
  if (!sessionToken) return false;
  const cache = CacheService.getScriptCache();
  const stored = cache.get('super_session_token');
  return stored && stored === sessionToken.toString().trim();
}

// Audit helper — emails every login event to the owner
function auditSuperEvent(event, detail) {
  try {
    MailApp.sendEmail(
      SUPER_OWNER_EMAIL,
      "[FTCIntel Super Admin] " + event,
      "Event: " + event + "\n" + detail + "\n\nTime: " + new Date().toISOString()
    );
  } catch(e) {}
}

// ─── ROUTER ──────────────────────────────────────────────────────────────────

function doGet(e) {
  if (!e || !e.parameter) return response({ success: false, msg: "Bad request." });
  const p      = e.parameter;
  const action = p.action ? p.action.toLowerCase().trim() : "";

  // Rate limiting — super-admin actions keyed globally, signup is stricter
  const isSuperAction = action.startsWith('super');
  const rlId  = isSuperAction ? 'superadmin' : (p.myTeam || p.teamId || p.team || 'anon') + '_' + action;
  const rlMax = action === 'signup' ? 3 : action === 'aianalysis' ? 5 : isSuperAction ? 10 : 30;
  const rlWin = action === 'signup' ? 3600 : action === 'aianalysis' ? 60 : isSuperAction ? 60 : 60;
  if (!checkRateLimit(rlId, rlMax, rlWin)) {
    return response({ success: false, msg: "Too many requests. Try again later." });
  }

  // Verify app key + timestamp + payload signature
  if (!verifyRequest(p)) {
    return response({ success: false, msg: "Invalid request." });
  }

  try {
    if (action === "signup")             return response(signup(sanitize(p.team, 10), sanitize(p.email, 100)));
    if (action === "login")              return response({ success: auth(sanitize(p.teamId, 10), sanitize(p.token, 60)) });
    if (action === "uplink")             return response(processUplink(p));
    if (action === "intel")              return response(getUnifiedIntel(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.target, 10), sanitize(p.eventCode, 30)));
    if (action === "mydata")             return response(getMyFullTable(sanitize(p.myTeam, 10), sanitize(p.myToken, 60)));
    if (action === "getevents")          return response(getEvents(sanitize(p.myTeam, 10), sanitize(p.myToken, 60)));
    if (action === "log")                return response(addLog(p));
    if (action === "validatescouter")    return response(validateScouter(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.scouterId, 20)));
    if (action === "addevent")           return response(addEvent(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.code, 30), sanitize(p.name, 100), sanitize(p.date, 20)));
    if (action === "adminauth")          return response({ success: authAdmin(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60)) });
    if (action === "admingetscouters")   return response(adminGetScouters(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60)));
    if (action === "adminaddscouter")    return response(adminAddScouter(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.name, 100), sanitize(p.scouterId, 20)));
    if (action === "admineditscouter")   return response(adminEditScouter(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.rowIndex, 10), sanitize(p.name, 100), sanitize(p.scouterId, 20)));
    if (action === "admindeletescouter") return response(adminDeleteScouter(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.rowIndex, 10)));
    if (action === "admingetdata")       return response(adminGetData(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60)));
    if (action === "admineditcell")      return response(adminEditCell(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.row, 10), sanitize(p.col, 10), sanitize(p.value, 500)));
    if (action === "admindeleterow")     return response(adminDeleteRow(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.row, 10)));
    if (action === "admineditevent")     return response(adminEditEvent(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.rowIndex, 10), sanitize(p.code, 30), sanitize(p.name, 100), sanitize(p.date, 20)));
    if (action === "admindeleteevent")   return response(adminDeleteEvent(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.adminPass, 60), sanitize(p.rowIndex, 10)));
    if (action === "aianalysis")         return response(getAiAnalysis(sanitize(p.myTeam, 10), sanitize(p.myToken, 60), sanitize(p.target, 10), sanitize(p.eventCode, 30)));
    // ── Super-admin auth routes (use password / OTP — no session yet) ──────
    if (action === "supersendotp")       return response(superSendOtp(p));
    if (action === "superverifyotp")     return response(superVerifyOtp(p));
    if (action === "superlogout")        return response(superLogout(p));
    if (action === "supersessioncheck")  return response(superSessionCheck(p));
    // ── Super-admin data routes (require valid session token) ────────────
    if (action === "supergetteams")      return response(superGetTeams(p));
    if (action === "superresettoken")    return response(superResetToken(p));
    if (action === "superdeleteteam")    return response(superDeleteTeam(p));
    if (action === "supergetlogs")       return response(superGetLogs(p));
    if (action === "supergetscouters")   return response(superGetAllScouters(p));
    if (action === "superdeletescouter") return response(superDeleteScouter(p));
    if (action === "supergetevents")     return response(superGetAllEvents(p));
    if (action === "supersendmail")      return response(superSendMail(p));
    return response({ success: false, msg: "Invalid action." });
  } catch (err) {
    return response({ success: false, msg: "An error occurred. Please try again." });
  }
}

function response(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj)).setMimeType(ContentService.MimeType.JSON);
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

function auth(id, tk) {
  if (!id || !tk) return false;
  const sh = SS.getSheetByName("credentials");
  if (!sh) return false;
  const d   = sh.getDataRange().getValues();
  const cId = Number(id.toString().replace(/\D/g, ""));
  const cTk = sha256(tk.toString().trim());   // compare against stored hash
  return d.some(function(r) {
    return Number(r[0]) === cId &&
           r[1].toString().trim() === cTk &&
           !isTokenExpired(r[5]);             // col F = token expiry
  });
}

function authAdmin(teamId, token, adminPass) {
  if (!auth(teamId, token)) return false;
  if (!adminPass) return false;
  const sh = SS.getSheetByName("credentials");
  if (!sh) return false;
  const d    = sh.getDataRange().getValues();
  const cId  = Number(teamId.toString().replace(/\D/g, ""));
  const cPass = sha256(adminPass.toString().trim()); // compare against stored hash
  return d.some(function(r) {
    return Number(r[0]) === cId && r[4] && r[4].toString().trim() === cPass;
  });
}

// ─── SIGNUP ──────────────────────────────────────────────────────────────────

function signup(teamId, email) {
  const numTeamId = parseInt(teamId.toString().replace(/\D/g, ""), 10);
  if (!numTeamId || !email) return { success: false, msg: "Invalid parameters." };
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { success: false, msg: "Invalid email format." };

  let credSh = SS.getSheetByName("credentials");
  if (!credSh) {
    credSh = SS.insertSheet("credentials");
    credSh.appendRow(["TEAM_ID", "TOKEN_HASH", "EMAIL", "DATE", "ADMIN_PASS_HASH", "TOKEN_EXPIRY"]);
  }

  const d = credSh.getDataRange().getValues();

  // One account per team
  if (d.some(function(r, i) { return i > 0 && Number(r[0]) === numTeamId; })) {
    return { success: false, msg: "Team already registered." };
  }
  // One account per email
  if (d.some(function(r, i) { return i > 0 && r[2].toString().trim().toLowerCase() === email.toLowerCase(); })) {
    return { success: false, msg: "Email already registered." };
  }

  const token     = "TK-"  + Math.random().toString(36).substr(2, 9).toUpperCase();
  const adminPass = "ADM-" + Math.random().toString(36).substr(2, 9).toUpperCase();
  const expiry    = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000); // 1 year

  // Store hashes — never store plaintext credentials
  credSh.appendRow([numTeamId, sha256(token), email, new Date(), sha256(adminPass), expiry]);

  const sheetName = "DATA_" + numTeamId;
  if (!SS.getSheetByName(sheetName)) {
    const newSh = SS.insertSheet(sheetName);
    newSh.appendRow(["Target Team","Red Close","Red Far","Blue Close","Blue Far","Match #","Teleop","RP","Timestamp","Event","Scout"]);
  }

  try {
    MailApp.sendEmail(
      email,
      "FTCIntel - Team Credentials",
      "Access token: " + token + "\nAdmin password: " + adminPass
    );
  } catch(e) {}

  return { success: true };
}

// ─── SCOUTER VALIDATION ──────────────────────────────────────────────────────

function validateScouter(myTeam, myToken, scouterId) {
  if (!auth(myTeam, myToken)) return { success: false, msg: "Auth failed" };
  if (!scouterId) return { success: false, msg: "No Scout ID provided." };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: false, msg: "Scout ID not recognized." };
  const data = sh.getDataRange().getValues();
  const id   = scouterId.toString().trim();
  const found = data.some(function(r, i) { return i > 0 && r[1].toString().trim() === id; });
  return found ? { success: true } : { success: false, msg: "Scout ID not recognized." };
}

// ─── UPLINK ──────────────────────────────────────────────────────────────────

function processUplink(p) {
  const myTeam  = sanitize(p.myTeam,  10);
  const myToken = sanitize(p.myToken, 60);
  if (!auth(myTeam, myToken)) return { success: false, msg: "Auth failed" };

  const sh = SS.getSheetByName("DATA_" + myTeam);
  if (!sh) return { success: false, msg: "Service unavailable." };

  const colMap = { 'rc': 2, 'rf': 3, 'bc': 4, 'bf': 5 };
  const lock   = LockService.getScriptLock();
  lock.waitLock(15000);

  try {
    SpreadsheetApp.flush();
    const targetTeam = parseInt(sanitize(p.target, 10).replace(/\D/g, ""), 10);
    const matchVal   = sanitize(p.match     || "", 20);
    const autoType   = sanitize(p.auto_type || "", 5);
    const autoVal    = sanitize(p.auto_val  || "", 30);
    const teleVal    = sanitize(p.tele      || "", 20);
    const rpVal      = sanitize(p.rp        || "", 10);
    const eventCode  = sanitize(p.eventCode || "", 30);
    const scoutId    = sanitize(p.scoutId   || "", 20);

    const data = sh.getDataRange().getValues();
    let rowIndex = -1;
    for (let i = 1; i < data.length; i++) {
      if (!data[i][0]) continue;
      const rowTeam  = Number(data[i][0]);
      const rowMatch = data[i][5].toString().replace(/^'/, "").trim();
      const rowEvent = data[i][9].toString().trim();
      if (rowTeam === targetTeam && rowMatch === matchVal && rowEvent === eventCode) {
        rowIndex = i + 1; break;
      }
    }

    const safeAppend = function(row, col, newVal) {
      if (!newVal || newVal === "0") return;
      const range   = sh.getRange(row, col);
      const current = range.getValue().toString().replace(/^'/, "").trim();
      const valStr  = newVal.toString().trim();
      if (current === "" || current === "0") {
        range.setValue("'" + valStr);
      } else {
        const parts = current.split(",").map(function(s) { return s.trim(); });
        if (!parts.includes(valStr)) range.setValue("'" + current + ", " + valStr);
      }
    };

    if (rowIndex !== -1) {
      if (autoType && colMap[autoType]) safeAppend(rowIndex, colMap[autoType], autoVal);
      safeAppend(rowIndex, 7, teleVal);
      safeAppend(rowIndex, 8, rpVal);
      sh.getRange(rowIndex, 9).setValue(new Date().toLocaleString());
      sh.getRange(rowIndex, 11).setValue(scoutId);
      return { success: true, msg: "Merged" };
    } else {
      const newRow = sh.getLastRow() + 1;
      sh.getRange(newRow, 1).setValue(targetTeam);
      if (autoType && colMap[autoType]) sh.getRange(newRow, colMap[autoType]).setValue("'" + autoVal);
      sh.getRange(newRow, 6).setValue("'" + matchVal);
      sh.getRange(newRow, 7).setValue("'" + teleVal);
      sh.getRange(newRow, 8).setValue("'" + rpVal);
      sh.getRange(newRow, 9).setValue(new Date().toLocaleString());
      sh.getRange(newRow, 10).setValue(eventCode);
      sh.getRange(newRow, 11).setValue(scoutId);
      return { success: true, msg: "New row " + newRow };
    }
  } finally {
    lock.releaseLock();
  }
}

// ─── INTEL ───────────────────────────────────────────────────────────────────

function getUnifiedIntel(myId, tk, targetId, eventCode) {
  if (!auth(myId, tk)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("DATA_" + myId);
  if (!sh) return { success: false, msg: "No data found." };
  const rows        = sh.getDataRange().getValues();
  const cleanTarget = Number(targetId.toString().replace(/\D/g, ""));

  let entries = rows.filter(function(r) { return Number(r[0]) === cleanTarget; });
  if (eventCode && eventCode.trim() !== "") {
    entries = entries.filter(function(r) { return r[9].toString().trim() === eventCode.trim(); });
  }
  if (entries.length === 0) return { success: false, msg: "No data for this team." };

  const extractNumbers = function(val) {
    if (!val) return [];
    return val.toString().split(",").map(function(s) {
      const m = s.match(/(\d+)/);
      return m ? parseInt(m[1]) : 0;
    }).filter(function(n) { return n > 0; });
  };

  let allTele = [];
  entries.forEach(function(r) {
    var nums = extractNumbers(r[6]);
    nums.forEach(function(n) { allTele.push(n); });
  });
  const avgTele  = allTele.length ? (allTele.reduce(function(a,b){return a+b;},0) / allTele.length).toFixed(1) : 0;
  const last3    = allTele.slice(-3);
  const avgLast3 = last3.length  ? (last3.reduce(function(a,b){return a+b;},0)  / last3.length).toFixed(1)  : 0;

  return {
    success: true,
    data: {
      target: cleanTarget, avgTele, avgLast3, teleHistory: allTele,
      maxAuto: {
        rap:  Math.max.apply(null, [0].concat(entries.map(function(r){ return Math.max.apply(null, [0].concat(extractNumbers(r[1]))); }))),
        rdep: Math.max.apply(null, [0].concat(entries.map(function(r){ return Math.max.apply(null, [0].concat(extractNumbers(r[2]))); }))),
        aap:  Math.max.apply(null, [0].concat(entries.map(function(r){ return Math.max.apply(null, [0].concat(extractNumbers(r[3]))); }))),
        adep: Math.max.apply(null, [0].concat(entries.map(function(r){ return Math.max.apply(null, [0].concat(extractNumbers(r[4]))); })))
      }
    }
  };
}

// ─── MY DATA ─────────────────────────────────────────────────────────────────

function getMyFullTable(myId, tk) {
  if (!auth(myId, tk)) return { success: false };
  const sh = SS.getSheetByName("DATA_" + myId);
  return { success: true, table: sh ? sh.getDataRange().getValues() : [] };
}

// ─── EVENTS ──────────────────────────────────────────────────────────────────

function getEvents(teamId, token) {
  if (!auth(teamId, token)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("Events");
  if (!sh) return { success: true, events: [] };
  const rows = sh.getDataRange().getValues();
  const team = teamId.toString().trim();
  const events = [];
  for (let i = 1; i < rows.length; i++) {
    if (!rows[i][0]) continue;
    if (rows[i][3].toString().trim() !== team) continue;
    events.push({
      code: rows[i][0].toString().trim(),
      name: rows[i][1].toString().trim(),
      date: rows[i][2] ? rows[i][2].toString().trim() : ''
    });
  }
  return { success: true, events };
}

function addEvent(teamId, token, code, name, date) {
  if (!auth(teamId, token)) return { success: false, msg: "Auth failed" };
  if (!code || !name) return { success: false, msg: "Code and Name are required." };
  let sh = SS.getSheetByName("Events");
  if (!sh) { sh = SS.insertSheet("Events"); sh.appendRow(["eventCode","eventName","date","teamId"]); }
  const rows = sh.getDataRange().getValues();
  const team = teamId.toString().trim();
  const duplicate = rows.some(function(r, i) {
    return i > 0 && r[0].toString().trim() === code.toString().trim() && r[3].toString().trim() === team;
  });
  if (duplicate) return { success: false, msg: "Event code already exists." };
  sh.appendRow([code.toString().trim(), name.toString().trim(), date || '', team]);
  return { success: true };
}

// ─── LOGS ────────────────────────────────────────────────────────────────────

function addLog(p) {
  let sh = SS.getSheetByName("Logs");
  if (!sh) { sh = SS.insertSheet("Logs"); sh.appendRow(["Timestamp","ScoutID","TeamID","EventCode","Action","Details"]); }
  sh.appendRow([
    new Date().toLocaleString(),
    sanitize(p.scoutId   || '', 20),
    sanitize(p.myTeam    || '', 10),
    sanitize(p.eventCode || '', 30),
    sanitize(p.logAction || '', 50),
    sanitize(p.details   || '', 200)
  ]);
  return { success: true };
}

// ─── ADMIN: SCOUTERS ─────────────────────────────────────────────────────────

function adminGetScouters(teamId, token, adminPass) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: true, scouters: [] };
  const rows = sh.getDataRange().getValues();
  const team = teamId.toString().trim();
  const scouters = [];
  for (let i = 1; i < rows.length; i++) {
    if (rows[i][2].toString().trim() !== team) continue;
    scouters.push({ row: i + 1, name: rows[i][0], id: rows[i][1] });
  }
  return { success: true, scouters };
}

function adminAddScouter(teamId, token, adminPass, name, scouterId) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  let sh = SS.getSheetByName("scouters");
  if (!sh) { sh = SS.insertSheet("scouters"); sh.appendRow(["Name","Scouter_ID","Team"]); }
  const rows = sh.getDataRange().getValues();
  if (rows.some(function(r, i) { return i > 0 && r[1].toString().trim() === scouterId.toString().trim(); })) {
    return { success: false, msg: "Scouter ID already exists." };
  }
  sh.appendRow([name, scouterId, teamId.toString().trim()]);
  return { success: true };
}

function adminEditScouter(teamId, token, adminPass, rowIndex, name, scouterId) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: false, msg: "Service unavailable." };
  const row   = parseInt(rowIndex);
  const owner = sh.getRange(row, 3).getValue().toString().trim();
  if (owner !== teamId.toString().trim()) return { success: false, msg: "Not your scouter." };
  sh.getRange(row, 1).setValue(name);
  sh.getRange(row, 2).setValue(scouterId);
  return { success: true };
}

function adminDeleteScouter(teamId, token, adminPass, rowIndex) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: false, msg: "Service unavailable." };
  const row   = parseInt(rowIndex);
  const owner = sh.getRange(row, 3).getValue().toString().trim();
  if (owner !== teamId.toString().trim()) return { success: false, msg: "Not your scouter." };
  sh.deleteRow(row);
  return { success: true };
}

// ─── ADMIN: DATABASE ─────────────────────────────────────────────────────────

function adminGetData(teamId, token, adminPass) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("DATA_" + teamId);
  if (!sh) return { success: false, msg: "Service unavailable." };
  return { success: true, table: sh.getDataRange().getValues() };
}

function adminEditCell(teamId, token, adminPass, row, col, value) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("DATA_" + teamId);
  if (!sh) return { success: false, msg: "Service unavailable." };
  sh.getRange(parseInt(row), parseInt(col)).setValue(value);
  return { success: true };
}

function adminDeleteRow(teamId, token, adminPass, row) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("DATA_" + teamId);
  if (!sh) return { success: false, msg: "Service unavailable." };
  sh.deleteRow(parseInt(row));
  return { success: true };
}

// ─── ADMIN: EVENTS ───────────────────────────────────────────────────────────

function adminEditEvent(teamId, token, adminPass, rowIndex, code, name, date) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("Events");
  if (!sh) return { success: false, msg: "Service unavailable." };
  const row   = parseInt(rowIndex);
  const owner = sh.getRange(row, 4).getValue().toString().trim();
  if (owner !== teamId.toString().trim()) return { success: false, msg: "Not your event." };
  sh.getRange(row, 1).setValue(code);
  sh.getRange(row, 2).setValue(name);
  sh.getRange(row, 3).setValue(date || '');
  return { success: true };
}

function adminDeleteEvent(teamId, token, adminPass, rowIndex) {
  if (!authAdmin(teamId, token, adminPass)) return { success: false, msg: "Auth failed" };
  const sh = SS.getSheetByName("Events");
  if (!sh) return { success: false, msg: "Service unavailable." };
  const row   = parseInt(rowIndex);
  const owner = sh.getRange(row, 4).getValue().toString().trim();
  if (owner !== teamId.toString().trim()) return { success: false, msg: "Not your event." };
  sh.deleteRow(row);
  return { success: true };
}

// ─── SUPER-ADMIN: MFA AUTH ───────────────────────────────────────────────────

// Step 1: validate password + 2 security questions → send OTP
function superSendOtp(p) {
  const pass = sanitize(p.superPass, 100);
  const q1   = sanitize(p.q1,        20).trim();
  const q2   = sanitize(p.q2,        100).trim().toLowerCase();

  // Check if this IP-equivalent is daria-blocked
  const cache = CacheService.getScriptCache();
  if (cache.get('super_daria_block')) {
    auditSuperEvent("Login blocked (daria block active)", "Attempted access while block is active.");
    return { success: false, msg: "Access blocked. Try again later." };
  }

  // Detect the blocked trigger word — block for 5 minutes, alert owner, no further processing
  if (q2 === SUPER_Q2_BLOCKED) {
    cache.put('super_daria_block', '1', 300); // 5-minute block
    auditSuperEvent("BLOCKED: Trigger word entered", "The blocked answer was submitted for security question 2.");
    return { success: false, msg: "Access blocked for 5 minutes." };
  }

  const passOk = pass === SUPER_ADMIN_PASS;
  const q1Ok   = q1 === SUPER_Q1_ANSWER;
  const q2Ok   = q2 === SUPER_Q2_ANSWER.toLowerCase();

  if (!passOk || !q1Ok || !q2Ok) {
    auditSuperEvent("Failed login attempt", "Password: " + (passOk ? "OK" : "WRONG") + " | Q1: " + (q1Ok ? "OK" : "WRONG") + " | Q2: " + (q2Ok ? "OK" : "WRONG"));
    return { success: false, msg: "Invalid credentials." };
  }

  // Generate 6-digit OTP
  const otp = ("000000" + Math.floor(Math.random() * 1000000)).slice(-6);
  cache.put('super_otp', sha256(otp), SUPER_OTP_TTL);

  // Email OTP to owner
  try {
    MailApp.sendEmail(
      SUPER_OWNER_EMAIL,
      "[FTCIntel] Super Admin Login OTP",
      "Your one-time login code is: " + otp + "\n\nValid for 2 minutes.\n\nIf you did not request this, secure your account immediately."
    );
  } catch(e) {
    return { success: false, msg: "Failed to send OTP email." };
  }

  auditSuperEvent("OTP sent", "All credentials correct. OTP emailed to owner.");
  return { success: true, step: 'otp' };
}

// Step 2: validate OTP → create session token (single active session)
function superVerifyOtp(p) {
  const otp = sanitize(p.otp, 10).trim();
  if (!otp) return { success: false, msg: "OTP required." };

  const cache = CacheService.getScriptCache();
  const stored = cache.get('super_otp');
  if (!stored) {
    auditSuperEvent("OTP expired or not found", "OTP verification attempted but no OTP was stored.");
    return { success: false, msg: "OTP expired or invalid." };
  }
  if (sha256(otp) !== stored) {
    auditSuperEvent("Wrong OTP entered", "An incorrect OTP was submitted.");
    return { success: false, msg: "Incorrect OTP." };
  }

  // Invalidate OTP immediately (single use)
  cache.remove('super_otp');

  // Create new session token — invalidates any existing session
  const sessionToken = Utilities.getUuid();
  cache.put('super_session_token', sessionToken, SUPER_SESSION_TTL);

  auditSuperEvent("Login SUCCESS", "Session token created. Session TTL: " + SUPER_SESSION_TTL + "s.");
  return { success: true, sessionToken };
}

function superLogout(p) {
  const cache = CacheService.getScriptCache();
  cache.remove('super_session_token');
  auditSuperEvent("Logout", "Session token invalidated.");
  return { success: true };
}

function superSessionCheck(p) {
  return { success: verifySuperSession(p.sessionToken) };
}

// ─── SUPER-ADMIN: DATA OPERATIONS ────────────────────────────────────────────

function superGetTeams(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const sh = SS.getSheetByName("credentials");
  if (!sh) return { success: true, teams: [] };
  const d = sh.getDataRange().getValues();
  const teams = [];
  for (let i = 1; i < d.length; i++) {
    if (!d[i][0]) continue;
    teams.push({
      teamId: d[i][0].toString(),
      email:  d[i][2].toString(),
      date:   d[i][3] ? d[i][3].toString() : '',
      expiry: d[i][5] ? d[i][5].toString() : ''
    });
  }
  return { success: true, teams };
}

function superResetToken(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const teamId = sanitize(p.teamId, 10);
  const numId  = parseInt(teamId.replace(/\D/g, ""), 10);
  if (!numId) return { success: false, msg: "Invalid team ID." };

  const sh = SS.getSheetByName("credentials");
  if (!sh) return { success: false, msg: "Service unavailable." };
  const d = sh.getDataRange().getValues();

  let rowIndex = -1;
  let email    = '';
  for (let i = 1; i < d.length; i++) {
    if (Number(d[i][0]) === numId) { rowIndex = i + 1; email = d[i][2].toString(); break; }
  }
  if (rowIndex === -1) return { success: false, msg: "Team not found." };

  const newToken = "TK-" + Math.random().toString(36).substr(2, 9).toUpperCase();
  const expiry   = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
  sh.getRange(rowIndex, 2).setValue(sha256(newToken));
  sh.getRange(rowIndex, 6).setValue(expiry);

  try {
    MailApp.sendEmail(email, "FTCIntel - Token Reset", "Your new access token: " + newToken);
  } catch(e) {}

  return { success: true, newToken };
}

function superDeleteTeam(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const teamId = sanitize(p.teamId, 10);
  const numId  = parseInt(teamId.replace(/\D/g, ""), 10);
  if (!numId) return { success: false, msg: "Invalid team ID." };

  // Remove from credentials sheet
  const credSh = SS.getSheetByName("credentials");
  if (credSh) {
    const d = credSh.getDataRange().getValues();
    for (let i = d.length - 1; i >= 1; i--) {
      if (Number(d[i][0]) === numId) { credSh.deleteRow(i + 1); break; }
    }
  }

  // Delete data sheet
  const dataSh = SS.getSheetByName("DATA_" + numId);
  if (dataSh) SS.deleteSheet(dataSh);

  // Remove from Events sheet
  const evSh = SS.getSheetByName("Events");
  if (evSh) {
    const ev = evSh.getDataRange().getValues();
    for (let i = ev.length - 1; i >= 1; i--) {
      if (ev[i][3].toString().trim() === numId.toString()) evSh.deleteRow(i + 1);
    }
  }

  // Remove from scouters sheet
  const scSh = SS.getSheetByName("scouters");
  if (scSh) {
    const sc = scSh.getDataRange().getValues();
    for (let i = sc.length - 1; i >= 1; i--) {
      if (sc[i][2].toString().trim() === numId.toString()) scSh.deleteRow(i + 1);
    }
  }

  return { success: true };
}

function superGetLogs(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const sh = SS.getSheetByName("Logs");
  if (!sh) return { success: true, logs: [], total: 0 };
  const all   = sh.getDataRange().getValues();
  const total = Math.max(0, all.length - 1);
  const header = all[0];
  const rows   = all.slice(1);
  const slice  = rows.slice(-300);
  return { success: true, logs: [header].concat(slice), total };
}

function superGetAllScouters(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: true, scouters: [] };
  const d = sh.getDataRange().getValues();
  const scouters = [];
  for (let i = 1; i < d.length; i++) {
    if (!d[i][0] && !d[i][1]) continue;
    scouters.push({ row: i + 1, name: d[i][0].toString(), id: d[i][1].toString(), team: d[i][2].toString() });
  }
  return { success: true, scouters };
}

function superDeleteScouter(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const row = parseInt(sanitize(p.rowIndex, 10));
  if (!row || row < 2) return { success: false, msg: "Invalid row." };
  const sh = SS.getSheetByName("scouters");
  if (!sh) return { success: false, msg: "Service unavailable." };
  if (row > sh.getLastRow()) return { success: false, msg: "Row out of bounds." };
  sh.deleteRow(row);
  return { success: true };
}

function superGetAllEvents(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const sh = SS.getSheetByName("Events");
  if (!sh) return { success: true, events: [] };
  const d = sh.getDataRange().getValues();
  const events = [];
  for (let i = 1; i < d.length; i++) {
    if (!d[i][0]) continue;
    events.push({
      code:   d[i][0].toString(),
      name:   d[i][1].toString(),
      date:   d[i][2] ? d[i][2].toString() : '',
      teamId: d[i][3].toString()
    });
  }
  return { success: true, events };
}

function superSendMail(p) {
  if (!verifySuperSession(p.sessionToken)) return { success: false, msg: "Unauthorized." };
  const recipient = sanitize(p.recipient, 2000); // increased for comma-separated IDs
  const subject   = sanitize(p.subject,   200);
  const body      = (p.body || '').toString().substring(0, 1000);

  if (!subject || !body) return { success: false, msg: "Subject and body required." };

  const credSh = SS.getSheetByName("credentials");
  if (!credSh) return { success: false, msg: "No teams found." };
  const d = credSh.getDataRange().getValues();

  let targets = [];
  if (recipient === 'all') {
    for (let i = 1; i < d.length; i++) {
      if (d[i][2]) targets.push(d[i][2].toString());
    }
  } else {
    // Support comma-separated list of team IDs
    const teamIds = recipient.split(',').map(function(id) {
      return parseInt(id.trim().replace(/\D/g, ''), 10);
    }).filter(function(id) { return id > 0; });
    for (let i = 1; i < d.length; i++) {
      if (teamIds.indexOf(Number(d[i][0])) !== -1 && d[i][2]) {
        targets.push(d[i][2].toString());
      }
    }
  }

  if (!targets.length) return { success: false, msg: "No recipients found." };

  const plainFooter = "\n\n---\nThis message was sent automatically by FTCIntel administrators. For further inquiries, please contact us at " + SUPER_OWNER_EMAIL + ".";
  const htmlFooter  = "<br><br><hr><em>This message was sent automatically by FTCIntel administrators. For further inquiries, please contact us at <a href='mailto:" + SUPER_OWNER_EMAIL + "'>" + SUPER_OWNER_EMAIL + "</a>.</em>";
  const htmlBody    = body.replace(/\n/g, '<br>') + htmlFooter;

  let sent = 0, failed = 0;
  targets.forEach(function(email) {
    try {
      MailApp.sendEmail(email, subject, body + plainFooter, { htmlBody: htmlBody });
      sent++;
    } catch(e) { failed++; }
  });

  return { success: true, sent, failed };
}

// ─── AI ANALYSIS (GEMINI) ────────────────────────────────────────────────────

function getAiAnalysis(myTeam, myToken, targetId, eventCode) {
  if (!auth(myTeam, myToken)) return { success: false, msg: "Auth failed" };

  const sh = SS.getSheetByName("DATA_" + myTeam);
  if (!sh) return { success: false, msg: "No data found." };

  const rows         = sh.getDataRange().getValues();
  const cleanTarget  = Number(targetId.toString().replace(/\D/g, ""));
  const allEvents    = !eventCode || eventCode.trim() === "";

  let entries = rows.filter(function(r) { return Number(r[0]) === cleanTarget; });
  if (!allEvents) {
    entries = entries.filter(function(r) { return r[9].toString().trim() === eventCode.trim(); });
  }
  if (entries.length === 0) return { success: false, msg: "No data for this team." };

  // Build compact data string for the prompt
  const dataLines = entries.map(function(r) {
    return [
      "Match:"    + (r[5]  || "-"),
      "Event:"    + (r[9]  || "-"),
      "RC:"       + (r[1]  || "0"),
      "RF:"       + (r[2]  || "0"),
      "BC:"       + (r[3]  || "0"),
      "BF:"       + (r[4]  || "0"),
      "Tele:"     + (r[6]  || "0"),
      "RP:"       + (r[7]  || "0"),
      "Time:"     + (r[8]  || "-")
    ].join(" | ");
  }).join("\n");

  const columnKey = "Columns: Match | Event | Red-Close Auto | Red-Far Auto | Blue-Close Auto | Blue-Far Auto | Teleop Score | Ranking Points | Timestamp";

  let prompt;

  if (allEvents) {
    const eventNames = entries
      .map(function(r) { return r[9].toString().trim(); })
      .filter(function(v, i, a) { return v && a.indexOf(v) === i; })
      .join(", ");

    prompt =
      "You are an expert FTC (FIRST Tech Challenge) robot performance analyst.\n" +
      "Below is scouting data for team " + cleanTarget + " across events: " + eventNames + ".\n" +
      columnKey + "\n\n" +
      dataLines + "\n\n" +
      "Write a detailed multi-event performance report covering:\n" +
      "1. Performance evolution across events — did they improve, regress, or stay flat?\n" +
      "2. Auto period tendencies: preferred starting position (Red Close/Far vs Blue Close/Far), scoring rates, consistency\n" +
      "3. Teleop scoring averages, peaks, variance, and progression over time\n" +
      "4. Ranking Points contribution pattern\n" +
      "5. Driver behavior and robot tendencies inferred from the data\n" +
      "6. Any signs of mechanical issues, match-to-match inconsistencies, or performance drops\n" +
      "7. Event-by-event highlights and key differences\n" +
      "8. Overall alliance selection recommendation with strengths and risks\n\n" +
      "Be specific with numbers. Use a clear, professional scouting report tone.";
  } else {
    prompt =
      "You are an expert FTC (FIRST Tech Challenge) robot performance analyst.\n" +
      "Below is scouting data for team " + cleanTarget + " at event '" + eventCode + "'.\n" +
      columnKey + "\n\n" +
      dataLines + "\n\n" +
      "Write a detailed single-event performance report covering:\n" +
      "1. Scoring averages and consistency (Teleop, Auto, RP)\n" +
      "2. Auto period tendencies: which starting positions do they prefer and why, how reliable are they?\n" +
      "3. Color alliance tendencies — do they score better on Red or Blue side?\n" +
      "4. Teleop scoring pattern — peaks, lows, trend across matches (improving, declining, erratic?)\n" +
      "5. Driver behavior — aggressive, conservative, methodical? Any notable tendencies?\n" +
      "6. Signs of mechanical issues or anomalies between matches\n" +
      "7. Ranking Points strategy and reliability\n" +
      "8. Strengths, weaknesses, and alliance suitability for eliminations\n\n" +
      "Be specific with numbers. Use a clear, professional scouting report tone.";
  }

  try {
    const payload = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.35, maxOutputTokens: 1200 }
    });

    const apiKey = PropertiesService.getScriptProperties().getProperty('GEMINI_API_KEY');
    if (!apiKey) return { success: false, msg: "AI service not configured." };

    const res  = UrlFetchApp.fetch(GEMINI_URL + apiKey, {
      method: 'post',
      contentType: 'application/json',
      payload: payload,
      muteHttpExceptions: true
    });

    const json = JSON.parse(res.getContentText());

    if (json.candidates && json.candidates[0] && json.candidates[0].content) {
      return { success: true, analysis: json.candidates[0].content.parts[0].text };
    }
    return { success: false, msg: "AI analysis unavailable." };
  } catch(e) {
    return { success: false, msg: "AI service error." };
  }
}
