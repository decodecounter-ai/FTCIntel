// FTCIntel — Google Apps Script Backend (Secured)
// Paste the entire contents of this file into your GAS project editor.
// IMPORTANT: Change APP_KEY to a unique random string and redeploy.

const SS = SpreadsheetApp.getActiveSpreadsheet();

// Must match APP_KEY in config.js
const APP_KEY = "FTCI-2026-S3CR3T-Ro2D2";

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

// ─── ROUTER ──────────────────────────────────────────────────────────────────

function doGet(e) {
  if (!e || !e.parameter) return response({ success: false, msg: "Bad request." });
  const p      = e.parameter;
  const action = p.action ? p.action.toLowerCase().trim() : "";

  // Rate limiting — signup is stricter (3 per hour per team)
  const rlId  = (p.myTeam || p.teamId || p.team || 'anon') + '_' + action;
  const rlMax = (action === 'signup') ? 3  : 30;
  const rlWin = (action === 'signup') ? 3600 : 60;
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
      "FTCIntel - Credentiale echipa",
      "Token acces: " + token + "\nParola Admin: " + adminPass
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
