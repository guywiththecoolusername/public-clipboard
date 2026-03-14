const apiUrl = "https://clipboard-test-files.guywiththecoolusername.workers.dev/";
const SECRET_PREFIX = 'PASSWORD_PROTECTED_DATA=';
const FILE_PREFIX   = 'FILE_ENTRY=';

// ── WebCrypto: TEXT ───────────────────────────────────────────────

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 200000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(plaintext, password) {
  const enc = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
  const combined = new Uint8Array(16 + 12 + cipherBuf.byteLength);
  combined.set(salt, 0); combined.set(iv, 16); combined.set(new Uint8Array(cipherBuf), 28);
  return btoa(String.fromCharCode(...combined));
}

async function decryptText(b64, password) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt  = bytes.slice(0, 16);
  const iv    = bytes.slice(16, 28);
  const cipher= bytes.slice(28);
  const key   = await deriveKey(password, salt);
  try {
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    return new TextDecoder().decode(plainBuf);
  } catch { return null; }
}

// ── WebCrypto: FILE ───────────────────────────────────────────────

async function generateFileKey() {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const raw = await crypto.subtle.exportKey("raw", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function importRawKey(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptFileAuto(buffer, rawB64) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const key = await importRawKey(rawB64);
  const enc = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);
  const out = new Uint8Array(12 + enc.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(enc), 12);
  return out.buffer;
}

async function decryptFileAuto(buffer, rawB64) {
  const bytes = new Uint8Array(buffer);
  const key   = await importRawKey(rawB64);
  return crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
}

async function encryptFilePassword(buffer, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(password, salt);
  const enc  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);
  const out  = new Uint8Array(16 + 12 + enc.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(enc), 28);
  return out.buffer;
}

async function decryptFilePassword(buffer, password) {
  const bytes = new Uint8Array(buffer);
  const key   = await deriveKey(password, bytes.slice(0, 16));
  try {
    return await crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(16, 28) }, key, bytes.slice(28));
  } catch { return null; }
}

// ── Archive detection ─────────────────────────────────────────────

async function detectArchiveProtection(file) {
  try {
    const reader  = new zip.ZipReader(new zip.BlobReader(file));
    const entries = await reader.getEntries();
    await reader.close();
    if (!entries.length) return { isArchive: true, format: "ZIP", isProtected: false };
    return { isArchive: true, format: "ZIP", isProtected: entries.some(e => e.encrypted) };
  } catch {
    return { isArchive: false, format: null, isProtected: false };
  }
}

// ── Helpers ───────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes < 1024)       return bytes + " B";
  if (bytes < 1048576)    return (bytes / 1024).toFixed(1) + " KB";
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + " MB";
  return (bytes / 1073741824).toFixed(1) + " GB";
}

function fileIcon(mimeType, name) {
  const m = (mimeType || "").toLowerCase();
  const n = (name     || "").toLowerCase();
  if (m.startsWith("image/"))                                          return "🖼️";
  if (m.startsWith("video/"))                                          return "🎬";
  if (m.startsWith("audio/"))                                          return "🎵";
  if (m.includes("pdf"))                                               return "📕";
  if (m.includes("zip")||m.includes("x-7z")||m.includes("rar")||
      n.endsWith(".zip")||n.endsWith(".7z")||n.endsWith(".rar"))       return "📦";
  if (m.includes("text")||n.endsWith(".txt")||n.endsWith(".md"))       return "📝";
  if (m.includes("javascript")||m.includes("json")||
      m.includes("html")||m.includes("css"))                          return "💻";
  return "📄";
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Animate a clip swiping out, then run callback ─────────────────
function deleteWithAnimation(el, callback) {
  el.classList.add("deleting");
  setTimeout(callback, 380);
}

// ── DOM refs ──────────────────────────────────────────────────────

const textContainer = document.getElementById("textContainer");

// ── Draft clip state ──────────────────────────────────────────────

let draftMode    = null;   // 'text' | 'file'
let draftFile    = null;   // { file, encrypted, autoKey }
let draftEncOn   = false;
let draftDragCnt = 0;
let holdTimer    = null;

// ── Draft clip: build DOM ─────────────────────────────────────────

function buildDraftClip() {
  const el = document.createElement("div");
  el.id = "draftClip";
  el.className = "draft-clip";
  el.innerHTML = `
    <!-- drag overlay — covers the whole clip incl fields on accidental drops -->
    <div class="draft-drag-overlay" id="draftDragOverlay">
      <span class="draft-drag-overlay-icon">📂</span>
      <span class="draft-drag-overlay-text">drop to attach</span>
    </div>

    <!-- dormant: click = text, right-click / long-press = file -->
    <div class="draft-dormant" id="draftDormant">
      <div class="draft-plus-circle">+</div>
      <span class="draft-dormant-label">new clip</span>
      <span class="draft-dormant-hint">left click for text · right click or hold for file</span>
    </div>

    <!-- editor (shown when active) -->
    <div class="draft-editor" id="draftEditor">

      <!-- TEXT mode -->
      <textarea class="draft-ta" id="draftTa" placeholder="Type or paste text…" rows="2"></textarea>

      <!-- FILE mode -->
      <div class="draft-file-zone" id="draftFileZone">
        <div class="draft-fdt" id="draftFdt">
          <div class="draft-fdt-plus" id="draftFdtPlus">+</div>
          <div class="draft-fdt-text" id="draftFdtText">
            <div class="draft-fdt-label">click to select · or drop anywhere on this clip</div>
            <div class="draft-fdt-hint">under 100 MB: auto-encrypted · over 100 MB: must be a password-protected ZIP</div>
          </div>
          <div class="draft-chip" id="draftChip">
            <span class="draft-chip-icon" id="draftChipIcon">📄</span>
            <div class="draft-chip-info">
              <div class="draft-chip-name" id="draftChipName">—</div>
              <div class="draft-chip-size" id="draftChipSize"></div>
            </div>
            <span class="draft-chip-close" id="draftChipClose">✕</span>
          </div>
        </div>
      </div>

      <!-- progress bar (shown during file upload) -->
      <div class="draft-progress-wrap" id="draftProgressWrap">
        <div class="draft-progress-bar" id="draftProgressBar"></div>
      </div>
      <div class="draft-progress-label" id="draftProgressLabel"></div>

      <!-- encrypt (optional) -->
      <div class="draft-fields" id="draftFields">
        <div class="draft-enc-row" id="draftEncRow">
          <label id="draftEncLabel">encrypt</label>
          <input type="password" id="draftEncInput" placeholder="encryption key" autocomplete="off" />
          <span class="draft-fclose" id="draftCloseEnc">✕</span>
        </div>
        <!-- password (always required) -->
        <div class="draft-pwd-row">
          <label>password <span class="draft-req-star">*</span></label>
          <input type="password" id="draftPwdInput" placeholder="required" autocomplete="off" />
        </div>
      </div>

      <!-- toolbar -->
      <div class="draft-toolbar" id="draftToolbar">
        <button class="draft-pill" id="draftPillEnc">🔒 <span id="draftPillEncLabel">encrypt</span></button>
        <div class="draft-spacer"></div>
        <button class="draft-btn-discard" id="draftDiscard">discard</button>
        <button class="draft-btn-save" id="draftSave">save clip</button>
      </div>

    </div>
  `;
  return el;
}

// ── Draft clip: init interactions ─────────────────────────────────

function initDraft() {
  const el          = document.getElementById("draftClip");
  const dormant     = document.getElementById("draftDormant");
  const ta          = document.getElementById("draftTa");
  const fdt         = document.getElementById("draftFdt");
  const chip        = document.getElementById("draftChip");
  const chipClose   = document.getElementById("draftChipClose");
  const pillEnc     = document.getElementById("draftPillEnc");
  const encRow      = document.getElementById("draftEncRow");
  const closeEnc    = document.getElementById("draftCloseEnc");
  const pwdInput    = document.getElementById("draftPwdInput");
  const discardBtn  = document.getElementById("draftDiscard");
  const saveBtn     = document.getElementById("draftSave");

  // ── Dormant: left click = text, right click = file ──
  dormant.addEventListener("click", e => {
    e.preventDefault();
    activateDraft("text");
  });
  dormant.addEventListener("contextmenu", e => {
    e.preventDefault();
    activateDraft("file");
  });
  // Long press for mobile = file
  dormant.addEventListener("touchstart", () => {
    holdTimer = setTimeout(() => activateDraft("file"), 500);
  }, { passive: true });
  dormant.addEventListener("touchend",  () => clearTimeout(holdTimer));
  dormant.addEventListener("touchmove", () => clearTimeout(holdTimer));

  // ── Textarea auto-grow ──
  ta.addEventListener("input", () => {
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 260) + "px";
  });
  ta.addEventListener("keydown", e => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) saveBtn.click();
  });

  // ── File drop target click ──
  fdt.addEventListener("click", () => {
    if (draftFile) return;
    const inp = document.createElement("input");
    inp.type = "file";
    inp.onchange = async ev => {
      const f = ev.target.files[0];
      if (f) await draftAttachFile(f);
    };
    inp.click();
  });

  // ── Remove attached file ──
  chipClose.addEventListener("click", e => {
    e.stopPropagation();
    draftClearFile();
  });

  // ── Encrypt pill ──
  pillEnc.addEventListener("click", () => {
    draftEncOn = !draftEncOn;
    pillEnc.classList.toggle("on", draftEncOn);
    encRow.classList.toggle("visible", draftEncOn);
    if (draftEncOn) setTimeout(() => document.getElementById("draftEncInput").focus(), 60);
  });
  closeEnc.addEventListener("click", () => {
    draftEncOn = false;
    pillEnc.classList.remove("on");
    encRow.classList.remove("visible");
    document.getElementById("draftEncInput").value = "";
  });

  // ── Password error clear on type ──
  pwdInput.addEventListener("input", () => pwdInput.classList.remove("error"));

  // ── Discard ──
  discardBtn.addEventListener("click", resetDraft);

  // ── Click outside draft to dismiss if empty ──
  document.addEventListener("click", e => {
    const el = document.getElementById("draftClip");
    if (!el || !el.classList.contains("active")) return;
    if (el.contains(e.target)) return;

    const isEmpty = draftMode === "text"
      ? !document.getElementById("draftTa").value.trim()
      : !draftFile;

    if (isEmpty) resetDraft();
  });

  // ── Save ──
  saveBtn.addEventListener("click", submitDraft);

  // ── Drag & drop — entire clip is the drop zone ──
  el.addEventListener("dragenter", e => {
    if (!e.dataTransfer.types.includes("Files")) return;
    e.preventDefault();
    draftDragCnt++;
    el.classList.add("drag-over");
    document.getElementById("draftDragOverlay").classList.add("visible");
  });
  el.addEventListener("dragleave", () => {
    draftDragCnt--;
    if (draftDragCnt <= 0) {
      draftDragCnt = 0;
      el.classList.remove("drag-over");
      document.getElementById("draftDragOverlay").classList.remove("visible");
    }
  });
  el.addEventListener("dragover", e => e.preventDefault());
  el.addEventListener("drop", async e => {
    e.preventDefault();
    draftDragCnt = 0;
    el.classList.remove("drag-over");
    document.getElementById("draftDragOverlay").classList.remove("visible");

    const file = e.dataTransfer.files[0];
    if (!file) return;

    // If currently in text mode (or dormant), switch to file
    if (draftMode !== "file") activateDraft("file");

    el.classList.add("drop-pulse");
    setTimeout(() => el.classList.remove("drop-pulse"), 450);
    await draftAttachFile(file);
  });
}

// ── Draft: activate ───────────────────────────────────────────────

function activateDraft(mode) {
  draftMode = mode;
  const el = document.getElementById("draftClip");
  el.classList.add("active");

  const ta       = document.getElementById("draftTa");
  const fileZone = document.getElementById("draftFileZone");
  const pillLbl  = document.getElementById("draftPillEncLabel");
  const encLbl   = document.getElementById("draftEncLabel");

  if (mode === "text") {
    ta.style.display       = "";
    fileZone.classList.remove("visible");
    pillLbl.textContent    = "encrypt";
    encLbl.textContent     = "encrypt";
    setTimeout(() => ta.focus(), 40);
  } else {
    ta.style.display       = "none";
    fileZone.classList.add("visible");
    pillLbl.textContent    = "custom key";
    encLbl.textContent     = "custom key";
  }
}

// ── Draft: reset to dormant ───────────────────────────────────────

function resetDraft() {
  const el = document.getElementById("draftClip");

  // Strip morph styles
  el.style.height     = "";
  el.style.overflow   = "";
  el.style.transition = "";
  el.classList.remove("active", "morphing", "drag-over", "drop-pulse");

  // Reset fields
  document.getElementById("draftTa").value        = "";
  document.getElementById("draftTa").style.height = "";
  document.getElementById("draftTa").style.display = "";
  document.getElementById("draftPwdInput").value  = "";
  document.getElementById("draftPwdInput").classList.remove("error");
  document.getElementById("draftEncInput").value  = "";
  document.getElementById("draftDragOverlay").classList.remove("visible");

  // Reset fields opacity (after morph)
  const fields  = document.getElementById("draftFields");
  const toolbar = document.getElementById("draftToolbar");
  const pw      = document.getElementById("draftProgressWrap");
  const pwLabel = document.getElementById("draftProgressLabel");
  [fields, toolbar, pw, pwLabel].forEach(n => {
    if (!n) return;
    n.style.opacity      = "";
    n.style.transition   = "";
    n.style.pointerEvents = "";
    n.style.visibility   = "";
  });
  pw.classList.remove("visible");
  document.getElementById("draftProgressBar").style.width = "0%";
  document.getElementById("draftProgressLabel").textContent = "";

  // Reset encrypt pill
  draftEncOn = false;
  document.getElementById("draftPillEnc").classList.remove("on");
  document.getElementById("draftEncRow").classList.remove("visible");

  // Reset file zone
  draftClearFile();
  document.getElementById("draftFileZone").classList.remove("visible");

  // Re-show save button text
  const saveBtn = document.getElementById("draftSave");
  saveBtn.disabled = false;
  saveBtn.textContent = "save clip";

  draftMode = null;
  draftFile = null;
}

// ── Draft: attach file ────────────────────────────────────────────

async function draftAttachFile(file) {
  draftClearFile();

  const ext = file.name.includes(".") ? file.name.split(".").pop().toLowerCase() : null;
  const fdt = document.getElementById("draftFdt");

  if (!ext) {
    fdt.classList.add("has-error");
    document.getElementById("draftFdtText").querySelector(".draft-fdt-label").textContent =
      "❌ Extensionless files are not allowed";
    return;
  }

  const MB100 = 100 * 1024 * 1024;

  if (file.size > MB100) {
    const result = await detectArchiveProtection(file);
    if (result.format !== "ZIP") {
      document.getElementById("draftFdtText").querySelector(".draft-fdt-label").textContent =
        "❌ Files over 100 MB must be a password-protected ZIP";
      document.getElementById("draftFdtText").querySelector(".draft-fdt-hint").textContent =
        "Use WinRAR, 7-Zip, or similar to create an encrypted ZIP first";
      return;
    }
    if (!result.isProtected) {
      document.getElementById("draftFdtText").querySelector(".draft-fdt-label").textContent =
        "❌ This ZIP is not password-protected — please encrypt it first";
      return;
    }
    draftFile = { file, encrypted: false, autoKey: null };
  } else {
    draftFile = { file, encrypted: true, autoKey: null };
  }

  // Show chip
  const chip = document.getElementById("draftChip");
  document.getElementById("draftChipIcon").textContent  = fileIcon(file.type, file.name);
  document.getElementById("draftChipName").textContent  = file.name;
  document.getElementById("draftChipSize").textContent  = formatBytes(file.size);
  chip.classList.add("visible");
  fdt.classList.add("has-file");
  document.getElementById("draftFdtPlus").style.display  = "none";
  document.getElementById("draftFdtText").style.display  = "none";
}

function draftClearFile() {
  draftFile = null;
  const chip = document.getElementById("draftChip");
  const fdt  = document.getElementById("draftFdt");
  chip.classList.remove("visible");
  fdt.classList.remove("has-file", "has-error");
  document.getElementById("draftFdtPlus").style.display  = "";
  document.getElementById("draftFdtText").style.display  = "";
  // Reset hint text in case it was changed by error
  document.getElementById("draftFdtText").querySelector(".draft-fdt-label").textContent =
    "click to select · or drop anywhere on this clip";
  document.getElementById("draftFdtText").querySelector(".draft-fdt-hint").textContent =
    "under 100 MB: auto-encrypted · over 100 MB: must be a password-protected ZIP";
}

// ── Draft: morph animation ────────────────────────────────────────

async function playMorph() {
  const el      = document.getElementById("draftClip");
  const fields  = document.getElementById("draftFields");
  const toolbar = document.getElementById("draftToolbar");
  const pw      = document.getElementById("draftProgressWrap");
  const pwLabel = document.getElementById("draftProgressLabel");
  const ta      = document.getElementById("draftTa");
  const fz      = document.getElementById("draftFileZone");

  // ── Step 1: snapshot current rendered height ──────────────────
  const fullH = el.getBoundingClientRect().height;

  // ── Step 2: cross-fade fields + toolbar out (100ms) ───────────
  const fadeTargets = [fields, toolbar, pw, pwLabel].filter(Boolean);
  fadeTargets.forEach(n => {
    n.style.transition = "opacity 0.1s ease";
    n.style.opacity    = "0";
    n.style.pointerEvents = "none";
  });

  await delay(110);

  // ── Step 3: measure the content-only height ───────────────────
  // Temporarily hide the faded sections from layout to measure content
  fadeTargets.forEach(n => { n.style.visibility = "hidden"; });

  let contentH;
  if (draftMode === "text") {
    // just the textarea itself
    contentH = ta.getBoundingClientRect().height + 2; // +2 for border
  } else {
    contentH = fz.getBoundingClientRect().height + 18;
  }
  contentH = Math.max(contentH, 50);

  // Restore visibility (opacity is still 0)
  fadeTargets.forEach(n => { n.style.visibility = ""; });

  // ── Step 4: pin height then animate down ─────────────────────
  el.style.overflow   = "hidden";
  el.style.height     = fullH + "px";
  el.style.transition = "none";

  // Flush, then transition
  el.getBoundingClientRect(); // force reflow
  el.style.transition = "height 0.42s cubic-bezier(0.4, 0, 0.2, 1), border-color 0.3s ease";
  el.style.height     = contentH + "px";

  await delay(450);
}

// ── Draft: set progress ───────────────────────────────────────────

function draftSetProgress(pct, label) {
  const wrap = document.getElementById("draftProgressWrap");
  wrap.classList.add("visible");
  document.getElementById("draftProgressBar").style.width = pct + "%";
  document.getElementById("draftProgressLabel").textContent = label;
}

// ── Draft: submit ─────────────────────────────────────────────────

async function submitDraft() {
  const pwdInput = document.getElementById("draftPwdInput");
  const saveBtn  = document.getElementById("draftSave");

  if (!pwdInput.value.trim()) {
    pwdInput.classList.add("error");
    pwdInput.focus();
    return;
  }

  const password = pwdInput.value.trim();
  const hasContent = draftMode === "text"
    ? document.getElementById("draftTa").value.trim().length > 0
    : draftFile !== null;

  if (!hasContent) return;

  saveBtn.disabled    = true;
  saveBtn.textContent = "saving…";

  try {
    if (draftMode === "text") {
      await submitDraftText(password);
    } else {
      await submitDraftFile(password);
    }

    // Morph then refresh
    await playMorph();
    await fetchTexts(true);
    resetDraft();

  } catch (err) {
    console.error(err);
    // Show error, re-enable
    pwdInput.classList.add("error");
    pwdInput.placeholder = "wrong password";
    saveBtn.disabled    = false;
    saveBtn.textContent = "save clip";
    // Restore fields visibility
    document.getElementById("draftFields").style.opacity = "";
    document.getElementById("draftToolbar").style.opacity = "";
    const el = document.getElementById("draftClip");
    el.style.height = ""; el.style.overflow = ""; el.style.transition = "";
  }
}

async function submitDraftText(password) {
  const rawText  = document.getElementById("draftTa").value.trim();
  const encInput = document.getElementById("draftEncInput");

  let texttoadd = rawText;
  if (draftEncOn && encInput.value) {
    const encrypted = await encryptText(rawText, encInput.value);
    texttoadd = SECRET_PREFIX + '"' + encrypted + '"';
  }

  const res = await fetch(apiUrl, {
    method:  "PUT",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ password, texttoadd }),
  });
  const data = await res.json().catch(() => ({}));
  if (data.error) throw new Error(data.error);
}

async function submitDraftFile(password) {
  if (!draftFile) throw new Error("No file selected");

  const { file, encrypted } = draftFile;
  const encInput    = document.getElementById("draftEncInput");
  const useCustomKey = draftEncOn && encInput.value;

  let fileBuffer = await file.arrayBuffer();
  let autoKey    = null;

  if (encrypted) {
    draftSetProgress(15, "Encrypting…");
    if (useCustomKey) {
      fileBuffer = await encryptFilePassword(fileBuffer, encInput.value);
    } else {
      autoKey    = await generateFileKey();
      fileBuffer = await encryptFileAuto(fileBuffer, autoKey);
    }
  }

  draftSetProgress(35, "Authorising…");
  const tokenRes  = await fetch(apiUrl + "token?password=" + encodeURIComponent(password));
  const tokenData = await tokenRes.json();
  if (!tokenData.accessToken) throw new Error(tokenData.error || "Auth failed — wrong password?");

  draftSetProgress(55, "Uploading…");
  const storedName = encrypted ? file.name + ".enc" : file.name;
  const storedMime = encrypted ? "application/octet-stream" : (file.type || "application/octet-stream");
  const boundary   = "browser_upload_boundary";
  const enc        = new TextEncoder();
  const metaPart   = `--${boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n${JSON.stringify({ name: storedName })}\r\n`;
  const filePart   = `--${boundary}\r\nContent-Type: ${storedMime}\r\n\r\n`;
  const endPart    = `\r\n--${boundary}--`;
  const body = new Uint8Array([
    ...enc.encode(metaPart),
    ...enc.encode(filePart),
    ...new Uint8Array(fileBuffer),
    ...enc.encode(endPart),
  ]);

  const uploadRes = await fetch(
    "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart",
    {
      method:  "POST",
      headers: {
        "Authorization": `Bearer ${tokenData.accessToken}`,
        "Content-Type":  `multipart/related; boundary=${boundary}`,
      },
      body,
    }
  );
  const uploadData = await uploadRes.json();
  if (!uploadData.id) throw new Error("Drive upload failed: " + JSON.stringify(uploadData));

  draftSetProgress(85, "Saving…");
  const regRes = await fetch(apiUrl + "register-file", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      password,
      driveId:  uploadData.id,
      name:     file.name,
      size:     file.size,
      mimeType: file.type || "application/octet-stream",
      encrypted,
      autoKey,
    }),
  });
  const regData = await regRes.json();
  if (!regData.success) throw new Error(regData.error || "Registration failed");
  draftSetProgress(100, "Done!");
}

// ── File download ─────────────────────────────────────────────────

async function downloadFile(meta) {
  const res    = await fetch(apiUrl + "file?id=" + meta.driveId);
  const buffer = await res.arrayBuffer();

  let finalBuffer;
  if (meta.encrypted) {
    if (meta.autoKey) {
      finalBuffer = await decryptFileAuto(buffer, meta.autoKey);
    } else {
      while (true) {
        const key = await promptDecryptKey();
        if (key === null) return;
        const result = await decryptFilePassword(buffer, key);
        if (result === null) {
          decryptBackdrop.classList.add("active");
          decryptError.style.display = "block";
          continue;
        }
        finalBuffer = result;
        break;
      }
    }
  } else {
    finalBuffer = buffer;
  }

  const blob = new Blob([finalBuffer], { type: meta.mimeType || "application/octet-stream" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = meta.name;          // must be in DOM for Firefox / some Chromium builds
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

// ── Deep link handler ─────────────────────────────────────────────
// Copy link encodes the file meta so opening the URL auto-triggers download

function handleDeepLink() {
  const params = new URLSearchParams(window.location.search);
  const dl = params.get("dl");
  if (!dl) return;
  try {
    const meta = JSON.parse(decodeURIComponent(escape(atob(dl))));
    history.replaceState({}, "", window.location.pathname);
    // Wait for modals to be ready, then trigger download
    requestAnimationFrame(() => downloadFile(meta));
  } catch (e) {
    console.warn("Deep link parse failed", e);
  }
}

// ── Render clips ──────────────────────────────────────────────────

async function fetchTexts(animateNewest = false) {
  const response = await fetch(apiUrl);
  const data     = await response.json();

  // Remove only non-draft elements so draft state is preserved
  Array.from(textContainer.children)
    .filter(el => el.id !== "draftClip")
    .forEach(el => el.remove());

  // Reverse for newest-first display; track original index for deletes
  const items = [...(data || [])].reverse();

  items.forEach((raw, displayIdx) => {
    const originalIndex = data.length - 1 - displayIdx;
    const isNewest = animateNewest && displayIdx === 0;

    // ── FILE CLIP ─────────────────────────────────────────────
    if (raw.startsWith(FILE_PREFIX)) {
      let meta;
      try { meta = JSON.parse(raw.slice(FILE_PREFIX.length)); }
      catch { return; }

      const box = document.createElement("div");
      box.className = "textBox fileBox";

      const icon = fileIcon(meta.mimeType, meta.name);
      box.innerHTML = `
        <div class="fileBox-info">
          <span class="fileBox-icon">${icon}</span>
          <div class="fileBox-details">
            <span class="fileBox-name">${meta.name}</span>
            <span class="fileBox-size">${formatBytes(meta.size)}${meta.encrypted ? " · 🔒 encrypted" : ""}</span>
          </div>
        </div>
        <div class="fileBox-actions">
          <button class="fileBox-btn copy-link-btn">🔗 Copy link</button>
          <button class="fileBox-btn download-btn">⬇ Download</button>
        </div>`;

      // Copy link: encode full meta so the link self-contains everything needed for download
      box.querySelector(".copy-link-btn").addEventListener("click", e => {
        e.stopPropagation();
        const metaB64 = btoa(unescape(encodeURIComponent(JSON.stringify(meta))));
        const link    = `${window.location.href.split("?")[0]}?dl=${encodeURIComponent(metaB64)}`;
        navigator.clipboard.writeText(link).catch(() => {
          const t = document.createElement("textarea");
          t.value = link; document.body.appendChild(t); t.select();
          document.execCommand("copy"); document.body.removeChild(t);
        });
        const btn = e.currentTarget;
        btn.textContent = "✅ Copied!";
        setTimeout(() => btn.textContent = "🔗 Copy link", 1800);
      });

      box.querySelector(".download-btn").addEventListener("click", e => {
        e.stopPropagation();
        downloadFile(meta);
      });

      const del = document.createElement("i");
      del.className = "fa fa-trash";
      del.style.cssText = "position:absolute;top:10px;right:10px;z-index:3;";
      del.addEventListener("click", async e => {
        e.stopPropagation();
        deleteWithAnimation(box, async () => {
          await fetch(apiUrl, {
            method:  "DELETE",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify({ index: originalIndex }),
          });
          fetchTexts();
        });
      });
      box.appendChild(del);
      if (isNewest) {
        box.classList.add("entering");
        setTimeout(() => box.classList.remove("entering"), 400);
      }
      textContainer.appendChild(box);
      return;
    }

    // ── TEXT CLIP (plain or secret) ───────────────────────────
    const isSecret    = raw.startsWith(SECRET_PREFIX);
    const b64         = isSecret ? raw.slice(SECRET_PREFIX.length).replace(/^"|"$/g, "") : null;
    const displayText = isSecret ? null : raw;

    const box = document.createElement("div");
    box.className = "textBox" + (isSecret ? " textBox--locked" : "");

    if (isSecret) {
      box.innerHTML = `
        <div class="lockOverlay">
          <span class="lockIcon">🔒</span>
          <span class="lockHint">Click to copy · Right-click to view</span>
        </div>`;
      box.addEventListener("click",       ()  => tryDecrypt(b64, "copy",   originalIndex));
      box.addEventListener("contextmenu", e   => { e.preventDefault(); tryDecrypt(b64, "expand", originalIndex); });
    } else {
      const content = document.createElement("pre");
      content.innerText = displayText;
      content.className = "content";

      const overlay = document.createElement("div");
      overlay.className = "overlay hidden";
      overlay.textContent = "Copied!";
      overlay.style.cssText = `
        position:absolute;top:0;left:0;width:100%;height:100%;
        display:flex;align-items:center;justify-content:center;
        background:rgba(255,255,255,0.12);font-weight:bold;
        color:#fff;transition:opacity 0.3s ease;z-index:1;border-radius:10px;`;
      box.appendChild(content);
      box.appendChild(overlay);

      box.addEventListener("click", () => {
        navigator.clipboard.writeText(displayText).catch(() => {
          const t = document.createElement("textarea");
          t.value = displayText; document.body.appendChild(t);
          t.select(); document.execCommand("copy"); document.body.removeChild(t);
        });
        content.classList.add("hidden");
        overlay.classList.remove("hidden");
        overlay.style.opacity = "1";
        setTimeout(() => {
          overlay.style.opacity = "0";
          setTimeout(() => { overlay.classList.add("hidden"); content.classList.remove("hidden"); }, 300);
        }, 1500);
      });

      box.addEventListener("contextmenu", e => { e.preventDefault(); openExpand(displayText, originalIndex, box); });
    }

    // Long press (mobile)
    let pressTimer;
    box.addEventListener("touchstart", e => {
      pressTimer = setTimeout(() => {
        e.preventDefault();
        if (isSecret) tryDecrypt(b64, "expand", originalIndex);
        else openExpand(displayText, originalIndex, box);
      }, 500);
    }, { passive: false });
    box.addEventListener("touchend",  () => clearTimeout(pressTimer));
    box.addEventListener("touchmove", () => clearTimeout(pressTimer));

    const deleteButton = document.createElement("i");
    deleteButton.className = "fa fa-trash";
    deleteButton.style.cssText = "position:absolute;top:10px;right:10px;z-index:3;";
    deleteButton.addEventListener("click", async e => {
      e.stopPropagation();
      deleteWithAnimation(box, async () => {
        await fetch(apiUrl, {
          method:  "DELETE",
          headers: { "Content-Type": "application/json" },
          body:    JSON.stringify({ index: originalIndex }),
        });
        fetchTexts();
      });
    });

    box.appendChild(deleteButton);
    if (isNewest) {
      box.classList.add("entering");
      setTimeout(() => box.classList.remove("entering"), 400);
    }
    textContainer.appendChild(box);
  });
}

// ── Expand modal ──────────────────────────────────────────────────

const expandBackdrop = document.createElement("div");
expandBackdrop.id = "expandBackdrop";
const expandModal  = document.createElement("div");
expandModal.id = "expandModal";
const expandClose  = document.createElement("button");
expandClose.id = "expandClose"; expandClose.innerHTML = "✕";
const expandText   = document.createElement("pre");
expandText.id = "expandText";
const expandActions = document.createElement("div");
expandActions.id = "expandActions";
const expandCopy   = document.createElement("button");
expandCopy.id = "expandCopy"; expandCopy.textContent = "Copy";
const expandDelete = document.createElement("button");
expandDelete.id = "expandDelete"; expandDelete.textContent = "Delete";
expandActions.appendChild(expandCopy);
expandActions.appendChild(expandDelete);
expandModal.appendChild(expandClose);
expandModal.appendChild(expandText);
expandModal.appendChild(expandActions);
expandBackdrop.appendChild(expandModal);
document.body.appendChild(expandBackdrop);

// ── Decrypt prompt modal ──────────────────────────────────────────

const decryptBackdrop = document.createElement("div");
decryptBackdrop.id = "decryptBackdrop";
const decryptBox = document.createElement("div");
decryptBox.id = "decryptBox";
decryptBox.innerHTML = `
  <div class="decrypt-title">🔒 Enter encryption key</div>
  <div style="position:relative; margin-top:16px;">
    <input id="decryptKeyInput" type="password" class="input" placeholder=" " style="width:100%;box-sizing:border-box;" />
    <div class="cut" style="width:100px; background:#1a1a2e;"></div>
    <label class="placeholder" for="decryptKeyInput">Encryption key</label>
    <i id="toggleDecryptKey" class="fa fa-eye"
       style="position:absolute;right:10px;top:50%;transform:translateY(-50%);cursor:pointer;color:#aaa;"></i>
  </div>
  <div id="decryptError" style="color:#e74c3c;font-size:13px;margin-top:8px;display:none;">Wrong key — try again</div>
  <div style="display:flex;gap:10px;margin-top:20px;">
    <button id="decryptCancel" class="decrypt-btn cancel">Cancel</button>
    <button id="decryptConfirm" class="decrypt-btn confirm">Unlock</button>
  </div>`;
decryptBackdrop.appendChild(decryptBox);
document.body.appendChild(decryptBackdrop);

const decryptKeyInput  = document.getElementById("decryptKeyInput");
const toggleDecryptKey = document.getElementById("toggleDecryptKey");
const decryptError     = document.getElementById("decryptError");
const decryptCancel    = document.getElementById("decryptCancel");
const decryptConfirm   = document.getElementById("decryptConfirm");

toggleDecryptKey.addEventListener("click", () => {
  const p = decryptKeyInput.type === "password";
  decryptKeyInput.type = p ? "text" : "password";
  toggleDecryptKey.className = p ? "fa fa-eye-slash" : "fa fa-eye";
});

let decryptResolve = null;
function promptDecryptKey() {
  return new Promise(resolve => {
    decryptResolve = resolve;
    decryptKeyInput.value = "";
    decryptError.style.display = "none";
    decryptBackdrop.classList.add("active");
    setTimeout(() => decryptKeyInput.focus(), 50);
  });
}
function closeDecryptPrompt(result) {
  decryptBackdrop.classList.remove("active");
  if (decryptResolve) { decryptResolve(result); decryptResolve = null; }
}
decryptCancel.addEventListener("click",   () => closeDecryptPrompt(null));
decryptBackdrop.addEventListener("click", e => { if (e.target === decryptBackdrop) closeDecryptPrompt(null); });
decryptKeyInput.addEventListener("keydown", e => { if (e.key === "Enter") decryptConfirm.click(); });
decryptConfirm.addEventListener("click",  () => closeDecryptPrompt(decryptKeyInput.value));

async function tryDecrypt(b64, action, index) {
  while (true) {
    const key = await promptDecryptKey();
    if (key === null) return;
    const plain = await decryptText(b64, key);
    if (plain === null) {
      decryptBackdrop.classList.add("active");
      decryptError.style.display = "block";
      continue;
    }
    if (action === "copy") {
      navigator.clipboard.writeText(plain).catch(() => {
        const t = document.createElement("textarea");
        t.value = plain; document.body.appendChild(t);
        t.select(); document.execCommand("copy"); document.body.removeChild(t);
      });
    } else {
      openExpand(plain, index, null, true);
    }
    return;
  }
}

// ── Expand open/close ─────────────────────────────────────────────

function openExpand(text, index, originBox, isDecrypted = false) {
  expandText.textContent     = text;
  expandDelete.dataset.index = index;

  const targetW = Math.min(800, window.innerWidth * 0.85);
  const targetH = window.innerHeight * 0.75;
  const targetL = (window.innerWidth  - targetW) / 2;
  const targetT = (window.innerHeight - targetH) / 2;

  expandModal.style.transition   = "none";
  expandModal.style.left         = targetL + "px";
  expandModal.style.top          = targetT + "px";
  expandModal.style.width        = targetW + "px";
  expandModal.style.height       = targetH + "px";
  expandModal.style.borderRadius = "16px";
  expandModal.style.opacity      = "0.5";

  if (originBox) {
    const rect  = originBox.getBoundingClientRect();
    const scaleX = rect.width  / targetW;
    const scaleY = rect.height / targetH;
    const tx = (rect.left + rect.width  / 2) - (targetL + targetW / 2);
    const ty = (rect.top  + rect.height / 2) - (targetT + targetH / 2);
    expandModal.style.transform = `translate(${tx}px, ${ty}px) scale(${scaleX}, ${scaleY})`;
  } else {
    expandModal.style.transform = "scale(0.92)";
  }

  expandBackdrop.classList.add("active");
  requestAnimationFrame(() => requestAnimationFrame(() => {
    const ease = "cubic-bezier(0.4, 0, 0.2, 1)";
    expandModal.style.transition = `transform 0.38s ${ease}, opacity 0.28s ease, border-radius 0.38s ease`;
    expandModal.style.transform  = "translate(0,0) scale(1)";
    expandModal.style.opacity    = "1";
  }));
}

function closeExpand() {
  const ease = "cubic-bezier(0.4, 0, 0.2, 1)";
  expandModal.style.transition = `transform 0.3s ${ease}, opacity 0.25s ease`;
  expandModal.style.transform  = "scale(0.9)";
  expandModal.style.opacity    = "0";
  setTimeout(() => {
    expandBackdrop.classList.remove("active");
    expandModal.style.transition = "none";
    expandModal.style.transform  = "none";
  }, 310);
}

expandClose.addEventListener("click", closeExpand);
expandBackdrop.addEventListener("click", e => { if (e.target === expandBackdrop) closeExpand(); });

expandCopy.addEventListener("click", () => {
  navigator.clipboard.writeText(expandText.textContent).catch(() => {
    const t = document.createElement("textarea");
    t.value = expandText.textContent;
    document.body.appendChild(t); t.select();
    document.execCommand("copy"); document.body.removeChild(t);
  });
  expandCopy.textContent = "Copied!";
  setTimeout(() => expandCopy.textContent = "Copy", 1800);
});

expandDelete.addEventListener("click", async () => {
  const idx = parseInt(expandDelete.dataset.index);
  await fetch(apiUrl, {
    method:  "DELETE",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ index: idx }),
  });
  closeExpand();
  fetchTexts();
});

// ── Init ──────────────────────────────────────────────────────────

// Handle deep-link download before modals are needed
handleDeepLink();

// Build draft clip and prepend to container
const draftEl = buildDraftClip();
textContainer.prepend(draftEl);
initDraft();

// Load existing clips
fetchTexts();
