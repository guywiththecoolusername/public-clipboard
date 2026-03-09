const apiUrl = "https://clipboard.guywiththecoolusername.workers.dev/";
const SECRET_PREFIX = 'PASSWORD_PROTECTED_DATA=';

// ── WebCrypto helpers ─────────────────────────────────────────────

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
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(plaintext)
  );
  // Pack: [16 salt][12 iv][ciphertext] → base64
  const combined = new Uint8Array(16 + 12 + cipherBuf.byteLength);
  combined.set(salt, 0);
  combined.set(iv,   16);
  combined.set(new Uint8Array(cipherBuf), 28);
  return btoa(String.fromCharCode(...combined));
}

async function decryptText(b64, password) {
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const salt   = bytes.slice(0,  16);
  const iv     = bytes.slice(16, 28);
  const cipher = bytes.slice(28);
  const key    = await deriveKey(password, salt);
  try {
    const plainBuf = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      cipher
    );
    return new TextDecoder().decode(plainBuf);
  } catch {
    return null; // wrong password
  }
}

// ── DOM refs ──────────────────────────────────────────────────────
const popup          = document.getElementById("popup");
const createButton   = document.getElementById("createButton");
const closePopup     = document.getElementById("closePopup");
const confirmButton  = document.getElementById("confirmButton");
const textContainer  = document.getElementById("textContainer");
const errorMessage   = document.getElementById("errorMessage");
const passwordInput  = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");
const secretCheckbox      = document.getElementById("secretCheckbox");

const secretKeyInput      = document.getElementById("secretKey");
const toggleSecretKey     = document.getElementById("toggleSecretKey");

// ── Secret checkbox — enable/disable the field ───────────────────
secretCheckbox.addEventListener("change", () => {
  secretKeyInput.disabled = !secretCheckbox.checked;
  if (!secretCheckbox.checked) secretKeyInput.value = "";
});

// ── Eye toggles ───────────────────────────────────────────────────
togglePassword.addEventListener("click", () => {
  const isPass = passwordInput.type === "password";
  passwordInput.type = isPass ? "text" : "password";
  togglePassword.className = isPass ? "fa fa-eye-slash" : "fa fa-eye";
});
toggleSecretKey.addEventListener("click", () => {
  const isPass = secretKeyInput.type === "password";
  secretKeyInput.type = isPass ? "text" : "password";
  toggleSecretKey.className = isPass ? "fa fa-eye-slash" : "fa fa-eye";
});

passwordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") confirmButton.click();
});
secretKeyInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") confirmButton.click();
});

// ── Create popup open/close ───────────────────────────────────────
createButton.addEventListener("click", () => {
  popup.style.display = "flex";
  secretCheckbox.checked = false;
  secretKeyInput.disabled = true;
  secretKeyInput.value = "";
});
closePopup.addEventListener("click",  () => popup.style.display = "none");
popup.addEventListener("click", (e)  => { if (e.target === popup) popup.style.display = "none"; });

// ── Submit ────────────────────────────────────────────────────────
confirmButton.addEventListener("click", async () => {
  const rawText  = document.getElementById("texttoadd").value.trim();
  const password = passwordInput.value;
  const isSecret = secretCheckbox.checked;
  const secretKey = secretKeyInput.value;

  if (!password) { errorMessage.classList.remove("hidden"); return; }
  if (isSecret && !secretKey) {
    errorMessage.textContent = "Enter an encryption key";
    errorMessage.classList.remove("hidden");
    return;
  }
  errorMessage.classList.add("hidden");
  errorMessage.textContent = "Incorrect password";

  let texttoadd = rawText;
  if (isSecret) {
    const encrypted = await encryptText(rawText, secretKey);
    texttoadd = SECRET_PREFIX + '"' + encrypted + '"';
  }

  popup.style.display = "none";
  await fetch(apiUrl, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, texttoadd })
  });
  fetchTexts();
});

// ── Expand modal ──────────────────────────────────────────────────
const expandBackdrop = document.createElement("div");
expandBackdrop.id = "expandBackdrop";

const expandModal = document.createElement("div");
expandModal.id = "expandModal";

const expandClose = document.createElement("button");
expandClose.id = "expandClose";
expandClose.innerHTML = "✕";

const expandText = document.createElement("pre");
expandText.id = "expandText";

const expandActions = document.createElement("div");
expandActions.id = "expandActions";

const expandCopy = document.createElement("button");
expandCopy.id = "expandCopy";
expandCopy.textContent = "Copy";

const expandDelete = document.createElement("button");
expandDelete.id = "expandDelete";
expandDelete.textContent = "Delete";

expandActions.appendChild(expandCopy);
expandActions.appendChild(expandDelete);
expandModal.appendChild(expandClose);
expandModal.appendChild(expandText);
expandModal.appendChild(expandActions);
expandBackdrop.appendChild(expandModal);
document.body.appendChild(expandBackdrop);

// ── Password prompt modal (for decryption) ────────────────────────
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
  </div>
`;
decryptBackdrop.appendChild(decryptBox);
document.body.appendChild(decryptBackdrop);

const decryptKeyInput  = document.getElementById("decryptKeyInput");
const toggleDecryptKey = document.getElementById("toggleDecryptKey");
const decryptError     = document.getElementById("decryptError");
const decryptCancel    = document.getElementById("decryptCancel");
const decryptConfirm   = document.getElementById("decryptConfirm");

toggleDecryptKey.addEventListener("click", () => {
  const isPass = decryptKeyInput.type === "password";
  decryptKeyInput.type = isPass ? "text" : "password";
  toggleDecryptKey.className = isPass ? "fa fa-eye-slash" : "fa fa-eye";
});

let decryptResolve = null;

function promptDecryptKey() {
  return new Promise((resolve) => {
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
decryptCancel.addEventListener("click",  () => closeDecryptPrompt(null));
decryptBackdrop.addEventListener("click", (e) => { if (e.target === decryptBackdrop) closeDecryptPrompt(null); });
decryptKeyInput.addEventListener("keydown", (e) => { if (e.key === "Enter") decryptConfirm.click(); });
decryptConfirm.addEventListener("click", () => closeDecryptPrompt(decryptKeyInput.value));

async function tryDecrypt(b64, action) {
  // action = "copy" | "expand"
  while (true) {
    const key = await promptDecryptKey();
    if (key === null) return; // cancelled
    const plain = await decryptText(b64, key);
    if (plain === null) {
      // show error and loop
      decryptBackdrop.classList.add("active");
      decryptError.style.display = "block";
      continue;
    }
    if (action === "copy") {
      navigator.clipboard.writeText(plain).catch(() => {
        const t = document.createElement("textarea");
        t.value = plain; document.body.appendChild(t);
        t.select(); document.execCommand("copy");
        document.body.removeChild(t);
      });
    } else {
      openExpand(plain, null, null, true);
    }
    return;
  }
}

// ── Expand open/close ─────────────────────────────────────────────
function openExpand(text, index, originBox, isDecrypted = false) {
  expandText.textContent = text;
  expandDelete.dataset.index = index;


  const targetW = Math.min(800, window.innerWidth * 0.85);
  const targetH = window.innerHeight * 0.75;
  const targetL = (window.innerWidth  - targetW) / 2;
  const targetT = (window.innerHeight - targetH) / 2;

  expandModal.style.transition = "none";
  expandModal.style.left   = targetL + "px";
  expandModal.style.top    = targetT + "px";
  expandModal.style.width  = targetW + "px";
  expandModal.style.height = targetH + "px";
  expandModal.style.borderRadius = "16px";
  expandModal.style.opacity = "0.5";

  if (originBox) {
    const rect = originBox.getBoundingClientRect();
    const scaleX = rect.width  / targetW;
    const scaleY = rect.height / targetH;
    const tx = (rect.left + rect.width  / 2) - (targetL + targetW / 2);
    const ty = (rect.top  + rect.height / 2) - (targetT + targetH / 2);
    expandModal.style.transform = `translate(${tx}px, ${ty}px) scale(${scaleX}, ${scaleY})`;
  } else {
    expandModal.style.transform = "scale(0.92)";
  }

  expandBackdrop.classList.add("active");

  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const ease = "cubic-bezier(0.4, 0, 0.2, 1)";
      expandModal.style.transition = `transform 0.38s ${ease}, opacity 0.28s ease, border-radius 0.38s ease`;
      expandModal.style.transform  = "translate(0,0) scale(1)";
      expandModal.style.opacity    = "1";
    });
  });
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
expandBackdrop.addEventListener("click", (e) => { if (e.target === expandBackdrop) closeExpand(); });

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
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ index: idx })
  });
  closeExpand();
  fetchTexts();
});

// ── Render boxes ──────────────────────────────────────────────────
async function fetchTexts() {
  const response = await fetch(apiUrl);
  const data = await response.json();
  textContainer.innerHTML = "";

  (data || []).forEach((raw, index) => {
    const isSecret = raw.startsWith(SECRET_PREFIX);
    const b64 = isSecret
      ? raw.slice(SECRET_PREFIX.length).replace(/^"|"$/g, "")
      : null;
    const displayText = isSecret ? null : raw;

    const box = document.createElement("div");
    box.className = "textBox" + (isSecret ? " textBox--locked" : "");

    if (isSecret) {
      // Locked appearance
      box.innerHTML = `
        <div class="lockOverlay">
          <span class="lockIcon">🔒</span>
          <span class="lockHint">Click to copy · Right-click to view</span>
        </div>
      `;
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
        color:#fff;transition:opacity 0.3s ease;z-index:1;border-radius:10px;
      `;
      box.appendChild(content);
      box.appendChild(overlay);

      // Left click → copy
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
          setTimeout(() => {
            overlay.classList.add("hidden");
            content.classList.remove("hidden");
          }, 300);
        }, 1500);
      });

      // Right click → expand
      box.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        openExpand(displayText, index, box);
      });
    }

    if (isSecret) {
      // Left click → decrypt & copy
      box.addEventListener("click", () => tryDecrypt(b64, "copy"));
      // Right click → decrypt & expand
      box.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        tryDecrypt(b64, "expand");
      });
    }

    // Long press for mobile (both normal and secret)
    let pressTimer;
    box.addEventListener("touchstart", (e) => {
      pressTimer = setTimeout(() => {
        e.preventDefault();
        if (isSecret) tryDecrypt(b64, "expand");
        else openExpand(displayText, index, box);
      }, 500);
    }, { passive: false });
    box.addEventListener("touchend",  () => clearTimeout(pressTimer));
    box.addEventListener("touchmove", () => clearTimeout(pressTimer));

    // Delete button (always present)
    const deleteButton = document.createElement("i");
    deleteButton.className = "fa fa-trash";
    deleteButton.style.cssText = "position:absolute;top:10px;right:10px;z-index:3;";
    deleteButton.addEventListener("click", async (e) => {
      e.stopPropagation();
      await fetch(apiUrl, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ index })
      });
      fetchTexts();
    });

    box.appendChild(deleteButton);
    textContainer.appendChild(box);
  });
}

fetchTexts();
