const apiUrl = "https://clipboard.guywiththecoolusername.workers.dev/";

const popup = document.getElementById("popup");
const createButton = document.getElementById("createButton");
const closePopup = document.getElementById("closePopup");
const confirmButton = document.getElementById("confirmButton");
const textContainer = document.getElementById("textContainer");
const errorMessage = document.getElementById("errorMessage");
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");

// ── Expand modal elements (injected once) ────────────────────────
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

let expandCurrentIndex = null;

function openExpand(text, index, originBox) {
  expandCurrentIndex = index;
  expandText.textContent = text;
  expandDelete.dataset.index = index;

  const rect = originBox.getBoundingClientRect();

  // Final size — modal is always rendered at this size, we just scale it
  const targetW = Math.min(800, window.innerWidth * 0.85);
  const targetH = window.innerHeight * 0.75;
  const targetL = (window.innerWidth  - targetW) / 2;
  const targetT = (window.innerHeight - targetH) / 2;

  // How much to scale down so it looks like the origin box
  const scaleX = rect.width  / targetW;
  const scaleY = rect.height / targetH;

  // Translate so the scaled modal sits over the origin box
  const originCX = rect.left + rect.width  / 2;
  const originCY = rect.top  + rect.height / 2;
  const modalCX  = targetL   + targetW     / 2;
  const modalCY  = targetT   + targetH     / 2;
  const tx = originCX - modalCX;
  const ty = originCY - modalCY;

  // Position modal at its final size/location, no transition yet
  expandModal.style.transition = "none";
  expandModal.style.left   = targetL + "px";
  expandModal.style.top    = targetT + "px";
  expandModal.style.width  = targetW + "px";
  expandModal.style.height = targetH + "px";
  expandModal.style.borderRadius = "10px";
  expandModal.style.opacity = "0.5";
  expandModal.style.transform = `translate(${tx}px, ${ty}px) scale(${scaleX}, ${scaleY})`;

  expandBackdrop.classList.add("active");

  // Two rAFs — browser paints start state, then we animate to final
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const ease = "cubic-bezier(0.4, 0, 0.2, 1)";
      expandModal.style.transition = `transform 0.38s ${ease}, opacity 0.28s ease, border-radius 0.38s ease`;
      expandModal.style.transform  = "translate(0, 0) scale(1)";
      expandModal.style.borderRadius = "16px";
      expandModal.style.opacity    = "1";
    });
  });
}

function closeExpand() {
  const ease = "cubic-bezier(0.4, 0, 0.2, 1)";
  expandModal.style.transition = `transform 0.3s ${ease}, opacity 0.25s ease, border-radius 0.3s ease`;
  expandModal.style.transform  = "translate(0, 0) scale(0.9)";
  expandModal.style.opacity    = "0";
  expandModal.style.borderRadius = "10px";
  setTimeout(() => {
    expandBackdrop.classList.remove("active");
    // Reset so next open starts clean
    expandModal.style.transition = "none";
    expandModal.style.transform  = "none";
  }, 310);
}

expandClose.addEventListener("click", closeExpand);
expandBackdrop.addEventListener("click", (e) => {
  if (e.target === expandBackdrop) closeExpand();
});

expandCopy.addEventListener("click", () => {
  navigator.clipboard.writeText(expandText.textContent).catch(() => {
    const t = document.createElement("textarea");
    t.value = expandText.textContent;
    document.body.appendChild(t);
    t.select();
    document.execCommand("copy");
    document.body.removeChild(t);
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

// ── Password toggle ───────────────────────────────────────────────
togglePassword.addEventListener("click", () => {
  const isPassword = passwordInput.type === "password";
  passwordInput.type = isPassword ? "text" : "password";
  togglePassword.className = isPassword ? "fa fa-eye-slash" : "fa fa-eye";
});

passwordInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") confirmButton.click();
});

// ── Create popup ──────────────────────────────────────────────────
createButton.addEventListener("click", () => popup.style.display = "flex");
closePopup.addEventListener("click", () => popup.style.display = "none");
popup.addEventListener("click", (e) => {
  if (e.target === popup) popup.style.display = "none";
});

confirmButton.addEventListener("click", async () => {
  const texttoadd = document.getElementById("texttoadd").value.trim();
  const password = document.getElementById("password").value;

  if (!password) {
    errorMessage.classList.remove("hidden");
    return;
  }

  errorMessage.classList.add("hidden");
  popup.style.display = "none";

  await fetch(apiUrl, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, texttoadd })
  });

  fetchTexts();
});

// ── Fetch & render text boxes ─────────────────────────────────────
async function fetchTexts() {
  const response = await fetch(apiUrl);
  const data = await response.json();

  textContainer.innerHTML = "";
  (data || []).forEach((text, index) => {
    const box = document.createElement("div");
    box.className = "textBox";

    const content = document.createElement("pre");
    content.innerText = text;
    content.className = "content";

    const overlay = document.createElement("div");
    overlay.className = "overlay hidden";
    overlay.textContent = "Copied!";
    overlay.style.cssText = `
      position:absolute; top:0; left:0; width:100%; height:100%;
      display:flex; align-items:center; justify-content:center;
      background:rgba(255,255,255,0.15); font-weight:bold;
      color:#fff; transition:opacity 0.3s ease; z-index:1;
      border-radius:10px;
    `;

    const deleteButton = document.createElement("i");
    deleteButton.className = "fa fa-trash";
    deleteButton.style.cssText = "position:absolute; top:10px; right:10px; z-index:2;";

    deleteButton.addEventListener("click", async (e) => {
      e.stopPropagation();
      await fetch(apiUrl, {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ index })
      });
      fetchTexts();
    });

    // Left click → copy with overlay flash
    box.addEventListener("click", () => {
      navigator.clipboard.writeText(text).catch(() => {
        const t = document.createElement("textarea");
        t.value = text; document.body.appendChild(t);
        t.select(); document.execCommand("copy");
        document.body.removeChild(t);
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

    // Right click → expand modal
    box.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      openExpand(text, index, box);
    });

    // Long press for mobile
    let pressTimer;
    box.addEventListener("touchstart", (e) => {
      pressTimer = setTimeout(() => {
        e.preventDefault();
        openExpand(text, index, box);
      }, 500);
    }, { passive: false });
    box.addEventListener("touchend", () => clearTimeout(pressTimer));
    box.addEventListener("touchmove", () => clearTimeout(pressTimer));

    box.appendChild(content);
    box.appendChild(overlay);
    box.appendChild(deleteButton);
    textContainer.appendChild(box);
  });
}

fetchTexts();
