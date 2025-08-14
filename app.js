const apiUrl = "https://jsonblob.com/api/jsonBlob/1405571704889204736"; // Replace with your JSONBlob URL

const popup = document.getElementById("popup");
const createButton = document.getElementById("createButton");
const closePopup = document.getElementById("closePopup");
const confirmButton = document.getElementById("confirmButton");
const textContainer = document.getElementById("textContainer");
const errorMessage = document.getElementById("errorMessage");
// Toggle password visibility
const passwordInput = document.getElementById("password");
const togglePassword = document.getElementById("togglePassword");



togglePassword.addEventListener("click", () => {
  const isPassword = passwordInput.type === "password";
  passwordInput.type = isPassword ? "text" : "password";
  togglePassword.className = isPassword ? "fa fa-eye-slash" : "fa fa-eye";
});

createButton.addEventListener("click", () => popup.style.display = "flex");
closePopup.addEventListener("click", () => popup.style.display = "none");

popup.addEventListener("click", (e) => {
  if (e.target === popup) popup.style.display = "none";
});

confirmButton.addEventListener("click", async () => {
  const texttoadd = document.getElementById("texttoadd").value.trim();
  const password = document.getElementById("password").value;

  if (password !== "3.14") {
    errorMessage.classList.remove("hidden");
    return;
  }

  errorMessage.classList.add("hidden");
  popup.style.display = "none";

  // Fetch current data
  let existingData = await fetch(apiUrl).then((res) => res.json());
  
  // Ensure it's an array
  if (!Array.isArray(existingData)) {
    existingData = [];
  }

  // Append new text
  const updatedData = [...existingData, texttoadd];

  // Save back to JSONBlob
  await fetch(apiUrl, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updatedData),
  });

  fetchTexts();
});


async function fetchTexts() {
  const response = await fetch(apiUrl);
  const data = await response.json();

  textContainer.innerHTML = "";
  (data || []).forEach((text, index) => {
    const box = document.createElement("div");
    box.className = "textBox";
    box.style.position = "relative";

    const content = document.createElement("pre");
    content.innerText = text;
    content.className = "content";

    const overlay = document.createElement("div");
    overlay.className = "overlay hidden";
    overlay.textContent = "Text copied to clipboard";
    overlay.style.position = "absolute";
    overlay.style.top = "0";
    overlay.style.left = "0";
    overlay.style.width = "100%";
    overlay.style.height = "100%";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.backgroundColor = "rgba(255, 255, 255, 0.9)";
    overlay.style.fontWeight = "bold";
    overlay.style.transition = "opacity 0.3s ease";
    overlay.style.zIndex = "1";

    const deleteButton = document.createElement("i");
    deleteButton.className = "fa fa-trash o";
    deleteButton.style.position = "absolute";
    deleteButton.style.top = "5px";
    deleteButton.style.right = "5px";
    deleteButton.style.zIndex = "2";
    deleteButton.addEventListener("click", async (e) => {
      e.stopPropagation();
      const updatedData = [...data];
      updatedData.splice(index, 1);

      await fetch(apiUrl, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updatedData),
      });

      fetchTexts();
    });

    box.addEventListener("click", () => {
      const tempInput = document.createElement("textarea");
      tempInput.value = text;
      document.body.appendChild(tempInput);
      tempInput.select();
      document.execCommand("copy");
      document.body.removeChild(tempInput);

      content.classList.add("hidden");
      overlay.classList.remove("hidden");
      overlay.style.opacity = "1";

      setTimeout(() => {
        overlay.style.opacity = "0";
        setTimeout(() => {
          overlay.classList.add("hidden");
          content.classList.remove("hidden");
        }, 300);
      }, 2000);
    });

    box.appendChild(content);
    box.appendChild(overlay);
    box.appendChild(deleteButton);
    textContainer.appendChild(box);
  });
}

fetchTexts();
