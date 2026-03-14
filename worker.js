export default {
  async fetch(request, env) {
    const { DB, EDIT_PASSWORD, GDRIVE_CLIENT_ID, GDRIVE_CLIENT_SECRET, GDRIVE_REFRESH_TOKEN } = env;
    const method = request.method;
    const url    = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, PUT, DELETE, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };
    if (method === "OPTIONS") return new Response(null, { headers: corsHeaders });

    // ── Google Drive helpers ──────────────────────────────────────────
    async function getAccessToken() {
      const res = await fetch("https://oauth2.googleapis.com/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          client_id:     GDRIVE_CLIENT_ID,
          client_secret: GDRIVE_CLIENT_SECRET,
          refresh_token: GDRIVE_REFRESH_TOKEN,
          grant_type:    "refresh_token",
        }),
      });
      const data = await res.json();
      if (!data.access_token) throw new Error("Failed to get access token: " + JSON.stringify(data));
      return data.access_token;
    }

    async function setPublic(driveId, accessToken) {
      await fetch(`https://www.googleapis.com/drive/v3/files/${driveId}/permissions`, {
        method:  "POST",
        headers: { "Authorization": `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ role: "reader", type: "anyone" }),
      });
    }

    async function deleteFromDrive(driveId, accessToken) {
      await fetch(`https://www.googleapis.com/drive/v3/files/${driveId}`, {
        method: "DELETE", headers: { "Authorization": `Bearer ${accessToken}` },
      });
    }

    // ── GET / — all entries ───────────────────────────────────────────
    if (method === "GET" && url.pathname === "/") {
      const data = (await DB.get("texts")) || "[]";
      return new Response(data, { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    // ── GET /file?id= — proxy file from Drive ─────────────────────────
    if (method === "GET" && url.pathname === "/file") {
      const driveId = url.searchParams.get("id");
      if (!driveId) return new Response("Missing id", { status: 400, headers: corsHeaders });
      const accessToken = await getAccessToken();
      const driveRes    = await fetch(
        `https://www.googleapis.com/drive/v3/files/${driveId}?alt=media`,
        { headers: { "Authorization": `Bearer ${accessToken}` } }
      );
      const blob = await driveRes.arrayBuffer();
      return new Response(blob, {
        headers: { ...corsHeaders, "Content-Type": driveRes.headers.get("Content-Type") || "application/octet-stream" },
      });
    }

    // ── PUT / — add text entry ────────────────────────────────────────
    if (method === "PUT") {
      const body = await request.json();
      const { password, texttoadd } = body || {};
      if (password !== EDIT_PASSWORD) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      let existing = JSON.parse((await DB.get("texts")) || "[]");
      if (!Array.isArray(existing)) existing = [];
      existing.push(texttoadd);
      await DB.put("texts", JSON.stringify(existing));
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ── GET /token — return short-lived access token to browser ─────
    // Browser uploads directly to Drive, bypassing Worker size limits
    if (method === "GET" && url.pathname === "/token") {
      const pw = url.searchParams.get("password");
      if (pw !== EDIT_PASSWORD) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
      try {
        const accessToken = await getAccessToken();
        return new Response(JSON.stringify({ accessToken }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }
    }

    // ── POST /register-file — save metadata after browser uploads to Drive
    if (method === "POST" && url.pathname === "/register-file") {
      let body;
      try { body = await request.json(); }
      catch { return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: corsHeaders }); }

      const { password, driveId, name, size, mimeType, encrypted, autoKey } = body || {};
      if (password !== EDIT_PASSWORD) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403, headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // Set file public after browser uploaded it
      try {
        const accessToken = await getAccessToken();
        await setPublic(driveId, accessToken);
      } catch (_) {}

      const entry = "FILE_ENTRY=" + JSON.stringify({
        driveId, name, size, mimeType, encrypted, autoKey: autoKey || null,
      });
      let existing = JSON.parse((await DB.get("texts")) || "[]");
      if (!Array.isArray(existing)) existing = [];
      existing.push(entry);
      await DB.put("texts", JSON.stringify(existing));

      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // ── DELETE / — remove entry + Drive file ─────────────────────────
    if (method === "DELETE") {
      const body = await request.json();
      const { index } = body || {};
      let existing = JSON.parse((await DB.get("texts")) || "[]");
      if (!Array.isArray(existing)) existing = [];
      const entry = existing[index];
      if (typeof entry === "string" && entry.startsWith("FILE_ENTRY=")) {
        try {
          const meta = JSON.parse(entry.slice("FILE_ENTRY=".length));
          if (meta.driveId) {
            const accessToken = await getAccessToken();
            await deleteFromDrive(meta.driveId, accessToken);
          }
        } catch (_) {}
      }
      existing.splice(index, 1);
      await DB.put("texts", JSON.stringify(existing));
      return new Response(JSON.stringify({ success: true }), {
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
  },
};
