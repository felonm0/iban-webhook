import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();
app.use(bodyParser.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

// ENV
const PORT = process.env.PORT || 3000;
const BOT_TOKEN = process.env.BOT_TOKEN;
const CHAT_ID = process.env.CHAT_ID;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "replace_me";

// Telegram helper
async function sendTelegram(text) {
  if (!BOT_TOKEN || !CHAT_ID) return;
  await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ chat_id: CHAT_ID, text })
  });
}

// Basit HMAC doğrulama (bankaya göre HEADER adı/methodu değişebilir)
function validSignature(rawBody, headerSignature) {
  if (!headerSignature || !WEBHOOK_SECRET) return false;
  const [method, sig] = headerSignature.split("=");
  const h = crypto.createHmac("sha256", WEBHOOK_SECRET);
  h.update(rawBody);
  const expected = h.digest("hex");
  try {
    return method === "sha256" &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));
  } catch (_) { return false; }
}

// Sağlık kontrolü
app.get("/health", (req,res)=>res.send("ok"));

// Banka/FAST webhook giriş noktası
app.post("/webhook", async (req, res) => {
  try {
    const sig = req.headers["x-signature"] || req.headers["x-hub-signature"];
    if (!validSignature(req.rawBody || "", sig)) {
      return res.status(401).send("invalid signature");
    }

    const p = req.body;
    // Farklı bankalar farklı isimler kullanır; olabildiğince esnek tuttuk
    const event = p.event || p.type || "incoming_payment";
    const txId = p.tx_id || p.transactionId || p.id || "unknown";
    const iban = p.destination_iban || p.iban || p.account || "unknown";
    const amount = p.amount || p.value || 0;
    const currency = p.currency || "TRY";
    const reference = p.reference || p.description || "";

    // Şimdilik direkt Telegram'a fırlatıyoruz (DB’siz hızlı doğrulama)
    await sendTelegram(
      `💸 Gelen Ödeme\n` +
      `• Tutar: ${amount} ${currency}\n` +
      `• IBAN: ${iban}\n` +
      (reference ? `• Ref: ${reference}\n` : ``) +
      `• TX: ${txId}`
    );

    return res.status(200).send("ok");
  } catch (e) {
    console.error("webhook error", e);
    return res.status(500).send("server error");
  }
});

app.listen(PORT, ()=> {
  console.log("FAST webhook listener running on", PORT);
});
