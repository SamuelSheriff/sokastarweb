# Sokastar Payment Server — Setup Guide (Safaricom Daraja C2B)
===========================================================

This server receives M-Pesa payments via **Safaricom Daraja Standard C2B** (Customer-to-Business) URL Registration and stores confirmed payments in Supabase, so the Sokastar Admin Dashboard shows them in real time. Requires **Node.js 18+**.

With Daraja C2B, the customer pays **manually** from their phone (M-Pesa → Lipa na M-Pesa → Buy Goods → enter Till Number + Amount → PIN). Safaricom then POSTs the payment details to your registered Confirmation URL.

## 1. Install Dependencies
```bash
npm install
```

## 2. Safaricom Daraja Account Setup (one-time)
1. Register at **[developer.safaricom.co.ke](https://developer.safaricom.co.ke/)**.
2. Create a new app and select **C2B** (Customer-to-Business) products.
3. Copy your **Consumer Key** and **Consumer Secret**.
4. Note your **Shortcode / Till Number** (e.g. `6884892`).
5. For production: complete the **Go Live** application to get production keys.

## 3. Environment Variables
```env
PORT=3000
ADMIN_API_KEY=your_secure_admin_api_key

# Supabase
SUPABASE_URL=your_supabase_project_url
SUPABASE_KEY=your_supabase_service_role_key

# Safaricom Daraja
DARAJA_CONSUMER_KEY=your_consumer_key
DARAJA_CONSUMER_SECRET=your_consumer_secret
MPESA_SHORTCODE=6884892
DARAJA_ENV=sandbox          # "sandbox" or "production"
```

## 4. Deploy (Render / Railway)
1. Push to GitHub, then create a **New Web Service** on your hosting provider.
2. **Build Command**: `npm install` · **Start Command**: `node server.js`
3. Add the env vars from Section 3.
4. Copy your public URL (e.g. `https://sokastar.onrender.com`).

## 5. Register URLs with Safaricom
After deploying, you must register your Validation + Confirmation URLs with Safaricom **once** (or whenever your server URL changes).

### Option A: Via the Dashboard
1. Open `/admin` and log in.
2. Go to **Daraja API** page.
3. Click the ⚡ icon **5 times** to unlock Developer Settings.
4. Enter your **Server URL** and **Admin API Key**, then **Save Config**.
5. Click **🔗 Register URLs with Safaricom**.

### Option B: Via cURL
```bash
curl -X POST https://YOUR_DOMAIN/api/register-urls \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: your_admin_api_key" \
  -d '{"callbackBase": "https://YOUR_DOMAIN"}'
```

This will call Safaricom's `/mpesa/c2b/v2/registerurl` API and register:
- **Validation URL**: `https://YOUR_DOMAIN/webhook/c2b/validate`
- **Confirmation URL**: `https://YOUR_DOMAIN/webhook/c2b/confirm`

## 6. How the Payment Flow Works
1. **Customer pays manually** — on their phone: M-Pesa → Lipa na M-Pesa → Buy Goods → Till `6884892` → Amount → PIN.
2. **Validation** — Safaricom POSTs to `/webhook/c2b/validate`. Server responds `{ ResultCode: 0 }` to accept.
3. **Confirmation** — Safaricom POSTs to `/webhook/c2b/confirm` with full transaction details (TransID, TransAmount, MSISDN, FirstName, LastName, etc.).
4. **Server saves** — deduplicates by TransID, infers the package from the amount, saves to Supabase `transactions` table.
5. **Dashboard** — polls `GET /api/transactions` and displays each payment in real time.

## Package Amount Mapping
| Package            | Expected (KES) | Allowed Range |
|--------------------|----------------|---------------|
| Daily              | 250            | 240 – 260     |
| Super MultiBet     | 50             | 45 – 55       |
| MidWeek Jackpot    | 40             | 35 – 45       |
| Mega Jackpot       | 80             | 75 – 85       |
| Half Time Full Time| 20             | 15 – 25       |

## Testing Locally
```bash
node server.js
curl http://localhost:3000/health

# Simulate a Safaricom C2B confirmation callback (no real payment needed):
curl -X POST http://localhost:3000/webhook/c2b/confirm \
  -H "Content-Type: application/json" \
  -d '{
    "TransactionType": "Pay Bill",
    "TransID": "TESTABC123",
    "TransTime": "20260609180000",
    "TransAmount": "250",
    "BusinessShortCode": "6884892",
    "BillRefNumber": "Sokastar",
    "MSISDN": "254712345678",
    "FirstName": "John",
    "MiddleName": "",
    "LastName": "Doe"
  }'
```
Then check the dashboard. (Delete test rows so they aren't mistaken for real payments.)

For **sandbox testing**, use [Safaricom's Daraja Sandbox Simulator](https://developer.safaricom.co.ke/) to trigger C2B payments. For **local development**, use [ngrok](https://ngrok.com/) to create a public HTTPS tunnel to your localhost.

## Endpoints
- `POST /webhook/c2b/validate`    — Safaricom validation callback (accepts all by default)
- `POST /webhook/c2b/confirm`     — Safaricom confirmation callback (saves payment to DB)
- `POST /api/register-urls`       — Register Validation + Confirmation URLs with Safaricom (admin)
- `GET  /api/transactions`        — Dashboard polling (X-Api-Key)
- `POST /api/transactions`        — Manual add from dashboard (X-Api-Key)
- `DELETE /api/transactions/:id`  — Delete transaction (X-Api-Key)
- `GET  /api/debug`               — Last POSTs received, to verify callbacks land (X-Api-Key)
- `GET  /health`                  — Uptime ping

## Project Structure
- `server.js` — Express server: Daraja C2B validation/confirmation, OAuth token, dashboard API
- `index.html` — Landing page with manual M-Pesa payment instructions
- `dashboard.html` — Admin dashboard with Daraja URL registration
