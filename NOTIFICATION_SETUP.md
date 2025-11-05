# Notification Setup Guide - NANA BAAKO STORES

## 🎉 Great News!

**You can now send notifications to customers WITHOUT Twilio!** The system supports multiple notification channels:

1. ✅ **Email** (FREE - Easiest to set up!)
2. ✅ **WhatsApp** (Popular in Ghana!)
3. ✅ **SMS** (via Twilio - optional)

The system automatically tries to send via Email first (if configured), then WhatsApp, then SMS. This means customers will receive notifications even if you don't have Twilio!

---

## 📧 Option 1: Email Notifications (FREE & RECOMMENDED)

### Setup with Gmail (FREE)

1. **Enable 2-Step Verification** on your Gmail account
   - Go to: https://myaccount.google.com/security
   - Enable "2-Step Verification"

2. **Generate App Password**
   - Go to: https://myaccount.google.com/apppasswords
   - Select "Mail" and "Other (Custom name)"
   - Enter "Nana Baako Stores" and click "Generate"
   - Copy the 16-character password (looks like: `abcd efgh ijkl mnop`)

3. **Add to .env file:**
   ```env
   EMAIL_PROVIDER=gmail
   GMAIL_USER=your-email@gmail.com
   GMAIL_APP_PASSWORD=abcdefghijklmnop
   ```

4. **Install packages:**
   ```bash
   npm install
   ```

5. **Restart your server** - Done! ✅

### Setup with SendGrid (FREE tier: 100 emails/day)

1. **Sign up at** https://sendgrid.com (FREE account)

2. **Get API Key:**
   - Go to Settings → API Keys
   - Create API Key
   - Copy the key

3. **Add to .env file:**
   ```env
   EMAIL_PROVIDER=sendgrid
   SENDGRID_API_KEY=SG.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   SENDGRID_FROM_EMAIL=noreply@nanabaakostores.com
   ```

4. **Install packages:**
   ```bash
   npm install
   ```

5. **Restart your server** - Done! ✅

---

## 📱 Option 2: WhatsApp Notifications (Popular in Ghana!)

### Setup with Twilio WhatsApp (if you have Twilio)

If you already have Twilio set up for SMS, you can use the same account for WhatsApp!

1. **Add to .env file:**
   ```env
   WHATSAPP_PROVIDER=twilio
   TWILIO_WHATSAPP_FROM=whatsapp:+12176247611
   ```
   (Use the same `TWILIO_ACCOUNT_SID` and `TWILIO_AUTH_TOKEN` as SMS)

2. **Restart your server** - Done! ✅

### Setup with Green API (FREE for testing)

1. **Sign up at** https://green-api.com (FREE account)

2. **Get credentials from dashboard**

3. **Add to .env file:**
   ```env
   WHATSAPP_PROVIDER=green-api
   GREEN_API_URL_INSTANCE=https://api.green-api.com/waInstance123456789
   GREEN_API_TOKEN_INSTANCE=your_token_here
   ```

4. **Restart your server** - Done! ✅

---

## 📱 Option 3: SMS (Twilio - Optional)

If you want SMS, keep your Twilio setup. But Email and WhatsApp work great too!

---

## 🎯 How It Works

The system sends notifications via **ALL configured channels** automatically:

1. **Order Received** → Email + WhatsApp + SMS (if configured)
2. **Payment Confirmed** → Email + WhatsApp + SMS
3. **Processing** → Email + WhatsApp + SMS
4. **Shipped** → Email + WhatsApp + SMS
5. **Delivered** → Email + WhatsApp + SMS
6. **Cancelled** → Email + WhatsApp + SMS

**Example:**
- If you configure Email → Customers get emails ✅
- If you configure WhatsApp → Customers get WhatsApp messages ✅
- If you configure both → Customers get both! ✅

---

## 🚀 Quick Start (Recommended)

**Just set up Email with Gmail - it's FREE and works immediately!**

1. Add to `.env`:
   ```env
   EMAIL_PROVIDER=gmail
   GMAIL_USER=your-email@gmail.com
   GMAIL_APP_PASSWORD=your-app-password
   ```

2. Install packages:
   ```bash
   npm install
   ```

3. Restart server:
   ```bash
   npm start
   ```

4. Test it - Make a purchase and check your email! ✅

---

## 📝 Full .env Example

```env
# Email (FREE - Recommended!)
EMAIL_PROVIDER=gmail
GMAIL_USER=your-email@gmail.com
GMAIL_APP_PASSWORD=abcdefghijklmnop

# WhatsApp (Optional)
WHATSAPP_PROVIDER=twilio
TWILIO_WHATSAPP_FROM=whatsapp:+12176247611

# SMS (Optional - only if you want SMS)
SMS_PROVIDER=twilio
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_FROM=+12176247611
```

---

## ✅ Benefits

1. **Email is FREE** - No costs, unlimited emails (with Gmail)
2. **WhatsApp is Popular** - Most people in Ghana use WhatsApp!
3. **Multiple Channels** - Customers get notifications via their preferred method
4. **No Twilio Needed** - Email works without any paid services!

---

## 🧪 Testing

Test notifications by making a purchase. Check:
- Your email inbox (if Email configured)
- Your WhatsApp (if WhatsApp configured)
- Your phone SMS (if SMS configured)

You can also test via the API:
```bash
curl -X POST http://localhost:3000/api/test/sms \
  -H "Content-Type: application/json" \
  -d '{"phone":"+233XXXXXXXXX"}'
```

---

## ❓ Troubleshooting

### Email not sending?
- Check Gmail App Password is correct (16 characters, no spaces)
- Make sure 2-Step Verification is enabled
- Check spam folder
- Check server logs for errors

### WhatsApp not sending?
- Verify phone number format: `+233XXXXXXXXX`
- Check Twilio/Green API credentials
- Check server logs for errors

### Nothing sending?
- Check `.env` file has correct values
- Restart server after changing `.env`
- Check server logs for errors

---

## 💡 Recommendation

**Start with Email (Gmail)** - It's FREE, reliable, and works immediately! Then add WhatsApp if you want.

No need for Twilio unless you specifically want SMS! 🎉

