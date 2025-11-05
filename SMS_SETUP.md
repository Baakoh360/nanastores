# SMS Setup Guide for NANA BAAKO STORES

## Current Status

✅ **SMS functionality is already implemented!** The system sends SMS notifications at every stage of the order process.

### Messages Currently Sent:

1. **Order Received** (when customer creates order)
   - Message: "NANA BAAKO STORES: Order received! Items: [items]. Total: GH₵[amount]. Please complete payment."

2. **Payment Confirmed** (when payment is successful)
   - Message: "NANA BAAKO STORES: Payment confirmed! Order for [items] is being processed."

3. **Processing** (when admin changes status to "Processing")
   - Message: "NANA BAAKO STORES: Your order for [items] is now being processed. We're preparing your items for shipment."

4. **Shipped** (when admin changes status to "Shipped")
   - Message: "NANA BAAKO STORES: Great news! Your order for [items] has been shipped. It's on its way to [location]. You'll receive it soon!"

5. **Delivered** (when admin changes status to "Delivered")
   - Message: "NANA BAAKO STORES: Your order for [items] has been delivered to [location]. Thank you for shopping with NANA BAAKO STORES!"

6. **Cancelled** (when admin cancels order)
   - Message: "NANA BAAKO STORES: Your order for [items] has been cancelled. If you have questions, please contact us."

---

## Current Mode: Mock/Test Mode

Right now, SMS messages are being **logged to the console** (not actually sent) because Twilio is not configured. This is perfect for testing - you can see what messages would be sent without actually sending them.

**To see SMS messages in action:**
- Check your server console/terminal when orders are created or status changes
- You'll see: `SMS (mock): +233XXXXXXXXX Your message here`

---

## How to Set Up Real SMS with Twilio

### Step 1: Create a Twilio Account

1. Go to [https://www.twilio.com](https://www.twilio.com)
2. Sign up for a free account (you get $15 credit to test)
3. Verify your phone number

### Step 2: Get Your Twilio Credentials

1. Log in to your Twilio Console
2. Go to **Account** → **API Keys & Tokens**
3. You'll need:
   - **Account SID** (starts with `AC...`)
   - **Auth Token** (click "View" to see it)
   - **Phone Number** (get a number from Twilio: Phone Numbers → Buy a Number)

### Step 3: Configure Your .env File

Add these lines to your `.env` file:

```env
# SMS Configuration (Twilio)
SMS_PROVIDER=twilio
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_auth_token_here
TWILIO_FROM=+1234567890
```

**Important Notes:**
- `TWILIO_FROM` should be your Twilio phone number (format: `+1234567890` with country code)
- For Ghana, use format: `+233XXXXXXXXX` (include country code)
- Make sure your Twilio number has SMS capabilities enabled

### Step 4: Restart Your Server

After adding the Twilio credentials to `.env`, restart your server:

```bash
npm start
# or
npm run dev
```

### Step 5: Test It

1. Create a test order on your website
2. Check if SMS is sent to the customer's phone
3. Update order status in admin panel and check for SMS

---

## Phone Number Format

The system expects phone numbers in international format:
- ✅ Correct: `+233XXXXXXXXX` (Ghana with country code)
- ❌ Wrong: `0XXXXXXXXX` or `XXXXXXXXX`

**The frontend should already handle this**, but make sure customers enter their numbers correctly.

---

## Troubleshooting

### SMS Not Sending?

1. **Check your .env file:**
   - Make sure all Twilio credentials are correct
   - Check for typos or extra spaces

2. **Check Twilio Console:**
   - Go to Twilio Console → Monitor → Logs
   - See if there are any error messages

3. **Check Server Console:**
   - Look for `SMS send error:` messages
   - Common errors:
     - Invalid phone number format
     - Insufficient Twilio balance
     - Number not verified (for trial accounts)

4. **Test Mode:**
   - If you're on Twilio trial account, you can only send SMS to verified numbers
   - Upgrade to a paid account to send to any number

### Still in Mock Mode?

If you see `SMS (mock):` in your console, it means:
- `SMS_PROVIDER` is not set to `twilio`, OR
- Twilio credentials are missing

Double-check your `.env` file!

---

## Cost Information

- **Twilio Pricing:** Typically $0.0075 - $0.01 per SMS (varies by country)
- **Ghana SMS:** Check Twilio pricing page for current rates
- **Free Trial:** $15 credit = ~1500 SMS messages to test

---

## Alternative SMS Providers

If you want to use a different SMS provider (like Africa's Talking, SMS Gateway, etc.), you can modify the `sendSMS` function in `server.js` to use their API.

---

## Need Help?

Check the server console logs - they will show you exactly what's happening with SMS messages!

