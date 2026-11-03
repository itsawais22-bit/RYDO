'use strict';
const config = require('./config');

/**
 * Plug your SMS gateway in here (e.g. Twilio, or a Pakistani bulk-SMS provider).
 * Called with the phone number and the message text.
 */
async function sendSms(phone, message) {
  if (config.exposeDevOtp) {
    console.log(`[SMS -> ${phone}] ${message}`);
    return;
  }
  // TODO: call your SMS provider here, e.g.
  // await fetch('https://provider.example/send', { method: 'POST', body: JSON.stringify({ to: phone, text: message }) });
  throw new Error('No SMS provider configured in src/sms.js');
}
module.exports = { sendSms };
