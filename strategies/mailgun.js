/*
* Mailgun integration example.
*/
import FormData from 'form-data';
import fetch from 'node-fetch';

// Mailgun REST API endpoint address
const MAILGUN_URL = 'api.mailgun.net'; // or api.mailgun.net for US customers

// REST API for sending email to list of recipients
export async function sendMail({email, otp, from}) {
  // create an email as form data
  const form = new FormData();
  form.append('from', from);
  form.append('to', email);
  form.append('subject', 'One-Time Password');
  form.append('text', `Hi there! Here's your one time password: ${otp}`);
  form.append('html', `Hi there! <br/>Here's your one time password: <b>${otp}</b><br/>Best regards, the X team.`);
  // Mailgun api endpoint
  //  "https://api:" + apikey + "@api.mailgun.net/v3/" + RESTDB_DOMAIN_NAME + "/messages",
  const url = `https://api:${process.env.MAILGUN_API_KEY}@api.mailgun.net/v3/${process.env.MAILGUN_DOMAIN}/messages`;
  // Mailgun credentials must be base64 encoded for Basic authentication
  const credentials = Buffer.from(`api:${process.env.MAILGUN_API_KEY}`).toString('base64');
  console.debug('Mailgun url', url)
  console.debug('Mailgun credentials', credentials)
  // POST REST API with the email form data
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      "Authorization": `Basic ${credentials}`
    },
    body: form
  });
  // handle response errors or OK data
  if (resp.status <= 201) {
    // Success, return Mailgun response to the REST API client
    const output = await resp.json();
    console.log("Success", output);
    // insert log to the NoSQL database
    const db = await Datastore.open();    
    const doc = await db.insertOne('maillog', {email, output});  
    return output;
  } else {
    console.error(resp.status, resp.statusText);
    // pass the Mailgun error to the REST API client
    return {error: resp.statusText};
  }    
}