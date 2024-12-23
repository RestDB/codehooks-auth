/*
* Mailgun integration example.
*/
import FormData from 'form-data';
import fetch from 'node-fetch';
import {Datastore} from 'codehooks-js';
// Mailgun REST API endpoint address
const MAILGUN_URL = 'api.mailgun.net'; // or api.mailgun.net for US customers

// REST API for sending email to list of recipients
export async function sendMail(settings,{to, subject, text, html}) {
  return new Promise(async (resolve, reject) => {
    try {
      console.debug('sendMail', to, subject, text, html)
      // create an email as form data
      const form = new FormData();
      form.append('from', settings.MAILGUN_FROM_EMAIL || 'noreply@example.com');
      form.append('to', to);
      form.append('subject', subject);
      form.append('text', text);
      form.append('html', html);
      // Mailgun api endpoint
      //  "https://api:" + apikey + "@api.mailgun.net/v3/" + RESTDB_DOMAIN_NAME + "/messages",
      const url = `https://api:${settings.MAILGUN_APIKEY}@api.mailgun.net/v3/${settings.MAILGUN_DOMAIN}/messages`;
      // Mailgun credentials must be base64 encoded for Basic authentication
      const credentials = Buffer.from(`api:${settings.MAILGUN_APIKEY}`).toString('base64');
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
        await db.insertOne('maillog', {to, subject, text, html, output, timestamp: new Date().toISOString()});  
        resolve(output);
      } else {
        console.error('Mailgun error', resp.status, resp.statusText);
        // pass the Mailgun error to the REST API client
        reject({error: resp.statusText});
      }    
    } catch (error) {
      console.error('Mailgun error:', error);
      reject({error: error.message});
    }
  });
}