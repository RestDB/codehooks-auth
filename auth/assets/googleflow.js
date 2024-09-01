/*
 * Create form to request access token from Google's OAuth 2.0 server.
 */
const CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'
const REDIRECT_URI = 'YOUR_REDIRECT_URI'
const SCOPE = 'https://www.googleapis.com/auth/userinfo.email' // https://developers.google.com/identity/protocols/oauth2/scopes

const hash = window.location.hash.substring(1);
const params = new URLSearchParams(hash);
const accessToken = params.get("access_token");
console.log('Got access token?', accessToken);

function oauthSignIn() {
    // Google's OAuth 2.0 endpoint for requesting an access token
    var oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
  
    // Create <form> element to submit parameters to OAuth 2.0 endpoint.
    var form = document.createElement('form');
    form.setAttribute('method', 'GET'); // Send as a GET request.
    form.setAttribute('action', oauth2Endpoint);
  
    // Parameters to pass to OAuth 2.0 endpoint.
    var params = {'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'token',
        'scope': SCOPE, 
        'include_granted_scopes': 'true',
        'state': 'pass-through value'};
  
    // Add form parameters as hidden input values.
    for (var p in params) {
      var input = document.createElement('input');
      input.setAttribute('type', 'hidden');
      input.setAttribute('name', p);
      input.setAttribute('value', params[p]);
      form.appendChild(input);
    }
  
    // Add form to page and submit it to open the OAuth 2.0 endpoint.
    document.body.appendChild(form);
    form.submit();
  }

// Execute functions when the page loads
document.addEventListener('DOMContentLoaded', function() {
    console.log("Google: DOM fully loaded and parsed");
    // Attach event listener to the SSO button
    document.querySelector('.sso-button').addEventListener('click', oauthSignIn);
});