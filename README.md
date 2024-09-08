# codehooks-auth
Open source client authentication for Codehooks.io REST API backends. 

codehooks-auth is a library that provides easy-to-use authentication functionality for Codehooks.io REST API backends. It supports various authentication methods, including password-based authentication and OAuth (e.g., Google).

Codehooks.io also has support for leading JWT based authentication providers like Auth0.com and Clerk.com. The codehooks-auth library aims to provide a simple and easy to use alternative for those who prefer not to use these providers or for those who need more control over the authentication process.

## Features

- Easy integration with Codehooks.io apps
- Support for password-based authentication
- OAuth support (e.g., Google)
- JWT-based access and refresh tokens
- Customizable success and failure redirects
- Static asset serving for auth-related pages
- Configurable caching for static assets

## Installation
To install codehooks-auth, use npm:

```bash
npm install codehooks-auth
```

The install script will create a folder `/auth/assets` with the login/signup pages and the javascript to drive them. Feel free to modify these to your liking.

## Usage

Here's a complete example of how to use codehooks-auth in your Codehooks.io app:

```javascript
import {app} from 'codehooks-js'
import { initAuth } from 'codehooks-auth'

// setup your crudl api for /api/person
app.crudlify({person: {}}, {prefix: "/api"})

const settings = {
  JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET, // coho set-env JWT_ACCESS_TOKEN_SECRET 'xxx' --encrypted
  JWT_REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET, // coho set-env JWT_REFRESH_TOKEN_SECRET 'xxx' --encrypted
  redirectSuccessUrl: '/dashboard.html', // where to redirect after successful login
  baseAPIRoutes: '/api', // protected routes
  google: {
    CLIENT_ID: process.env.CLIENT_ID, // TODO: get this from google cloud console
    CLIENT_SECRET: process.env.CLIENT_SECRET, // TODO: get this from google cloud console
    REDIRECT_URI: 'https://your-app.codehooks.io/auth/oauthcallback/google' // TODO: change this to your app url, add the callback url you set in google cloud console
  }
}
// setup auth settings
initAuth(app, settings)

// serve /auth/assets html forms javascripts etc
app.static({ route: '/auth', directory: '/auth/assets', default: 'login.html' })

// bind to serverless runtime
export default app.init()
```

## Client web app

Client web apps can use `codehooks-auth` to login and signup. Add a route to the auth lock screen to the client web app `/auth/assets/login.html`.

The screenshot below shows the lock screen.
![lock-screen](./examples/images/auth-lock-screen.png)

If your app redirectSuccessUrl is `/dashboard.html` then after login you will be redirected to this with an JWT accesstoken parameter in the url `https://yourapp.codehooks.io/dashboard.html#access_token=xxx`.

Use the access_token to call your Codehooks.io API.

```javascript
const accessToken = new URLSearchParams(window.location.hash.substr(1)).get('access_token');
fetch('/api/person', {
  headers: {
    'Authorization': `Bearer ${accessToken}`
  }
});
```

## Configuration

The `settings` object allows you to configure various aspects of the authentication process:

### userCollection
- Type: `string`
- Description: Name of the database collection for storing user information.
- Default: `'users'`
- Example: `'myusers'`

### saltRounds
- Type: `number`
- Description: Number of salt rounds for password hashing.
- Default: `10`

### JWT_ACCESS_TOKEN_SECRET
- Type: `string`
- Description: Secret key used for signing JWT access tokens.
- Default: `'keep_locked_away'`
- Example: `process.env.JWT_ACCESS_TOKEN_SECRET`

### JWT_ACCESS_TOKEN_SECRET_EXPIRE
- Type: `string`
- Description: Expiration time for JWT access tokens.
- Default: `'10m'`
- Example: `'1h'`

### JWT_REFRESH_TOKEN_SECRET
- Type: `string`
- Description: Secret key used for signing JWT refresh tokens.
- Default: `'bury_in_the_sand'`
- Example: `process.env.JWT_REFRESH_TOKEN_SECRET`

### JWT_REFRESH_TOKEN_SECRET_EXPIRE
- Type: `string`
- Description: Expiration time for JWT refresh tokens.
- Default: `'8h'`
- Example: `'24h'`

### redirectSuccessUrl
- Type: `string`
- Description: URL to redirect after successful authentication.
- Default: `'/'`
- Example: `'/dashboard.html'`

### redirectFailUrl
- Type: `string`
- Description: URL to redirect after failed authentication.
- Default: `'/'`
- Example: `'/auth/login.html#error=true'`

### useCookie
- Type: `boolean`
- Description: Whether to use cookies for storing tokens.
- Default: `true`

### baseAPIRoutes
- Type: `string`
- Description: Base path for API routes protected by auth.
- Default: `'/'`
- Example: `'/api'`

### google
- Type: `object`
- Description: Configuration for Google OAuth.
- Properties:
  - `CLIENT_ID`: Google OAuth client ID.
  - `CLIENT_SECRET`: Google OAuth client secret.
  - `REDIRECT_URI`: Redirect URI for Google OAuth callback.
- Example:
  ```javascript
  {
    CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    REDIRECT_URI: 'https://{YOUR_APP_URL}/auth/oauthcallback/google'
  }
  ```
### github
In progress ...

## Authentication Callback

The `initAuth` function takes a callback as its third argument. This callback is called after successful authentication and allows you to customize the response:

```javascript
initAuth(app, settings, (req, res, payload) => {  
 console.log('User logged in', payload.user)
  if (payload.method === 'PASSWORD') {
    res.json({access_token: payload.access_token, redirectURL: payload.redirectURL})
  } else {
    res.redirect(302, `/dashboard.html#access_token=${payload.access_token}`)
  }  
})
```

## Deployment

The easiest way to deploy your app with codehooks-auth is to use the `codehooks-cli` tool. This will deploy your code with the auth bindings and setup the environment variables for you.

```bash
codehooks deploy
```


## Security Note

Always keep your JWT secrets and OAuth client secrets secure. Use environment variables for sensitive information in production.


