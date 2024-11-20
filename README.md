# codehooks-auth
Open source Client app authentication for Codehooks.io REST API backends. 

codehooks-auth is a library that provides easy-to-use authentication functionality for Codehooks.io REST API backends. It supports various authentication methods, including password-based authentication and OAuth (Google and Github).

Codehooks.io supports leading JWT based authentication providers like [Auth0.com](https://auth0.com) and [Clerk.com](https://clerk.com). 

However, the codehooks-auth library aims to provide a simple and easy to use alternative for those who prefer not to use these providers or for those who need more control over the authentication process.

## Features

- Easy integration with Codehooks.io apps
- Support for one time password authentication
- OAuth support (Google and Github)
- JWT-based access and refresh tokens
- Customizable success and failure redirects
- Static asset serving for auth-related pages
- Configurable caching for static assets

Check out the [live demo example](https://trustworthy-summit-721c.codehooks.io/index.html).

## Installation
To install codehooks-auth, use npm:

```bash
npm install codehooks-auth codehooks-js
```

The install script will create a folder `/auth/assets` with the login/signup pages and the javascript to drive them. Feel free to modify these to your liking.

After the install, your project should have a `auth` folder structure like this:

```
auth
└── assets
    ├── forgot.html
    ├── login.html
    ├── passwordflow.js
    └── signup.html
```

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
    REDIRECT_URI: 'https://{YOUR_APP_URL}.codehooks.io/auth/oauthcallback/google' // TODO: change this to your app url, add the callback url you set in google cloud console
  },
  github: {
    CLIENT_ID: process.env.GITHUB_CLIENT_ID, // TODO: get this from github
    CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET, // TODO: get this from github
    REDIRECT_URI: 'https://{YOUR_APP_URL}.codehooks.io/auth/oauthcallback/github' // TODO: change this to your app url, add the callback url you set in github
  },
  email: {
    MAILGUN_APIKEY: process.env.MAILGUN_APIKEY, // TODO: get this from mailgun
    MAILGUN_DOMAIN: process.env.MAILGUN_DOMAIN, // TODO: get this from mailgun
    MAILGUN_FROM_EMAIL: process.env.MAILGUN_FROM_EMAIL, // TODO: set this to your email
    MAILGUN_FROM_NAME: process.env.MAILGUN_FROM_NAME // TODO: set this to your name
  }
}
// setup auth settings
initAuth(app, settings)

// serve /auth/assets html forms javascripts etc
app.static({ route: '/auth', directory: '/auth/assets', default: 'login.html' })

// bind to serverless runtime
export default app.init()
```

## Deployment of the server side code

The easiest way to deploy your app with codehooks-auth is to use the `codehooks-cli` tool. This will deploy your code with the auth bindings and setup the environment variables for you.


```bash
coho deploy
```

## Client web app

Client web apps can use the codehooks-auth package to login and signup. To authenticate your users, direct them to the client web app route `https://{YOUR-APP}.codehooks.io/auth/login.html`.

The screenshot below shows the lock screen presented to the users.

![lock-screen](./examples/images/auth-lock-screen.png)

The screenshot below shows the one time password screen presented to the users.

![lock-screen](./examples/images/otp-screen.png)

If your app `redirectSuccessUrl` is `https://example.com/dashboard.html` then after login you will be redirected to this URL. And, a httpOnly cookie will be set with the access_token and a refresh_token. This makes it very simple to call your Codehooks.io API.

Call your Codehooks.io API with the implicit access_token in the url hash or the httpOnly cookie.

```javascript
fetch('/api/person', {
  credentials: "include",
  headers: {
    'Content-Type': 'application/json'
  }
});
```

_ToDo: Provide a complete client side JavaScript that handles access token, and refresh token when the access token expires._

## Manage your users

You can manage your users with the codehooks-cli tool or the web ui. 

The easiest way to get started is to add a user with the Studio app as shown in the screenshot below.

![add-user](./examples/images/users.png)

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
- Default: `'15m'`
- Example: `'1h'`

### JWT_REFRESH_TOKEN_SECRET
- Type: `string`
- Description: Secret key used for signing JWT refresh tokens.
- Default: `'bury_in_the_sand'`
- Example: `process.env.JWT_REFRESH_TOKEN_SECRET`

### JWT_REFRESH_TOKEN_SECRET_EXPIRE
- Type: `string`
- Description: Expiration time for JWT refresh tokens.
- Default: `'8d'`
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
    REDIRECT_URI: 'https://{YOUR_APP_URL}.codehooks.io/auth/oauthcallback/google'
  }
  ```
### github
- Type: `object`
- Description: Configuration for GitHub OAuth.
- Properties:
  - `CLIENT_ID`: GitHub OAuth client ID.
  - `CLIENT_SECRET`: GitHub OAuth client secret.
  - `REDIRECT_URI`: Redirect URI for GitHub OAuth callback.
- Example:
  ```javascript
  {
    CLIENT_ID: process.env.GITHUB_CLIENT_ID,
    CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET,
    REDIRECT_URI: 'https://{YOUR_APP_URL}.codehooks.io/auth/oauthcallback/github'
  }
  ```

### email
- Type: `object`
- Description: Configuration for email sending. 
- Properties:
  - `MAILGUN_APIKEY`: Mailgun API key.
  - `MAILGUN_DOMAIN`: Mailgun domain.
  - `MAILGUN_FROM_EMAIL`: Email address to send from.
  - `MAILGUN_FROM_NAME`: Name to send from. 
- Example:
  ```javascript
  {
    MAILGUN_APIKEY: process.env.MAILGUN_APIKEY,
    MAILGUN_DOMAIN: process.env.MAILGUN_DOMAIN,
    MAILGUN_FROM_EMAIL: 'jane@example.com',
    MAILGUN_FROM_NAME: 'Jane Doe'
  }
  ```

## Optional: Overriding the flow with an authentication callback

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

## Refresh Token

The refresh token is used to get a new access token when the current access token expires. The refresh token is stored in a httpOnly cookie.

Call the `/auth/refresh` endpoint with the refresh token in the httpOnly cookie to get a new access token.

```javascript
const response = await fetch('https://{YOUR_APP_URL}.codehooks.io/auth/refreshtoken', {
    method: 'POST',
    credentials: "include",
    headers: { 
        'Content-Type': 'application/json' 
    }
});
if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
}
const result = await response.json()
console.log('new access token', result.access_token);
```


## Security Note

Always keep your JWT secrets and OAuth client secrets secure. Use environment variables for sensitive information in production.


