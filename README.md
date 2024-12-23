# codehooks-auth
Open source client app authentication for Codehooks.io REST API backends. 

**codehooks-auth** is a library that provides easy-to-use authentication functionality for Codehooks.io REST API backends. It supports various authentication methods, including one time password authentication and OAuth (Google and Github).

The **codehooks-auth** library aims to provide a simple and easy to use alternative for those who prefer not to use these providers or for those who need more control over the authentication process.

>Note: Codehooks.io supports leading JWT based authentication providers like [Auth0.com](https://auth0.com) and [Clerk.com](https://clerk.com). 


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

The install script will create a folder in your project `/auth/assets` with the client side assets and JavaScript used by the lock screen.

```
auth
└── assets
    ├── favicon.ico
    ├── otp.js
    ├── signin.js
    └── styles.css
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
  emailProvider: 'mailgun',
  emailSettings: {
    mailgun: {
      MAILGUN_APIKEY: process.env.MAILGUN_APIKEY, // TODO: get this from mailgun
      MAILGUN_DOMAIN: process.env.MAILGUN_DOMAIN, // TODO: get this from mailgun
      MAILGUN_FROM_EMAIL: process.env.MAILGUN_FROM_EMAIL, // TODO: set this to your email
      MAILGUN_FROM_NAME: process.env.MAILGUN_FROM_NAME // TODO: set this to your name
    }
  }
}
// setup auth settings
initAuth(app, settings)

// bind to serverless runtime
export default app.init(()=>{
  console.log('Look Mummy, I have my own authenticated app!')
})
```

## Deployment of the server side code

The easiest way to deploy your app with codehooks-auth is to use the `codehooks-cli` tool. This will deploy your code with the auth bindings and setup the environment variables for you.


```bash
coho deploy
```

## Client web app

Client web apps can use the codehooks-auth package to login and signup. To authenticate your users, direct them to the client web app route `https://{YOUR-APP}.codehooks.io/auth/login`.

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

### Core Settings
- Type: `AuthSettings`
- Default configuration:
```javascript
{
    userCollection: 'users',
    saltRounds: 10,
    JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET,
    JWT_ACCESS_TOKEN_SECRET_EXPIRE: '15m',
    JWT_REFRESH_TOKEN_SECRET: process.env.JWT_REFRESH_TOKEN_SECRET,
    JWT_REFRESH_TOKEN_SECRET_EXPIRE: '8d',
    redirectSuccessUrl: '/',
    redirectFailUrl: '/',
    useCookie: true,
    baseAPIRoutes: '/myapi',
    emailProvider: 'none',
    labels: {
        signinTitle: 'Sign in',
        signupTitle: 'Sign up',
        otpTitle: 'OTP'
    }
}
```

### Email Configuration
The email configuration has been updated to support multiple providers. Currently supports:
- Mailgun
- Postmark (coming soon)
- SendGrid (coming soon)

Example configuration:
```javascript
{
    emailProvider: 'mailgun', // 'mailgun' | 'postmark' | 'sendgrid' | 'none'
    emailSettings: {
        mailgun: {
            MAILGUN_APIKEY: process.env.MAILGUN_APIKEY,
            MAILGUN_DOMAIN: process.env.MAILGUN_DOMAIN,
            MAILGUN_FROM_EMAIL: process.env.MAILGUN_FROM_EMAIL,
            MAILGUN_FROM_NAME: process.env.MAILGUN_FROM_NAME
        }
        // Additional provider configs will go here
    }
}
```

### UI Customization
You can customize the authentication UI labels:
```javascript
{
    labels: {
        signinTitle: 'Custom Sign In',
        signupTitle: 'Custom Sign Up',
        otpTitle: 'Enter Code'
    }
}
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


