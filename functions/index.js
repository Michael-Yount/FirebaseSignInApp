/**
 * Copyright 2017 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for t`he specific language governing permissions and
 * limitations under the License.
 */
'use strict';



import { https, logger } from 'firebase-functions/v1';

// CORS Express middleware to enable CORS Requests.
const cors = require('cors')({origin: true});

// Firebase Setup
import { initializeApp } from 'firebase-admin/app';
import { initializeApp, credential as _credential, auth } from 'firebase-admin';
// @ts-ignore
import serviceAccount from './service-account.json';
initializeApp({
  credential: _credential.cert(serviceAccount),
  databaseURL: `https://${process.env.GCLOUD_PROJECT}.firebaseio.com`,
});

import fetch from 'node-fetch';
import { FIREBASE_CONFIG_VAR } from 'firebase-admin/lib/app/lifecycle';

/* 

*/
export const auth = https.onRequest((req, res) => {
  const handleError = (username, error) => {
    logger.error({ User: username }, error);
    res.sendStatus(500);
    return;
  };

  const handleResponse = (username, status, body) => {
    logger.log(
      { User: username },
      {
        Response: {
          Status: status,
          Body: body,
        },
      }
    );
    if (body) {
      return res.status(200).json(body);
    }
    return res.sendStatus(status);
  };

  let username = '';
  try {
    return cors(req, res, async () => {
      // Authentication requests are POSTed, other requests are forbidden
      if (req.method !== 'POST') {
        return handleResponse(username, 403);
      }
      username = req.body.username;
      if (!username) {
        return handleResponse(username, 400);
      }
      const password = req.body.password;
      if (!password) {
        return handleResponse(username, 400);
      }

      // TODO(DEVELOPER): In production you'll need to update the `authenticate` function so that it authenticates with your own credentials system.
      const valid = await authenticate(username, password)
      if (!valid) {
        return handleResponse(username, 401); // Invalid username/password
      }

      // On success return the Firebase Custom Auth Token.
      const firebaseToken = await auth().createCustomToken(username);
      return handleResponse(username, 200, { token: firebaseToken });
    });
  } catch (error) {
    return handleError(username, error);
  }
});

/**
 * Authenticate the provided credentials.
 * TODO(DEVELOPER): In production you'll need to update this function so that it authenticates with your own credentials system.
 * @returns {Promise<boolean>} success or failure.
 */
async function authenticate(username, password) {
  // For the purpose of this example use httpbin (https://httpbin.org) and send a basic authentication request.
  // (Only a password of `Testing123` will succeed)
  const authEndpoint = `https://httpbin.org/basic-auth/${username}/Testing123`;
  const response = await fetch(authEndpoint, {
    headers: {
      Authorization: 'Basic ' + Buffer.from(username + ":" + password).toString('base64')
    }
  });

  if (response.status === 200) {
    return true;
  } else if (response.status === 401) {
    return false
  } else {
    throw new Error(`invalid response returned from ${authEndpoint} status code ${response.status}`)
  }
}
