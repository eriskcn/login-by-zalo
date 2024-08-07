import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import * as crypto from 'crypto';
import base64url from 'base64url';

@Injectable()
export class AuthService {
    private appId: string;
    private secretKey: string;
    private callbackUrl: string;

    constructor(private configService: ConfigService) {
        this.appId = this.configService.get<string>('APP_ID');
        this.secretKey = this.configService.get<string>('SECRET_KEY');
        this.callbackUrl = this.configService.get<string>('CALLBACK_URL');
    }



    /**
 * Generates a random code verifier for OAuth 2.0 PKCE flow.
 *
 * @returns {string} The generated code verifier.
 *
 * @remarks
 * The code verifier is a random string, base64url-encoded, used to protect against
 * authorization code interception attacks. It is used in the authorization request
 * and must be sent to the authorization server in the authorization request.
 *
 * The code verifier should be at least 43 characters long and contain a mix of
 * uppercase and lowercase letters, digits, and the characters "-" and "_".
 *
 * The code verifier should be generated using a cryptographically secure random
 * number generator.
 *
 * The code verifier should be stored securely and not exposed to the user.
 *
 * The code verifier should be used only once in the authorization flow.
 *
 */
    createCodeVerifier() {
        const codeVerifier = base64url.encode(crypto.randomBytes(32));
        return codeVerifier;
    }

    /**
 * Creates a code challenge for OAuth 2.0 PKCE flow.
 *
 * @param {string} codeVerifier - The code verifier generated by `createCodeVerifier` method.
 * @returns {string} The generated code challenge.
 *
 * @remarks
 * The code challenge is a hashed version of the code verifier, base64url-encoded,
 * used to protect against authorization code interception attacks. It is used in the
 * authorization request and must be sent to the authorization server in the
 * authorization request.
 *
 * The code challenge is generated by hashing the code verifier using the SHA-256
 * algorithm and then encoding the result using base64url.
 *
 * The code challenge should be at least 43 characters long and contain a mix of
 * uppercase and lowercase letters, digits, and the characters "-" and "_".
 *
 * The code challenge should be generated using a cryptographically secure hash
 * function.
 *
 * The code challenge should be stored securely and not exposed to the user.
 *
 * The code challenge should be used only once in the authorization flow.
 *
 */
    createCodeChallenge(codeVerifier: string) {
        const hash = crypto.createHash('sha256').update(codeVerifier).digest();
        return base64url.encode(hash);
    }

    /**
 * Generates the authorization URL for Zalo OAuth 2.0 PKCE flow.
 *
 * @param {string} codeChallenge - The code challenge generated by `createCodeChallenge` method.
 * @param {string} state - A random string used to protect against CSRF attacks.
 * @returns {string} The generated authorization URL.
 *
 * @remarks
 * The authorization URL is used to initiate the OAuth 2.0 PKCE flow. It includes
 * the necessary parameters such as app_id, redirect_uri, code_challenge, and state.
 *
 * The authorization URL should be opened in a browser to allow the user to
 * authenticate and authorize the application.
 *
 * The authorization URL should be generated using the app_id, redirect_uri,
 * code_challenge, and state provided as parameters.
 *
 * The state parameter should be a random string generated by the application to
 * protect against CSRF attacks. It should be stored securely and verified during
 * the callback.
 *
 */
    getAuthorizationUrl(codeChallenge: string, state: string) {
        return `https://oauth.zaloapp.com/v4/permission?app_id=${this.appId}&redirect_uri=${this.callbackUrl}&code_challenge=${codeChallenge}&state=${state}`;
    }

    /**
 * Retrieves the access token from Zalo OAuth 2.0 PKCE flow.
 *
 * @param {string} code - The authorization code received from the Zalo OAuth 2.0 server.
 * @param {string} codeVerifier - The code verifier used in the authorization request.
 * @returns {Promise<any>} A promise that resolves to the access token data.
 *
 * @remarks
 * This method sends a POST request to the Zalo OAuth 2.0 server to retrieve the access token.
 * It includes the necessary parameters such as code, app_id, grant_type, and code_verifier.
 * The access token data is then returned as the promise resolution.
 *
 * @throws {Error} If the request fails or if the response status code is not 200.
 *
 */
    async getAccessToken(code: string, codeVerifier: string) {
        const url = 'https://oauth.zaloapp.com/v4/access_token';
        const response = await axios.post(url, null, {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'secret_key': this.secretKey,
            },
            params: {
                code: code,
                app_id: this.appId,
                grant_type: 'authorization_code',
                code_verifier: codeVerifier,
            },
        });
        return response.data;
    }

    async getUserInfo(accessToken: string) {
        const url = 'https://graph.zalo.me/v2.0/me';
        const response = await axios.get(url, {
            headers: {
                'access_token': accessToken,
            },
            params: {
                fields: 'id,name,picture',
            },
        });

        return response.data;
    }
}
