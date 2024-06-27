import { Controller, Get, Query, Res, Req } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express';
import { Session } from 'express-session';

@Controller('auth')
export class AuthController {
    constructor(private readonly authService: AuthService) { }

    /**
 * Handles the login process for Zalo authentication.
 *
 * @param {Request & { session: Session }} req - The request object containing session data.
 * @param {Response} res - The response object to send HTTP responses.
 *
 * @returns {Promise<void>} A promise that resolves when the login process is completed.
 */
    @Get('zalo/login')
    async login(@Req() req: Request & { session: Session }, @Res() res: Response) {
        const state = 'someRandomState'; // Generate a random state if needed
        const codeVerifier = this.authService.createCodeVerifier();
        const codeChallenge = this.authService.createCodeChallenge(codeVerifier);

        // Store codeVerifier in session
        req.session.codeVerifier = codeVerifier;

        const authUrl = this.authService.getAuthorizationUrl(codeChallenge, state);
        res.redirect(authUrl);
    }

    /**
 * Handles the callback from Zalo authentication.
 * Retrieves the code verifier from the session, validates it, and exchanges it for an access token.
 *
 * @param {string} code - The authorization code received from Zalo.
 * @param {string} state - The state parameter received from Zalo.
 * @param {Request & { session: Session }} req - The request object containing session data.
 * @param {Response} res - The response object to send HTTP responses.
 *
 * @returns {Promise<void>} A promise that resolves when the access token is retrieved and sent as a JSON response.
 *
 * @throws Will throw a 400 status code and an error message if the code verifier is not found in the session.
 */
    @Get('zalo/callback')
    async callback(@Query('code') code: string, @Query('state') state: string, @Req() req: Request & { session: Session }, @Res() res: Response) {
        // Retrieve codeVerifier from session
        const codeVerifier = req.session.codeVerifier;

        if (!codeVerifier) {
            return res.status(400).json({ error: 'Code verifier not found in session' });
        }

        const accessTokenResponse = await this.authService.getAccessToken(code, codeVerifier);

        // Clear codeVerifier from session
        req.session.codeVerifier = null;

        res.json(accessTokenResponse);
    }
}