import { cookies } from "next/headers";
import AppInfo from "./app_info";
import Errors from "./error_handler";
import JwtHandler from "./jwt_token_handler";

export class AuthenticationManager {
    private jwtHandler: JwtHandler;
    private request: Request;

    constructor(request: Request);
    constructor(request: Request, privateKey: string, publicKey: string, tokenValidationTime: string);

    constructor(
        request: Request,
        privateKey?: string,
        publicKey?: string,
        tokenValidationTime?: string) {
        if (privateKey && publicKey && tokenValidationTime) {
            this.jwtHandler = new JwtHandler(
                privateKey,
                publicKey,
                tokenValidationTime);
        }
        else {
            this.jwtHandler = new JwtHandler(
                process.env.JWT_PRIVATE_KEY ?? '',
                process.env.JWT_PUBLIC_KEY ?? '',
                process.env.JWT_TOKEN_VALIDATION_TIME ?? '')
        }
        this.request = request;
    }

    async getTokenFromCookies(): Promise<string> {
        const token = (await cookies()).get(AppInfo.authenticationCookie)?.value
        if (!token) throw new Errors('Identity cookies is missing', 401);
        return token;
    }

    getToekn(): string {
        const authHeader = this.request.headers.get('authorization');
        if (!authHeader) throw new Errors('Authorization header is missing', 401);

        const parts = authHeader.split(' ');
        if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
            throw new Errors('Authorization header must be in the form "Bearer <token>"', 401);
        }
        const token = parts[1];

        return token
    }

    async authenticate() {
        try {
            const token = this.getToekn();
            await this.jwtHandler.verifyToken(token);
        }
        catch (error) {
            throw new Errors(error as Error, 401, 'Unauthorized request');
        }
    }

    async authenticationByCookies() {
        try {
            const token = await this.getTokenFromCookies();
            await this.jwtHandler.verifyToken(token);
        }
        catch (error) {
            throw new Errors(error as Error, 401, 'Unauthorized request');
        }
    }

    permissionForRoles(roles: string) {
        const accessRoles = this.getClaim('roles');
        if (!accessRoles || accessRoles.length === 0) throw new Errors('Bad request', 400);

        const userRoles = roles.split(',');
        if (!userRoles || userRoles.length === 0) throw new Errors('Bad request', 400);

        let isPermited = false;
        for (const role of userRoles) {
            if (accessRoles.includes(role)) {
                isPermited = true;
                break;
            }
        }

        if (!isPermited) throw new Errors('Unauthorized request', 401);
    }

    permissionForClaim(claim: [string, any]) {
        const [claimName, claimValue] = claim;
        if (!claimName) throw new Errors('Bad request', 400);

        const accessClaim = this.getClaim(claimName);
        if (!accessClaim || accessClaim.length === 0) throw new Errors('Bad request', 400);

        // If claimValue is array
        if (Array.isArray(claimValue)) {
            if (!claimValue.some(v => v === accessClaim)) throw new Errors('Unauthorized request', 401);
            return;
        }

        if (accessClaim !== claimValue) throw new Errors('Unauthorized request', 401);
    }

    getClaims(): Record<string, any> {
        const token = this.getToekn();
        return this.jwtHandler.decodeToken(token) as object;
    }

    getClaim(name: string): any | null {
        const payload = this.getClaims();
        if (name in payload) {
            return payload[name];
        }
        return null;
    }
}

const Authorization = async (
    request: Request,
    roles?: string | null,
    claim?: [string, any] | null) => {
    const authenManager = new AuthenticationManager(request);
    await authenManager.authenticate();

    if (roles)
        authenManager.permissionForRoles(roles);

    if (claim)
        authenManager.permissionForClaim(claim);
}

export const AuthorizationByCookies = async (request: Request) => {
    const authenManager = new AuthenticationManager(
        request,
        process.env.JWT_COOKIE_PRIVATE_KEY ?? '',
        process.env.JWT_COOKIE_PUBLIC_KEY ?? '',
        process.env.JWT_COOKIE_TOKEN_VALIDATION_TIME ?? '');
    await authenManager.authenticationByCookies();
}

export default Authorization;