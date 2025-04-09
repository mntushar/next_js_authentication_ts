import { NextRequest, NextResponse } from "next/server";
import { AuthenticationManager } from "./authentication";
import { match } from "path-to-regexp";

export class AuthenticationMiddleware {
    private protectedRoutes: string[];
    private authenticationManager: AuthenticationManager;
    private request: NextRequest;
    private loginUrl: string;

    constructor(
        request: NextRequest,
        authenticationList: string[],
        loginUrl: string) {
        this.request = request;
        this.protectedRoutes = authenticationList;
        this.loginUrl = loginUrl;
        this.authenticationManager = new AuthenticationManager(
            request,
            process.env.JWT_COOKIE_PRIVATE_KEY ?? '',
            process.env.JWT_COOKIE_PUBLIC_KEY ?? '',
            process.env.JWT_COOKIE_TOKEN_VALIDATION_TIME ?? ''
        );
    }

    async authenticationByCookies(): Promise<NextResponse<unknown>> {
        try {
            const path = this.request.nextUrl.pathname;
            const isProtectedRoute = this.protectedRoutes.some(route => {
                const matcher = match(route, { decode: decodeURIComponent });
                return !!matcher(path);
            });
            if (isProtectedRoute) {
                await this.authenticationManager.authenticationByCookies();
            }

            return NextResponse.next();
        }
        catch (error) {
            console.error('Authentication Error:', error);
            return NextResponse.redirect(new URL(this.loginUrl, this.request.nextUrl))
        }
    }
}