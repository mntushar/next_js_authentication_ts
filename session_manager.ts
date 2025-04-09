import Account from "@/request_handlers/account";
import { decodeJwt } from "jose";
import { AppRouterInstance } from "next/dist/shared/lib/app-router-context.shared-runtime";
import AppInfo from "./app_info";
import Errors from "./error_handler";

class SessionManager {
    responseHandler: Account = new Account();
    private router: AppRouterInstance;

    constructor(useRouter: AppRouterInstance) {
        this.router = useRouter;
    }

    async getToken(): Promise<string> {
        const token = await this.getValidAccessToken();
        return token;
    };

    private async getValidAccessToken(): Promise<string> {
        try {
            let token: string | null = this.getItem(AppInfo.accessTokenName);
            if (!token || token.trim() === "") {
                token = await this.refreshAccessToken();
            }

            const isvalid = this.checkTokenValidation(token);
            if(!isvalid){
                token = await this.refreshAccessToken();
            }

            if(!token || token.trim() === "") throw new Errors('Unauthorize', 401)

            return token;

        } catch (error) {
            console.error(error);
            this.router.push(AppInfo.loginOutUrl);
            return '';
        }
    }

    private checkTokenValidation(token: string): boolean {
        const payload = this.decodeToken(token);
        if (!("exp" in payload) && !payload.exp) return false;
        const expireTime = new Date(payload.exp * 1000);
        const nowDateTime = new Date();
        if((expireTime.getTime() - nowDateTime.getTime()) <= AppInfo.TokenValidationTimeDifference) {
            return false;
        } 
        return true;
    }

    private decodeToken(token: string): any {
        return decodeJwt(token);
    }

    private async refreshAccessToken(): Promise<string> {
        const refreshToken: string | null = this.getItem(AppInfo.refreshTokenName);
        if (!refreshToken || refreshToken.trim() === "") {
            throw new Errors("Refresh token is null");
        }

        const result = await this.responseHandler.refreshToken(refreshToken);
        this.setItem(AppInfo.accessTokenName, result.accessToken);

        return result.accessToken;
    }

    setItem(key: string, data: string): void {
        localStorage.setItem(key, data);
    }

    getItem(key: string): string | null {
        return localStorage.getItem(key);
    }

    clearAll(): void {
        localStorage.clear();
    }
}

export default SessionManager;
