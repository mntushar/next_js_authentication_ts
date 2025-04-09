import Cryptography from "./cryptography";
import Errors from "./error_handler";
import JwtHandler, { Claims } from "./jwt_token_handler";

class UserManager {
    private crypto: Cryptography;
    private jwtHandler: JwtHandler;
    private stringSeparator = ';';
    private refreshTokenExpairName = 'expires'

    constructor() {
        this.crypto = new Cryptography();
        this.jwtHandler = new JwtHandler(
            process.env.JWT_PRIVATE_KEY ?? '',
            process.env.JWT_PUBLIC_KEY ?? '',
            process.env.JWT_TOKEN_VALIDATION_TIME ?? ''
        );
    }

    async create(password: string, repeatPassword: string): Promise<string> {
        if (password !== repeatPassword) throw new Errors('Password is not same.');

        const hashPassword = await this.crypto.hashPassword(password);
        return hashPassword;
    }

    async singIn(password: string, hashPassword: string): Promise<boolean> {
        return await this.crypto.verifyPassword(hashPassword, password);
    }

    async getToken(
        claims: Claims): Promise<string> {
        return await this.jwtHandler.generateToken(claims);
    }

    private parseStringToObject(input: string): Record<string, any> {
        const parts = input.split(this.stringSeparator).filter(part => part.trim() !== '');
        const obj: Record<string, any> = {};

        parts.forEach(part => {
            const separatorIndex = part.indexOf(':');
            if (separatorIndex !== -1) {
                const key = part.substring(0, separatorIndex).trim();
                const value = part.substring(separatorIndex + 1).trim();
                obj[key] = value || null;
            }
        });

        return obj;
    }

    getRefreshToken(id: string, email: string): string {
        const expires = new Date();
        expires.setUTCDate(expires.getDate() + parseInt(process.env.REFRESH_TOKEN_VALIDATION_DAY as string, 10));
        const identityText = `id:${id}${this.stringSeparator}email:${email}${this.stringSeparator}${this.refreshTokenExpairName}:${expires.toUTCString()}${this.stringSeparator}`;
        return this.crypto.aseEncrypt(identityText);
    }

    validateRefreshToken(refreshToken: string): Record<string, any> {
        const identityText = this.crypto.aseDecrypt(refreshToken);
        const data = this.parseStringToObject(identityText);
        if (!(this.refreshTokenExpairName in data)) throw new Errors('Token has expired', 401);

        const expireTime = new Date(data[this.refreshTokenExpairName]);
        const nowDateTime = new Date();
        if (nowDateTime >= expireTime) throw new Errors('Token has expired', 401);

        return data;
    }

    async getCookiesToken(claims: Claims): Promise<string> {
        const jwtHandler = new JwtHandler(
            process.env.JWT_COOKIE_PRIVATE_KEY ?? '',
            process.env.JWT_COOKIE_PUBLIC_KEY ?? '',
            process.env.JWT_COOKIE_TOKEN_VALIDATION_TIME ?? '');
        return await jwtHandler.generateToken(claims);
    }
}

export default UserManager;