import { decodeJwt, importPKCS8, importSPKI, JWTPayload, jwtVerify, JWTVerifyResult, SignJWT } from "jose";

export interface Claims {
    [key: string]: unknown;
}

class JwtHandler {
    private algorithm = process.env.JWT_ENCODE_ALGORITHM || '';
    private privateKey = process.env.JWT_PRIVATE_KEY || '';
    private publicKey = process.env.JWT_PUBLIC_KEY || '';
    private tokenValidationTime: number;

    constructor(
        privateKey: string,
        publicKey: string,
        tokenValidationTime: string,) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
            this.tokenValidationTime = parseInt(tokenValidationTime || '3600', 10);
    }

    private async generate(payload: Claims): Promise<string> {
        const key = await importPKCS8(this.privateKey, this.algorithm);
        const token = await new SignJWT(payload)
            .setProtectedHeader({ alg: this.algorithm, typ: 'JWT' })
            .sign(key);
        return token;
    }

    public async generateToken(
        claims: Claims,
        aud: string | null = null): Promise<string> {
        if (aud) {
            claims.aud = aud;
        }

        claims.iat = Math.floor(Date.now() / 1000);
        claims.exp = Math.floor((Date.now() + this.tokenValidationTime * 1000) / 1000);

        return await this.generate(claims);
    }

    public async verifyToken(token: string): Promise<JWTVerifyResult<JWTPayload>> {
        const key = await importSPKI(this.publicKey, this.algorithm);
        const payload = await jwtVerify(token, key);
        return payload;
    }

    public decodeToken(token: string): any {
        return decodeJwt(token);
    }
}

export default JwtHandler;


