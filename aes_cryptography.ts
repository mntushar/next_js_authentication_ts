class AesCryptography {
    private async generateKey(password: string): Promise<CryptoKey> {
        // Convert password to raw bytes
        const enc = new TextEncoder();
        const passwordBytes = enc.encode(password);

        // Hash password with SHA-256 to get a 256-bit key
        const hash = await crypto.subtle.digest("SHA-256", passwordBytes);

        // Import hash as AES-CBC key
        return crypto.subtle.importKey(
            "raw",
            hash,
            { name: "AES-CBC" },
            false,
            ["encrypt", "decrypt"]
        );
    }

    private async encryptStringToBytes(
        plainText: string,
        key: CryptoKey,
        iv: BufferSource): Promise<ArrayBuffer> {
        if (!plainText) throw new Error("plain_text cannot be null or empty.");
        if (!key) throw new Error("key cannot be null or empty.");
        if (!iv) throw new Error("iv cannot be null or empty.");

        const enc = new TextEncoder();
        return await crypto.subtle.encrypt(
            { name: "AES-CBC", iv },
            key,
            enc.encode(plainText)
        );
    }

    private async decryptStringFromBytes(
        cipherText: ArrayBuffer,
        key: CryptoKey,
        iv: BufferSource): Promise<string> {
        if (!cipherText) throw new Error("cipher_text cannot be null or empty.");
        if (!key) throw new Error("key cannot be null or empty.");
        if (!iv) throw new Error("iv cannot be null or empty.");

        const decrypted = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv },
            key,
            cipherText
        );

        const dec = new TextDecoder();
        return dec.decode(decrypted);
    }

    async encrypt(text: string, password: string): Promise<string> {
        try {
            const key = await this.generateKey(password);
            const iv = crypto.getRandomValues(new Uint8Array(16));
            const encrypted = await this.encryptStringToBytes(text, key, iv);

            // Combine IV + encrypted data into one buffer
            const combined = new Uint8Array(iv.length + encrypted.byteLength);
            combined.set(iv);
            combined.set(new Uint8Array(encrypted), iv.length);

            // Return Base64 encoded
            return encodeURIComponent(
                btoa(String.fromCharCode(...Array.from(combined))));
        } catch (error) {
            throw error;
        }
    }

    async decrypt(encryptedText: string, password: string): Promise<string> {
        try {
            const combinedBytes = new Uint8Array(
                atob(decodeURIComponent(encryptedText))
                    .split("")
                    .map(c => c.charCodeAt(0))
            );

            const iv = combinedBytes.subarray(0, 16);
            const encryptedData = combinedBytes.subarray(16);
            const key = await this.generateKey(password);

            return await this
                .decryptStringFromBytes(encryptedData.slice().buffer, key, iv);
        } catch (error) {
            throw error;
        }
    }
}

export default AesCryptography;