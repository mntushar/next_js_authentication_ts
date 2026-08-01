import argon2 from 'argon2';
import AesCryptography from './aes_cryptography';

class Cryptography {
  private aesCryptography = new AesCryptography();

  async hashPassword(password: string): Promise<string> {
    try {
      const hash = await argon2.hash(password, { type: argon2.argon2id });
      return hash;
    } catch (error) {
      throw error;
    }
  }

  async verifyPassword(storedHash: string, password: string): Promise<boolean> {
    try {
      const isValid = await argon2.verify(storedHash, password);
      return isValid;
    } catch (error) {
      throw error;
    }
  }

  async aseEncrypt(text: string): Promise<string> {
    return await this.aesCryptography
      .encrypt(text, process.env.AES_CRYPTOGRAPHY_PASSWORD as string);
  }

  async aseDecrypt(encryptedText: string): Promise<string> {
    return await this.aesCryptography
      .decrypt(encryptedText, process.env.AES_CRYPTOGRAPHY_PASSWORD as string);
  }
}

export default Cryptography;