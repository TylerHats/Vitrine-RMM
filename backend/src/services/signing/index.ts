import fs from 'fs';
import path from 'path';

export interface SigningResult {
  success: boolean;
  signedFilePath?: string;
  error?: string;
  filename?: string;
}

export class CodeSigningService {
  private endpointUrl: string;

  constructor(endpointUrl = process.env.CODE_SIGNING_URL || 'http://10.10.10.20:5000') {
    this.endpointUrl = endpointUrl;
  }

  public async signFile(filePath: string): Promise<SigningResult> {
    try {
      const filename = path.basename(filePath);
      const fileData = fs.readFileSync(filePath);
      const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);

      // Construct multipart/form-data payload
      const pre = Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`
      );
      const post = Buffer.from(`\r\n--${boundary}--\r\n`);
      const body = Buffer.concat([pre, fileData, post]);

      const res = await fetch(`${this.endpointUrl}/sign`, {
        method: 'POST',
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`
        },
        body
      });

      if (!res.ok) {
        const errorText = await res.text();
        return { success: false, error: `Signer returned HTTP ${res.status}: ${errorText}`, filename };
      }

      const arrayBuffer = await res.arrayBuffer();
      const signedBuffer = Buffer.from(arrayBuffer);

      // Verify the response is not a JSON error
      const textPreview = signedBuffer.slice(0, 100).toString('utf8');
      if (textPreview.startsWith('{"status":"Failed"')) {
        const parsed = JSON.parse(signedBuffer.toString('utf8'));
        return { success: false, error: parsed.error, filename };
      }

      const signedFilePath = filePath.replace(/(\.[^.]+)$/, '.signed$1');
      fs.writeFileSync(signedFilePath, signedBuffer);

      return {
        success: true,
        signedFilePath,
        filename
      };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  }
}

export const codeSigningService = new CodeSigningService();
