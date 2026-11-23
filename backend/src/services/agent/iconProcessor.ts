import zlib from 'node:zlib';

export interface RgbaImage {
  width: number;
  height: number;
  data: Uint8Array; // length = width * height * 4 (R, G, B, A)
}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const MAX_DIMENSION = 4096;
const MAX_RGBA_BYTES = 64 * 1024 * 1024;

const ADAM7_PASSES: ReadonlyArray<{ xStart: number; yStart: number; xStep: number; yStep: number }> = [
  { xStart: 0, yStart: 0, xStep: 8, yStep: 8 },
  { xStart: 4, yStart: 0, xStep: 8, yStep: 8 },
  { xStart: 0, yStart: 4, xStep: 4, yStep: 8 },
  { xStart: 2, yStart: 0, xStep: 4, yStep: 4 },
  { xStart: 0, yStart: 2, xStep: 2, yStep: 4 },
  { xStart: 1, yStart: 0, xStep: 2, yStep: 2 },
  { xStart: 0, yStart: 1, xStep: 1, yStep: 2 }
];

const CRC_TABLE = (() => {
  const tbl = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) !== 0 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    tbl[n] = c >>> 0;
  }
  return tbl;
})();

function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makePngChunk(type: string, data: Buffer): Buffer {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.allocUnsafe(4);
  lenBuf.writeUInt32BE(data.length, 0);
  const body = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.allocUnsafe(4);
  crcBuf.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([lenBuf, body, crcBuf]);
}

function paethPredictor(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  if (pb <= pc) return b;
  return c;
}

function unfilterScanline(
  filterType: number,
  raw: Uint8Array,
  rawOff: number,
  prev: Uint8Array | null,
  out: Uint8Array,
  rowBytes: number,
  bpp: number
): void {
  switch (filterType) {
    case 0:
      for (let i = 0; i < rowBytes; i++) out[i] = raw[rawOff + i];
      break;
    case 1:
      for (let i = 0; i < rowBytes; i++) {
        const a = i >= bpp ? out[i - bpp] : 0;
        out[i] = (raw[rawOff + i] + a) & 0xff;
      }
      break;
    case 2:
      for (let i = 0; i < rowBytes; i++) {
        const b = prev ? prev[i] : 0;
        out[i] = (raw[rawOff + i] + b) & 0xff;
      }
      break;
    case 3:
      for (let i = 0; i < rowBytes; i++) {
        const a = i >= bpp ? out[i - bpp] : 0;
        const b = prev ? prev[i] : 0;
        out[i] = (raw[rawOff + i] + ((a + b) >> 1)) & 0xff;
      }
      break;
    case 4:
      for (let i = 0; i < rowBytes; i++) {
        const a = i >= bpp ? out[i - bpp] : 0;
        const b = prev ? prev[i] : 0;
        const c = prev && i >= bpp ? prev[i - bpp] : 0;
        out[i] = (raw[rawOff + i] + paethPredictor(a, b, c)) & 0xff;
      }
      break;
    default:
      throw new Error(`Unsupported PNG scanline filter type: ${filterType}`);
  }
}

function readSampleValue(scanline: Uint8Array, x: number, sampleOffset: number, samplesPerPixel: number, bitDepth: number): number {
  const sampleIdx = x * samplesPerPixel + sampleOffset;
  if (bitDepth === 8) {
    return scanline[sampleIdx];
  }
  if (bitDepth === 16) {
    return scanline[sampleIdx * 2];
  }
  const samplesPerByte = 8 / bitDepth;
  const byteIdx = Math.floor(sampleIdx / samplesPerByte);
  const subIdx = sampleIdx % samplesPerByte;
  const shift = 8 - bitDepth * (subIdx + 1);
  const mask = (1 << bitDepth) - 1;
  return (scanline[byteIdx] >> shift) & mask;
}

function scaleLowBitSample(val: number, bitDepth: number): number {
  if (bitDepth === 8) return val;
  if (bitDepth === 1) return val ? 255 : 0;
  if (bitDepth === 2) return val * 85;
  if (bitDepth === 4) return val * 17;
  return val;
}

export function isPngBuffer(buf: Buffer): boolean {
  return buf.length >= 29 && buf.subarray(0, 8).equals(PNG_SIG);
}

export function isIcoBuffer(buf: Buffer): boolean {
  if (buf.length < 22) return false;
  const reserved = buf.readUInt16LE(0);
  const type = buf.readUInt16LE(2);
  const count = buf.readUInt16LE(4);
  return reserved === 0 && type === 1 && count >= 1 && count <= 256;
}

export function decodePngToRgba(buf: Buffer): RgbaImage {
  if (!isPngBuffer(buf)) {
    throw new Error('Invalid PNG signature');
  }

  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  let sawIhdr = false;
  let sawIend = false;
  let palette: Buffer | null = null;
  let trns: Buffer | null = null;
  const idatChunks: Buffer[] = [];

  while (offset + 12 <= buf.length) {
    const chunkLen = buf.readUInt32BE(offset);
    const chunkType = buf.subarray(offset + 4, offset + 8).toString('ascii');
    const dataStart = offset + 8;
    const dataEnd = dataStart + chunkLen;
    if (chunkLen > 0x7fffffff || dataEnd + 4 > buf.length) {
      throw new Error(`Truncated or malformed PNG chunk '${chunkType}'`);
    }
    const chunkData = buf.subarray(dataStart, dataEnd);

    if (chunkType === 'IHDR') {
      if (sawIhdr || chunkLen !== 13) throw new Error('Invalid PNG IHDR chunk');
      width = chunkData.readUInt32BE(0);
      height = chunkData.readUInt32BE(4);
      bitDepth = chunkData[8];
      colorType = chunkData[9];
      const compression = chunkData[10];
      const filterMethod = chunkData[11];
      interlace = chunkData[12];
      if (width < 1 || height < 1 || width > MAX_DIMENSION || height > MAX_DIMENSION) {
        throw new Error(`PNG dimensions ${width}x${height} out of bounds`);
      }
      if (width * height * 4 > MAX_RGBA_BYTES) {
        throw new Error('PNG pixel buffer exceeds 64 MB safety limit');
      }
      if (compression !== 0 || filterMethod !== 0 || (interlace !== 0 && interlace !== 1)) {
        throw new Error('Unsupported PNG compression, filter, or interlace method');
      }
      const validDepths: Record<number, number[]> = {
        0: [1, 2, 4, 8, 16],
        2: [8, 16],
        3: [1, 2, 4, 8],
        4: [8, 16],
        6: [8, 16]
      };
      if (!validDepths[colorType] || !validDepths[colorType].includes(bitDepth)) {
        throw new Error(`Unsupported PNG colorType=${colorType} bitDepth=${bitDepth}`);
      }
      sawIhdr = true;
    } else if (chunkType === 'PLTE') {
      if (!sawIhdr || chunkLen === 0 || chunkLen % 3 !== 0) {
        throw new Error('Invalid PNG PLTE chunk');
      }
      palette = chunkData;
    } else if (chunkType === 'tRNS') {
      trns = chunkData;
    } else if (chunkType === 'IDAT') {
      if (!sawIhdr) throw new Error('IDAT encountered before IHDR');
      idatChunks.push(chunkData);
    } else if (chunkType === 'IEND') {
      sawIend = true;
      break;
    }

    offset = dataEnd + 4;
  }

  if (!sawIhdr || idatChunks.length === 0 || !sawIend) {
    throw new Error('Incomplete PNG stream (missing IHDR, IDAT, or IEND)');
  }
  if (colorType === 3 && !palette) {
    throw new Error('Indexed PNG missing required PLTE palette');
  }

  const samplesPerPixel =
    colorType === 0 ? 1 : colorType === 2 ? 3 : colorType === 3 ? 1 : colorType === 4 ? 2 : 4;
  const bpp = Math.max(1, Math.ceil((samplesPerPixel * bitDepth) / 8));

  const compressed = Buffer.concat(idatChunks);
  const raw = zlib.inflateSync(compressed, { maxOutputLength: MAX_RGBA_BYTES * 2 });
  const rgba = new Uint8Array(width * height * 4);

  const grayTrns = colorType === 0 && trns && trns.length >= 2 ? (bitDepth === 16 ? trns[0] : trns.readUInt16BE(0)) : -1;
  const rgbTrnsR = colorType === 2 && trns && trns.length >= 6 ? (bitDepth === 16 ? trns[0] : trns.readUInt16BE(0)) : -1;
  const rgbTrnsG = colorType === 2 && trns && trns.length >= 6 ? (bitDepth === 16 ? trns[2] : trns.readUInt16BE(2)) : -1;
  const rgbTrnsB = colorType === 2 && trns && trns.length >= 6 ? (bitDepth === 16 ? trns[4] : trns.readUInt16BE(4)) : -1;

  const writePixel = (x: number, y: number, scanline: Uint8Array, sx: number) => {
    const outIdx = (y * width + x) * 4;
    if (colorType === 6) {
      rgba[outIdx] = readSampleValue(scanline, sx, 0, 4, bitDepth);
      rgba[outIdx + 1] = readSampleValue(scanline, sx, 1, 4, bitDepth);
      rgba[outIdx + 2] = readSampleValue(scanline, sx, 2, 4, bitDepth);
      rgba[outIdx + 3] = readSampleValue(scanline, sx, 3, 4, bitDepth);
    } else if (colorType === 2) {
      const r = readSampleValue(scanline, sx, 0, 3, bitDepth);
      const g = readSampleValue(scanline, sx, 1, 3, bitDepth);
      const b = readSampleValue(scanline, sx, 2, 3, bitDepth);
      rgba[outIdx] = r;
      rgba[outIdx + 1] = g;
      rgba[outIdx + 2] = b;
      rgba[outIdx + 3] = rgbTrnsR >= 0 && r === rgbTrnsR && g === rgbTrnsG && b === rgbTrnsB ? 0 : 255;
    } else if (colorType === 3 && palette) {
      const idx = readSampleValue(scanline, sx, 0, 1, bitDepth);
      const pOff = idx * 3;
      if (pOff + 2 < palette.length) {
        rgba[outIdx] = palette[pOff];
        rgba[outIdx + 1] = palette[pOff + 1];
        rgba[outIdx + 2] = palette[pOff + 2];
      }
      rgba[outIdx + 3] = trns && idx < trns.length ? trns[idx] : 255;
    } else if (colorType === 4) {
      const g = readSampleValue(scanline, sx, 0, 2, bitDepth);
      const a = readSampleValue(scanline, sx, 1, 2, bitDepth);
      rgba[outIdx] = g;
      rgba[outIdx + 1] = g;
      rgba[outIdx + 2] = g;
      rgba[outIdx + 3] = a;
    } else if (colorType === 0) {
      const rawVal = readSampleValue(scanline, sx, 0, 1, bitDepth);
      const g = scaleLowBitSample(rawVal, bitDepth);
      rgba[outIdx] = g;
      rgba[outIdx + 1] = g;
      rgba[outIdx + 2] = g;
      rgba[outIdx + 3] = grayTrns >= 0 && rawVal === grayTrns ? 0 : 255;
    }
  };

  let rawPos = 0;
  if (interlace === 0) {
    const rowBytes = Math.ceil((width * samplesPerPixel * bitDepth) / 8);
    let prev = new Uint8Array(rowBytes);
    let curr = new Uint8Array(rowBytes);
    for (let y = 0; y < height; y++) {
      if (rawPos + 1 + rowBytes > raw.length) {
        throw new Error('Truncated decompressed PNG image data');
      }
      const filterType = raw[rawPos++];
      unfilterScanline(filterType, raw, rawPos, y === 0 ? null : prev, curr, rowBytes, bpp);
      rawPos += rowBytes;
      for (let x = 0; x < width; x++) {
        writePixel(x, y, curr, x);
      }
      const tmp = prev;
      prev = curr;
      curr = tmp;
    }
  } else {
    for (const pass of ADAM7_PASSES) {
      if (pass.xStart >= width || pass.yStart >= height) continue;
      const passW = Math.ceil((width - pass.xStart) / pass.xStep);
      const passH = Math.ceil((height - pass.yStart) / pass.yStep);
      const rowBytes = Math.ceil((passW * samplesPerPixel * bitDepth) / 8);
      let prev = new Uint8Array(rowBytes);
      let curr = new Uint8Array(rowBytes);
      for (let py = 0; py < passH; py++) {
        if (rawPos + 1 + rowBytes > raw.length) {
          throw new Error('Truncated interlaced PNG pass data');
        }
        const filterType = raw[rawPos++];
        unfilterScanline(filterType, raw, rawPos, py === 0 ? null : prev, curr, rowBytes, bpp);
        rawPos += rowBytes;
        const y = pass.yStart + py * pass.yStep;
        for (let px = 0; px < passW; px++) {
          const x = pass.xStart + px * pass.xStep;
          writePixel(x, y, curr, px);
        }
        const tmp = prev;
        prev = curr;
        curr = tmp;
      }
    }
  }

  return { width, height, data: rgba };
}

function decodeBmpDibToRgba(dib: Buffer): RgbaImage {
  if (dib.length < 40) {
    throw new Error('Truncated ICO BITMAPINFOHEADER');
  }
  const biSize = dib.readUInt32LE(0);
  if (biSize < 40 || biSize > dib.length) {
    throw new Error(`Unsupported DIB header size: ${biSize}`);
  }
  const width = dib.readInt32LE(4);
  const rawHeight = dib.readInt32LE(8);
  const height = Math.floor(Math.abs(rawHeight) / 2);
  const planes = dib.readUInt16LE(12);
  const bitCount = dib.readUInt16LE(14);
  const compression = dib.readUInt32LE(16);
  const clrUsed = dib.readUInt32LE(32);

  if (width < 1 || height < 1 || width > MAX_DIMENSION || height > MAX_DIMENSION) {
    throw new Error(`ICO DIB dimensions ${width}x${height} out of bounds`);
  }
  if (planes !== 1 || compression !== 0) {
    throw new Error(`Unsupported ICO DIB planes=${planes} compression=${compression}`);
  }

  const paletteColors = bitCount <= 8 ? (clrUsed > 0 ? clrUsed : 1 << bitCount) : 0;
  const paletteOffset = biSize;
  const pixelOffset = paletteOffset + paletteColors * 4;
  const xorRowBytes = Math.ceil((width * bitCount) / 32) * 4;
  const xorSize = xorRowBytes * height;
  const andRowBytes = Math.ceil(width / 32) * 4;
  const andOffset = pixelOffset + xorSize;

  if (andOffset > dib.length) {
    throw new Error('Truncated ICO DIB pixel buffer');
  }

  const hasAndMask = andOffset + andRowBytes * height <= dib.length;
  const rgba = new Uint8Array(width * height * 4);
  let anyAlphaNonZero = false;

  for (let row = 0; row < height; row++) {
    const srcY = rawHeight > 0 ? height - 1 - row : row;
    const xorRowStart = pixelOffset + srcY * xorRowBytes;
    const andRowStart = andOffset + srcY * andRowBytes;

    for (let x = 0; x < width; x++) {
      const outIdx = (row * width + x) * 4;
      let r = 0;
      let g = 0;
      let b = 0;
      let a = 255;

      if (bitCount === 32) {
        const px = xorRowStart + x * 4;
        b = dib[px];
        g = dib[px + 1];
        r = dib[px + 2];
        a = dib[px + 3];
        if (a !== 0) anyAlphaNonZero = true;
      } else if (bitCount === 24) {
        const px = xorRowStart + x * 3;
        b = dib[px];
        g = dib[px + 1];
        r = dib[px + 2];
      } else if (bitCount === 8 || bitCount === 4 || bitCount === 1) {
        let colorIdx = 0;
        if (bitCount === 8) {
          colorIdx = dib[xorRowStart + x];
        } else if (bitCount === 4) {
          const byteVal = dib[xorRowStart + (x >> 1)];
          colorIdx = (x & 1) === 0 ? (byteVal >> 4) & 0x0f : byteVal & 0x0f;
        } else {
          const byteVal = dib[xorRowStart + (x >> 3)];
          colorIdx = (byteVal >> (7 - (x & 7))) & 1;
        }
        const palOff = paletteOffset + colorIdx * 4;
        if (palOff + 3 < pixelOffset) {
          b = dib[palOff];
          g = dib[palOff + 1];
          r = dib[palOff + 2];
        }
      } else {
        throw new Error(`Unsupported ICO DIB bit depth: ${bitCount}`);
      }

      if (bitCount !== 32 && hasAndMask) {
        const maskByte = dib[andRowStart + (x >> 3)];
        const isTransparent = ((maskByte >> (7 - (x & 7))) & 1) !== 0;
        a = isTransparent ? 0 : 255;
      }

      rgba[outIdx] = r;
      rgba[outIdx + 1] = g;
      rgba[outIdx + 2] = b;
      rgba[outIdx + 3] = a;
    }
  }

  // Legacy 32-bit DIBs with all-zero alpha rely on the 1-bit AND mask
  if (bitCount === 32 && !anyAlphaNonZero && hasAndMask) {
    for (let row = 0; row < height; row++) {
      const srcY = rawHeight > 0 ? height - 1 - row : row;
      const andRowStart = andOffset + srcY * andRowBytes;
      for (let x = 0; x < width; x++) {
        const maskByte = dib[andRowStart + (x >> 3)];
        const isTransparent = ((maskByte >> (7 - (x & 7))) & 1) !== 0;
        rgba[(row * width + x) * 4 + 3] = isTransparent ? 0 : 255;
      }
    }
  }

  return { width, height, data: rgba };
}

export function decodeIcoToRgba(buf: Buffer): RgbaImage {
  if (!isIcoBuffer(buf)) {
    throw new Error('Invalid ICO header');
  }
  const count = buf.readUInt16LE(4);
  if (buf.length < 6 + count * 16) {
    throw new Error('Truncated ICO directory entries');
  }

  interface CandidateEntry {
    w: number;
    h: number;
    bpp: number;
    size: number;
    offset: number;
  }
  const entries: CandidateEntry[] = [];
  for (let i = 0; i < count; i++) {
    const base = 6 + i * 16;
    const w = buf[base] === 0 ? 256 : buf[base];
    const h = buf[base + 1] === 0 ? 256 : buf[base + 1];
    const bpp = buf.readUInt16LE(base + 6);
    const size = buf.readUInt32LE(base + 8);
    const off = buf.readUInt32LE(base + 12);
    if (size >= 8 && off >= 6 + count * 16 && off + size <= buf.length) {
      entries.push({ w, h, bpp, size, offset: off });
    }
  }

  if (entries.length === 0) {
    throw new Error('No valid image entries found in ICO');
  }

  entries.sort((a, b) => {
    const areaDiff = b.w * b.h - a.w * a.h;
    if (areaDiff !== 0) return areaDiff;
    return b.bpp - a.bpp;
  });

  let lastErr: unknown = null;
  for (const entry of entries) {
    const slice = buf.subarray(entry.offset, entry.offset + entry.size);
    try {
      if (isPngBuffer(slice)) {
        return decodePngToRgba(slice);
      }
      return decodeBmpDibToRgba(slice);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error('Failed to decode ICO image entries');
}

function resizeRectRgba(
  src: RgbaImage,
  srcX0: number,
  srcY0: number,
  srcCropW: number,
  srcCropH: number,
  dstW: number,
  dstH: number
): Uint8Array {
  const out = new Uint8Array(dstW * dstH * 4);
  const { width: sW, height: sH, data } = src;
  const scaleX = srcCropW / dstW;
  const scaleY = srcCropH / dstH;

  if (scaleX >= 1.0 && scaleY >= 1.0) {
    // High-quality premultiplied box/area averaging downscaler
    for (let dy = 0; dy < dstH; dy++) {
      const sy0 = Math.max(0, srcY0 + dy * scaleY);
      const sy1 = Math.min(sH, srcY0 + (dy + 1) * scaleY);
      const iy0 = Math.floor(sy0);
      const iy1 = Math.min(sH - 1, Math.floor(Math.max(sy0, sy1 - 1e-6)));

      for (let dx = 0; dx < dstW; dx++) {
        const sx0 = Math.max(0, srcX0 + dx * scaleX);
        const sx1 = Math.min(sW, srcX0 + (dx + 1) * scaleX);
        const ix0 = Math.floor(sx0);
        const ix1 = Math.min(sW - 1, Math.floor(Math.max(sx0, sx1 - 1e-6)));

        let sumW = 0;
        let sumA = 0;
        let sumR = 0;
        let sumG = 0;
        let sumB = 0;

        for (let py = iy0; py <= iy1; py++) {
          const wy = Math.min(sy1, py + 1) - Math.max(sy0, py);
          if (wy <= 0) continue;
          for (let px = ix0; px <= ix1; px++) {
            const wx = Math.min(sx1, px + 1) - Math.max(sx0, px);
            if (wx <= 0) continue;
            const w = wx * wy;
            const idx = (py * sW + px) * 4;
            const a = data[idx + 3];
            const wa = w * a;
            sumW += w;
            sumA += wa;
            sumR += data[idx] * wa;
            sumG += data[idx + 1] * wa;
            sumB += data[idx + 2] * wa;
          }
        }

        const outIdx = (dy * dstW + dx) * 4;
        if (sumA > 1e-6 && sumW > 1e-6) {
          out[outIdx] = Math.min(255, Math.max(0, Math.round(sumR / sumA)));
          out[outIdx + 1] = Math.min(255, Math.max(0, Math.round(sumG / sumA)));
          out[outIdx + 2] = Math.min(255, Math.max(0, Math.round(sumB / sumA)));
          out[outIdx + 3] = Math.min(255, Math.max(0, Math.round(sumA / sumW)));
        }
      }
    }
    return out;
  }

  // Bilinear sampler with premultiplied alpha for upscaling or mixed scale axes
  for (let dy = 0; dy < dstH; dy++) {
    const sy = Math.min(sH - 1, Math.max(0, srcY0 + ((dy + 0.5) * srcCropH) / dstH - 0.5));
    const y0 = Math.floor(sy);
    const y1 = Math.min(sH - 1, y0 + 1);
    const fy = sy - y0;

    for (let dx = 0; dx < dstW; dx++) {
      const sx = Math.min(sW - 1, Math.max(0, srcX0 + ((dx + 0.5) * srcCropW) / dstW - 0.5));
      const x0 = Math.floor(sx);
      const x1 = Math.min(sW - 1, x0 + 1);
      const fx = sx - x0;

      const w00 = (1 - fx) * (1 - fy);
      const w10 = fx * (1 - fy);
      const w01 = (1 - fx) * fy;
      const w11 = fx * fy;

      const i00 = (y0 * sW + x0) * 4;
      const i10 = (y0 * sW + x1) * 4;
      const i01 = (y1 * sW + x0) * 4;
      const i11 = (y1 * sW + x1) * 4;

      const a00 = data[i00 + 3] * w00;
      const a10 = data[i10 + 3] * w10;
      const a01 = data[i01 + 3] * w01;
      const a11 = data[i11 + 3] * w11;
      const sumA = a00 + a10 + a01 + a11;

      const outIdx = (dy * dstW + dx) * 4;
      if (sumA > 1e-6) {
        out[outIdx] = Math.min(
          255,
          Math.max(0, Math.round((data[i00] * a00 + data[i10] * a10 + data[i01] * a01 + data[i11] * a11) / sumA))
        );
        out[outIdx + 1] = Math.min(
          255,
          Math.max(
            0,
            Math.round((data[i00 + 1] * a00 + data[i10 + 1] * a10 + data[i01 + 1] * a01 + data[i11 + 1] * a11) / sumA)
          )
        );
        out[outIdx + 2] = Math.min(
          255,
          Math.max(
            0,
            Math.round((data[i00 + 2] * a00 + data[i10 + 2] * a10 + data[i01 + 2] * a01 + data[i11 + 2] * a11) / sumA)
          )
        );
        out[outIdx + 3] = Math.min(255, Math.max(0, Math.round(sumA)));
      }
    }
  }
  return out;
}

export function resizeRgbaToSquare(
  src: RgbaImage,
  targetSize: number,
  fit: 'contain' | 'cover' = 'contain'
): RgbaImage {
  const size = Math.max(1, Math.min(MAX_DIMENSION, Math.round(targetSize)));
  if (src.width === size && src.height === size) {
    return { width: size, height: size, data: new Uint8Array(src.data) };
  }

  if (fit === 'cover') {
    const side = Math.min(src.width, src.height);
    const sx0 = (src.width - side) / 2;
    const sy0 = (src.height - side) / 2;
    const data = resizeRectRgba(src, sx0, sy0, side, side, size, size);
    return { width: size, height: size, data };
  }

  const scale = Math.min(size / src.width, size / src.height);
  const dstW = Math.max(1, Math.min(size, Math.round(src.width * scale)));
  const dstH = Math.max(1, Math.min(size, Math.round(src.height * scale)));
  const fitted = resizeRectRgba(src, 0, 0, src.width, src.height, dstW, dstH);

  if (dstW === size && dstH === size) {
    return { width: size, height: size, data: fitted };
  }

  const out = new Uint8Array(size * size * 4);
  const offX = Math.floor((size - dstW) / 2);
  const offY = Math.floor((size - dstH) / 2);
  for (let y = 0; y < dstH; y++) {
    const srcStart = y * dstW * 4;
    const dstStart = ((offY + y) * size + offX) * 4;
    out.set(fitted.subarray(srcStart, srcStart + dstW * 4), dstStart);
  }
  return { width: size, height: size, data: out };
}

export function encodeCleanPng(rgba: Uint8Array, width: number, height: number): Buffer {
  const ihdr = Buffer.allocUnsafe(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0; // zlib deflate
  ihdr[11] = 0; // standard filter
  ihdr[12] = 0; // no interlace

  const stride = width * 4;
  const raw = Buffer.allocUnsafe(height * (1 + stride));
  for (let y = 0; y < height; y++) {
    const rowOut = y * (1 + stride);
    const rowIn = y * stride;
    raw[rowOut] = 1; // Sub filter
    for (let i = 0; i < stride; i++) {
      const a = i >= 4 ? rgba[rowIn + i - 4] : 0;
      raw[rowOut + 1 + i] = (rgba[rowIn + i] - a) & 0xff;
    }
  }

  const compressed = zlib.deflateSync(raw, { level: 6 });
  return Buffer.concat([
    PNG_SIG,
    makePngChunk('IHDR', ihdr),
    makePngChunk('IDAT', compressed),
    makePngChunk('IEND', Buffer.alloc(0))
  ]);
}

export function sanitizeAndSquareBrandingPng(buf: Buffer, maxSize = 256): Buffer | null {
  let decoded: RgbaImage;
  if (isPngBuffer(buf)) {
    decoded = decodePngToRgba(buf);
  } else if (isIcoBuffer(buf)) {
    decoded = decodeIcoToRgba(buf);
  } else {
    return null;
  }

  const targetSize =
    decoded.width === decoded.height && decoded.width <= maxSize
      ? decoded.width
      : Math.min(maxSize, Math.max(decoded.width, decoded.height));
  const squared = resizeRgbaToSquare(decoded, targetSize, 'contain');
  return encodeCleanPng(squared.data, squared.width, squared.height);
}

export function buildMultiSizeUncompressedIcoFromRgba(
  rgba: Uint8Array,
  width: number,
  height: number,
  sizes: number[] = [16, 32, 48]
): Buffer {
  const src: RgbaImage = { width, height, data: rgba };
  const dibs: Array<{ size: number; dib: Buffer }> = [];

  for (const rawSize of sizes) {
    const s = Math.max(8, Math.min(256, Math.round(rawSize)));
    const sq = resizeRgbaToSquare(src, s, 'contain');
    const xorLen = s * s * 4;
    const andRowBytes = Math.ceil(s / 32) * 4;
    const andLen = andRowBytes * s;
    const dib = Buffer.alloc(40 + xorLen + andLen, 0);

    // BITMAPINFOHEADER
    dib.writeUInt32LE(40, 0);
    dib.writeInt32LE(s, 4);
    dib.writeInt32LE(s * 2, 8); // XOR + AND combined height
    dib.writeUInt16LE(1, 12); // planes
    dib.writeUInt16LE(32, 14); // bpp
    dib.writeUInt32LE(0, 16); // BI_RGB (uncompressed)
    dib.writeUInt32LE(xorLen + andLen, 20);

    // Bottom-up BGRA XOR bitmap + bottom-up 1-bit AND mask
    const xorBase = 40;
    const andBase = 40 + xorLen;
    for (let y = 0; y < s; y++) {
      const srcY = s - 1 - y; // bottom-up DIB ordering
      for (let x = 0; x < s; x++) {
        const sIdx = (srcY * s + x) * 4;
        const dIdx = xorBase + (y * s + x) * 4;
        const r = sq.data[sIdx];
        const g = sq.data[sIdx + 1];
        const b = sq.data[sIdx + 2];
        const a = sq.data[sIdx + 3];
        dib[dIdx] = b;
        dib[dIdx + 1] = g;
        dib[dIdx + 2] = r;
        dib[dIdx + 3] = a;

        if (a < 128) {
          const andIdx = andBase + y * andRowBytes + (x >> 3);
          dib[andIdx] |= 1 << (7 - (x & 7));
        }
      }
    }
    dibs.push({ size: s, dib });
  }

  const headerSize = 6 + dibs.length * 16;
  const header = Buffer.alloc(headerSize, 0);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type = ICON
  header.writeUInt16LE(dibs.length, 4);

  let offset = headerSize;
  for (let i = 0; i < dibs.length; i++) {
    const { size: s, dib } = dibs[i];
    const base = 6 + i * 16;
    header[base] = s >= 256 ? 0 : s;
    header[base + 1] = s >= 256 ? 0 : s;
    header[base + 2] = 0;
    header[base + 3] = 0;
    header.writeUInt16LE(1, base + 4);
    header.writeUInt16LE(32, base + 6);
    header.writeUInt32LE(dib.length, base + 8);
    header.writeUInt32LE(offset, base + 12);
    offset += dib.length;
  }

  return Buffer.concat([header, ...dibs.map((d) => d.dib)]);
}

export function imageBufferToMultiSizeIco(buf: Buffer): Buffer | null {
  try {
    let img: RgbaImage | null = null;
    if (isPngBuffer(buf)) {
      img = decodePngToRgba(buf);
    } else if (isIcoBuffer(buf)) {
      img = decodeIcoToRgba(buf);
    }
    if (!img) return null;
    return buildMultiSizeUncompressedIcoFromRgba(img.data, img.width, img.height, [16, 32, 48]);
  } catch {
    return null;
  }
}

