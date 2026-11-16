/**
 * RFC 4648 Base32 및 RFC 6238 TOTP 표준 암호화 순수 모듈
 * 
 * [보안 원칙 준수]
 * 1. Math.random() 절대 금지: window.crypto.getRandomValues() 사용
 * 2. Zero-Transmission: Web Crypto API (SubtleCrypto) 기반 브라우저 내 연산 (외부 전송 0건)
 * 3. 메모리 기반 격리: 영구 스토리지에 저장하지 않고 순수 함수로 데이터 처리
 */

export const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Uint8Array 바이트 배열을 RFC 4648 Base32 문자열로 인코딩합니다.
 * Google Authenticator 호환성을 위해 패딩 문자(=)는 생략합니다.
 * @param {Uint8Array} bytes 
 * @returns {string} Base32 인코딩 문자열
 */
export function bytesToBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Base32 문자열을 디코딩하여 Uint8Array 바이트 배열로 변환합니다.
 * @param {string} base32String 
 * @returns {Uint8Array}
 */
export function base32ToBytes(base32String) {
  if (typeof base32String !== 'string') {
    throw new TypeError('Base32 입력은 문자열이어야 합니다.');
  }

  const cleanStr = base32String.replace(/\s+/g, '').replace(/=+$/, '').toUpperCase();
  if (cleanStr.length === 0) {
    return new Uint8Array(0);
  }

  for (let i = 0; i < cleanStr.length; i++) {
    if (BASE32_ALPHABET.indexOf(cleanStr[i]) === -1) {
      throw new Error(`유효하지 않은 Base32 문자입니다: '${cleanStr[i]}'`);
    }
  }

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleanStr[i]);
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * 암호학적으로 안전한 난수(CSPRNG)를 사용해 Base32 비밀 키를 생성합니다.
 * (Math.random 사용 절대 금지, window.crypto.getRandomValues 사용)
 * @param {number} byteLength 기본값 20 바이트 (160비트, 32자리 Base32)
 * @returns {string}
 */
export function generateSecret(byteLength = 20) {
  const bytes = new Uint8Array(byteLength);
  const cryptoObj = typeof window !== 'undefined' ? window.crypto : (globalThis.crypto || null);
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new Error('Web Crypto API (getRandomValues)를 지원하지 않는 환경입니다.');
  }
  cryptoObj.getRandomValues(bytes);
  return bytesToBase32(bytes);
}

/**
 * RFC 6238 TOTP (Time-based One-Time Password) 코드를 비동기로 계산합니다.
 * Web Crypto API의 SubtleCrypto HMAC-SHA1을 사용합니다.
 * @param {string} secretBase32 Base32 비밀 키
 * @param {number} counterOffset 카운터 오프셋 (기본 0, 시간 오차 보정 시 -1 또는 +1)
 * @param {number} timeStep 시간 주기 (기본 30초)
 * @param {number} digits 자릿수 (기본 6자리)
 * @param {number|null} overrideTimestamp 테스트용 임의 타임스탬프 (초 단위)
 * @returns {Promise<string>} 6자리 숫자 문자열 (예: '012345')
 */
export async function generateTOTP(
  secretBase32,
  counterOffset = 0,
  timeStep = 30,
  digits = 6,
  overrideTimestamp = null
) {
  const keyBytes = base32ToBytes(secretBase32);
  const timestamp = overrideTimestamp !== null ? overrideTimestamp : Math.floor(Date.now() / 1000);
  const counter = Math.floor(timestamp / timeStep) + counterOffset;

  // 64-bit Big-Endian 카운터 버퍼 생성
  const buffer = new ArrayBuffer(8);
  const dataView = new DataView(buffer);
  dataView.setBigUint64(0, BigInt(counter), false);

  const cryptoObj = typeof window !== 'undefined' ? window.crypto : (globalThis.crypto || null);
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('Web Crypto API (SubtleCrypto)를 지원하지 않는 환경입니다.');
  }

  // HMAC-SHA1 키 임포트 및 서명 연산
  const cryptoKey = await cryptoObj.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await cryptoObj.subtle.sign('HMAC', cryptoKey, buffer);
  const hash = new Uint8Array(signature);

  // RFC 4226 / RFC 6238 Dynamic Truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % (10 ** digits);
  return otp.toString().padStart(digits, '0');
}

/**
 * 30초 주기 카운트다운 및 타임스탬프 계산 유틸리티
 * @param {number} timeStep 
 * @returns {{ remaining: number, progress: number, timestamp: number, counter: number }}
 */
export function getTimeInfo(timeStep = 30) {
  const now = Math.floor(Date.now() / 1000);
  const remaining = timeStep - (now % timeStep);
  const progress = ((timeStep - remaining) / timeStep) * 100;
  const counter = Math.floor(now / timeStep);
  return {
    remaining,
    progress,
    timestamp: now,
    counter,
  };
}

/**
 * Google Authenticator 규격의 otpauth:// URI를 생성합니다.
 * @param {string} issuer 발급자 (예: 'Polytech-Sec')
 * @param {string} account 계정명 (예: 'yr@security.kr')
 * @param {string} secret Base32 비밀 키
 * @returns {string}
 */
export function generateOtpAuthUri(issuer, account, secret) {
  const encodedIssuer = encodeURIComponent(issuer.trim() || 'Service');
  const encodedAccount = encodeURIComponent(account.trim() || 'user');
  const cleanSecret = secret.replace(/\s+/g, '').toUpperCase();
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${cleanSecret}&issuer=${encodedIssuer}`;
}

