import {
  generateSecret,
  base32ToBytes,
  bytesToBase32,
  generateTOTP,
} from '../src/utils/totp.js';

async function runTests() {
  console.log('🧪 RFC 6238 & RFC 4648 표준 자체 검증 시작...\n');

  let passed = 0;
  let total = 0;

  function assert(condition, message) {
    total++;
    if (condition) {
      console.log(`  ✅ [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${message}`);
    }
  }

  // 1. Base32 인코딩/디코딩 라운드트립 테스트
  console.log('1. Base32 인코딩 / 디코딩 라운드트립 검증:');
  const sampleBytes = new TextEncoder().encode('12345678901234567890');
  const b32 = bytesToBase32(sampleBytes);
  assert(
    b32 === 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    `ASCII '12345678901234567890' -> Base32 변환 일치: ${b32}`
  );

  const decodedBytes = base32ToBytes(b32);
  const roundtripText = new TextDecoder().decode(decodedBytes);
  assert(
    roundtripText === '12345678901234567890',
    `Base32 디코딩 원문 복원 일치: ${roundtripText}`
  );

  // 2. CSPRNG 비밀 키 생성기 검증 (Math.random 금지, 160비트/32자리 Base32)
  console.log('\n2. CSPRNG 비밀 키 생성기 검증:');
  const secret1 = generateSecret(20);
  const secret2 = generateSecret(20);
  assert(
    secret1.length === 32,
    `20바이트(160비트) 비밀 키의 Base32 길이는 정확히 32자여야 함: ${secret1.length}`
  );
  assert(
    secret1 !== secret2,
    `두 번 연속 생성된 비밀 키는 암호학적 난수이므로 달라야 함: ${secret1} !== ${secret2}`
  );
  assert(
    /^[A-Z2-7]{32}$/.test(secret1),
    `RFC 4648 Base32 유효 문자셋(패딩 없음) 검사 통과: ${secret1}`
  );

  // 3. RFC 6238 공식 테스트 벡터 검증
  console.log('\n3. RFC 6238 Appendix B 공식 테스트 벡터 검증 (SHA-1, 6 Digits):');
  const testSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const testVectors = [
    { time: 59, expected: '287082', counter: 1 },
    { time: 1111111109, expected: '081804', counter: 37037036 },
    { time: 1111111111, expected: '050471', counter: 37037037 },
    { time: 1234567890, expected: '005924', counter: 41152263 },
    { time: 2000000000, expected: '279037', counter: 66666666 },
    { time: 20000000000, expected: '353130', counter: 666666666 },
  ];

  for (const tv of testVectors) {
    const otp = await generateTOTP(testSecret, 0, 30, 6, tv.time);
    assert(
      otp === tv.expected,
      `Time=${tv.time}s (T=${tv.counter}): 계산값 '${otp}' === 기대값 '${tv.expected}'`
    );
  }

  // 4. 시간 오차(Time drift) 보정 검증
  console.log('\n4. 시간 오차(±1 Step) 오프셋 검증:');
  const baseTime = 1234567890; // T=41152263 -> '005924'
  const prevOtp = await generateTOTP(testSecret, -1, 30, 6, baseTime);
  const currOtp = await generateTOTP(testSecret, 0, 30, 6, baseTime);
  const nextOtp = await generateTOTP(testSecret, +1, 30, 6, baseTime);

  assert(
    currOtp === '005924',
    `기준 시간 OTP('${currOtp}') 일치`
  );

  // 이전 스텝(T-1)은 baseTime - 30초에서의 일반 TOTP와 정확히 같아야 함
  const actualPrev = await generateTOTP(testSecret, 0, 30, 6, baseTime - 30);
  const actualNext = await generateTOTP(testSecret, 0, 30, 6, baseTime + 30);
  assert(
    prevOtp === actualPrev,
    `오프셋 -1 OTP('${prevOtp}')는 이전 30초 실제 OTP와 일치`
  );
  assert(
    nextOtp === actualNext,
    `오프셋 +1 OTP('${nextOtp}')는 다음 30초 실제 OTP와 일치`
  );

  console.log(`\n========================================`);
  console.log(`🎯 테스트 결과: ${passed} / ${total} 통과 (${passed === total ? 'ALL PASS! 🎉' : 'FAIL'})`);
  console.log(`========================================\n`);

  if (passed !== total) {
    process.exit(1);
  }
}

runTests().catch((err) => {
  console.error('테스트 실행 중 오류 발생:', err);
  process.exit(1);
});
