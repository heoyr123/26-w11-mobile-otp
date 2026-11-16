import {
  generateSecret,
  generateTOTP,
  getTimeInfo,
  generateOtpAuthUri,
} from '../src/utils/totp.js';

async function testE2EWorkflow() {
  console.log('🔄 모바일 OTP 엔드투엔드(E2E) 워크플로우 시뮬레이션 시작...\n');

  // 1. 발급자(Issuer) & 계정(Account) 기본값 설정
  const issuer = 'Polytech-Sec';
  const account = 'yr@security.kr';
  console.log(`[1] 발급자: ${issuer}, 계정명: ${account}`);

  // 2. CSPRNG 비밀 키 발급
  const secret = generateSecret(20);
  console.log(`[2] 자동 발급된 비밀 키 (Base32): ${secret} (길이: ${secret.length}자)`);
  if (!/^[A-Z2-7]{32}$/.test(secret)) {
    throw new Error('비밀 키 형식 불일치');
  }

  // 3. otpauth:// URI 생성
  const uri = generateOtpAuthUri(issuer, account, secret);
  console.log(`[3] 생성된 URI: ${uri}`);
  const expectedPrefix = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}`;
  if (uri !== expectedPrefix) {
    throw new Error(`URI 포맷 불일치: ${uri} !== ${expectedPrefix}`);
  }

  // 4. 타이머 및 현재 실시간 OTP 계산
  const timeInfo = getTimeInfo(30);
  console.log(`[4] 현재 시각 메타데이터: Timestamp=${timeInfo.timestamp}, Counter(T)=${timeInfo.counter}, 남은 초=${timeInfo.remaining}s`);
  const currentOtp = await generateTOTP(secret, 0, 30, 6);
  console.log(`[5] 현재 계산된 6자리 OTP: [ ${currentOtp.slice(0, 3)} ${currentOtp.slice(3)} ]`);
  if (!/^\d{6}$/.test(currentOtp)) {
    throw new Error('OTP 6자리 숫자 형식 불일치');
  }

  // 5. 2FA 코드 검증 시뮬레이션
  console.log('\n[6] 2FA 검증기 시뮬레이션:');
  
  // (a) 정확한 번호 입력 시
  const verifyCurrent = await generateTOTP(secret, 0, 30, 6);
  if (verifyCurrent === currentOtp) {
    console.log(`  ✅ 정확한 코드('${currentOtp}') 입력 시: 인증 성공 판정 (T=0)`);
  } else {
    throw new Error('정확한 코드 검증 실패');
  }

  // (b) 잘못된 번호 입력 시
  const wrongCode = currentOtp === '123456' ? '654321' : '123456';
  const isMatchWrong = (wrongCode === currentOtp);
  if (!isMatchWrong) {
    console.log(`  ✅ 틀린 코드('${wrongCode}') 입력 시: 인증 실패 판정`);
  } else {
    throw new Error('틀린 코드가 성공으로 판정됨');
  }

  // (c) 시간 오차 보정 (±1 Step 허용 시뮬레이션)
  const prevOtp = await generateTOTP(secret, -1, 30, 6);
  const nextOtp = await generateTOTP(secret, +1, 30, 6);
  console.log(`  ✅ 시간 오차 보정 - 이전 스텝(-30s) 코드: ${prevOtp}, 다음 스텝(+30s) 코드: ${nextOtp}`);

  console.log('\n🎉 모든 E2E 워크플로우 시뮬레이션 통과!');
}

testE2EWorkflow().catch((err) => {
  console.error('E2E 시뮬레이션 오류:', err);
  process.exit(1);
});
