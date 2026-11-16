/**
 * RFC 6238 모바일 OTP 2FA 체험 스튜디오 메인 애플리케이션 모듈
 * 
 * [핵심 보안 원칙]
 * 1. Zero-Transmission: 외부 네트워크 통신 일절 없음 (전부 로컬 클라이언트 연산)
 * 2. Math.random() 사용 금지: window.crypto.getRandomValues() 사용
 * 3. 스토리지 비저장: 비밀 키는 오직 JS 메모리 변수(state)에만 보관
 */

import {
  generateSecret,
  generateTOTP,
  getTimeInfo,
  generateOtpAuthUri,
} from './utils/totp.js';

// ============================================================================
// 애플리케이션 상태 (JavaScript 메모리 전용, 스토리지 미저장)
// ============================================================================
const state = {
  issuer: 'Polytech-Sec',
  account: 'yr@security.kr',
  secret: '', // Base32 Secret Key (160비트 암호학적 난수)
  currentOtp: '000000',
  qrCodeInstance: null,
  lastCalculatedCounter: null,
};

// ============================================================================
// DOM 요소 캐싱
// ============================================================================
const elements = {
  inputIssuer: document.getElementById('input-issuer'),
  inputAccount: document.getElementById('input-account'),
  displaySecret: document.getElementById('display-secret'),
  btnCopySecret: document.getElementById('btn-copy-secret'),
  btnGenerateSecret: document.getElementById('btn-generate-secret'),
  qrcodeBox: document.getElementById('qrcode-box'),
  displayUri: document.getElementById('display-uri'),
  btnCopyUri: document.getElementById('btn-copy-uri'),
  
  otpCodeDisplay: document.getElementById('otp-code-display'),
  timerSecondsBadge: document.getElementById('timer-seconds-badge'),
  timerProgressBar: document.getElementById('timer-progress-bar'),
  debugTimestamp: document.getElementById('debug-timestamp'),
  debugCounter: document.getElementById('debug-counter'),
  
  formVerify: document.getElementById('form-verify'),
  inputVerifyCode: document.getElementById('input-verify-code'),
  btnVerify: document.getElementById('btn-verify'),
  checkTimeDrift: document.getElementById('check-time-drift'),
  resultBox: document.getElementById('verification-result-box'),
  resultBadge: document.getElementById('result-badge'),
  resultIcon: document.getElementById('result-icon'),
  resultStatus: document.getElementById('result-status'),
  resultDetail: document.getElementById('result-detail'),
  
  toast: document.getElementById('toast'),
  btnSelfTest: document.getElementById('btn-self-test'),
  modalSelfTest: document.getElementById('modal-self-test'),
  btnCloseModal: document.getElementById('btn-close-modal'),
  btnConfirmModal: document.getElementById('btn-confirm-modal'),
  btnRunSelfTestAgain: document.getElementById('btn-run-self-test-again'),
  selfTestResults: document.getElementById('self-test-results'),
};

// ============================================================================
// 유틸리티 함수: 토스트 알림
// ============================================================================
let toastTimeout = null;
function showToast(message, duration = 2500) {
  if (!elements.toast) return;
  elements.toast.textContent = message;
  elements.toast.classList.remove('hidden');

  if (toastTimeout) clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => {
    elements.toast.classList.add('hidden');
  }, duration);
}

// ============================================================================
// QR 코드 및 URI 갱신 (로컬 qrcodejs 라이브러리 사용, 외부 API 전송 0건)
// ============================================================================
function updateQRCodeAndUri() {
  const uri = generateOtpAuthUri(state.issuer, state.account, state.secret);
  
  // URI 텍스트 박스 갱신
  if (elements.displayUri) {
    elements.displayUri.textContent = uri;
  }

  // QR 코드 렌더링
  if (elements.qrcodeBox) {
    elements.qrcodeBox.innerHTML = '';
    
    // 로컬 qrcodejs 라이브러리 (window.QRCode) 확인
    if (typeof window.QRCode !== 'undefined') {
      try {
        state.qrCodeInstance = new window.QRCode(elements.qrcodeBox, {
          text: uri,
          width: 170,
          height: 170,
          colorDark: '#0a0f1d',
          colorLight: '#ffffff',
          correctLevel: window.QRCode.CorrectLevel.M,
        });
      } catch (err) {
        console.error('QR 코드 렌더링 실패:', err);
        elements.qrcodeBox.textContent = 'QR 렌더링 오류';
      }
    } else {
      console.warn('qrcode.min.js가 아직 로드되지 않았습니다.');
      elements.qrcodeBox.textContent = 'QR 라이브러리 로드 중...';
    }
  }
}

// ============================================================================
// 실시간 OTP 렌더링 (대형 3-3 분할 폰트)
// ============================================================================
function renderOtpDisplay(otpString) {
  state.currentOtp = otpString;
  const digits = otpString.padStart(6, '0').split('');
  
  if (elements.otpCodeDisplay) {
    elements.otpCodeDisplay.innerHTML = `
      <span class="otp-digit">${digits[0]}</span>
      <span class="otp-digit">${digits[1]}</span>
      <span class="otp-digit">${digits[2]}</span>
      <span class="otp-divider"></span>
      <span class="otp-digit">${digits[3]}</span>
      <span class="otp-digit">${digits[4]}</span>
      <span class="otp-digit">${digits[5]}</span>
    `;
  }
}

// ============================================================================
// 비밀 키 재발급 및 초기화
// ============================================================================
async function regenerateSecret() {
  try {
    // 160-bit (20 Bytes) 암호학적 난수 생성 (Math.random 금지)
    state.secret = generateSecret(20);
    if (elements.displaySecret) {
      elements.displaySecret.value = state.secret;
    }

    updateQRCodeAndUri();

    // 카운터 강제 재계산 플래그 초기화 및 즉시 새 OTP 계산
    state.lastCalculatedCounter = null;
    await syncTimerAndOtp(true);

    showToast('새 160비트 비밀 키가 생성되었습니다.');
  } catch (err) {
    console.error('비밀 키 생성 오류:', err);
    showToast('비밀 키 생성 실패: ' + err.message);
  }
}

// ============================================================================
// 1초 타이머 주기 동기화 루프
// ============================================================================
async function syncTimerAndOtp(forceUpdate = false) {
  const { remaining, timestamp, counter } = getTimeInfo(30);

  // 1. 디버그 메타데이터 갱신
  if (elements.debugTimestamp) elements.debugTimestamp.textContent = timestamp.toString();
  if (elements.debugCounter) elements.debugCounter.textContent = counter.toString();

  // 2. 카운트다운 초 뱃지 갱신
  if (elements.timerSecondsBadge) {
    elements.timerSecondsBadge.textContent = `${remaining}s`;
    if (remaining <= 5) {
      elements.timerSecondsBadge.classList.add('warning');
    } else {
      elements.timerSecondsBadge.classList.remove('warning');
    }
  }

  // 3. 프로그레스 바 갱신 (30초 동안 서서히 줄어듦)
  if (elements.timerProgressBar) {
    const percentage = (remaining / 30) * 100;
    elements.timerProgressBar.style.width = `${percentage}%`;
    if (remaining <= 5) {
      elements.timerProgressBar.classList.add('warning');
    } else {
      elements.timerProgressBar.classList.remove('warning');
    }
  }

  // 4. 새로운 30초 스텝 진입 시 또는 강제 갱신 시 OTP 재계산
  if (forceUpdate || state.lastCalculatedCounter !== counter) {
    state.lastCalculatedCounter = counter;
    try {
      const newOtp = await generateTOTP(state.secret, 0, 30, 6, timestamp);
      renderOtpDisplay(newOtp);
    } catch (err) {
      console.error('OTP 계산 실패:', err);
    }
  }
}

// ============================================================================
// 2FA 코드 검증 로직
// ============================================================================
async function handleVerify(e) {
  if (e) e.preventDefault();

  const rawInput = elements.inputVerifyCode ? elements.inputVerifyCode.value : '';
  const cleanInput = rawInput.replace(/[\s-]/g, '');

  if (!cleanInput) {
    showToast('6자리 인증 번호를 입력해 주세요.');
    if (elements.inputVerifyCode) elements.inputVerifyCode.focus();
    return;
  }

  if (!/^\d{6}$/.test(cleanInput)) {
    showVerificationResult(false, '유효하지 않은 형식', '숫자 6자리를 정확히 입력해 주세요.');
    return;
  }

  const allowDrift = elements.checkTimeDrift ? elements.checkTimeDrift.checked : true;
  const now = Math.floor(Date.now() / 1000);

  try {
    // 1. 현재 스텝(Offset 0) 검증
    const currentStepOtp = await generateTOTP(state.secret, 0, 30, 6, now);
    if (cleanInput === currentStepOtp) {
      showVerificationResult(
        true,
        '인증 성공 ✅',
        '현재 시간 스텝(T=0)과 정확히 일치합니다.'
      );
      return;
    }

    // 2. 시간 오차(±1 Step) 허용 시 이전/다음 스텝 검증
    if (allowDrift) {
      const prevStepOtp = await generateTOTP(state.secret, -1, 30, 6, now);
      if (cleanInput === prevStepOtp) {
        showVerificationResult(
          true,
          '인증 성공 ✅ (이전 스텝 일치)',
          '클라이언트/단말 시간 차이로 이전 스텝(T-1, -30초) 코드와 일치합니다.'
        );
        return;
      }

      const nextStepOtp = await generateTOTP(state.secret, +1, 30, 6, now);
      if (cleanInput === nextStepOtp) {
        showVerificationResult(
          true,
          '인증 성공 ✅ (다음 스텝 일치)',
          '클라이언트/단말 시간 차이로 다음 스텝(T+1, +30초) 코드와 일치합니다.'
        );
        return;
      }
    }

    // 일치하지 않음
    showVerificationResult(
      false,
      '인증 실패 ❌',
      '입력한 코드가 서버의 예상 OTP와 일치하지 않습니다. 비밀 키나 시간 동기화를 확인하세요.'
    );
  } catch (err) {
    console.error('검증 중 오류:', err);
    showVerificationResult(false, '검증 오류 발생', err.message);
  }
}

function showVerificationResult(isSuccess, statusText, detailText) {
  if (!elements.resultBox) return;

  elements.resultBox.classList.remove('hidden');
  
  if (isSuccess) {
    elements.resultBadge.className = 'result-badge success';
    elements.resultIcon.textContent = '✅';
  } else {
    elements.resultBadge.className = 'result-badge error';
    elements.resultIcon.textContent = '❌';
  }

  elements.resultStatus.textContent = statusText;
  elements.resultDetail.textContent = detailText;
}

// ============================================================================
// RFC 6238 공식 테스트 벡터 브라우저 내 자가진단
// ============================================================================
async function runSelfTestInBrowser() {
  if (!elements.selfTestResults) return;
  elements.selfTestResults.innerHTML = '<div class="test-row">⏳ 테스트 실행 중...</div>';

  const testSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  const testVectors = [
    { time: 59, expected: '287082', counter: 1 },
    { time: 1111111109, expected: '081804', counter: 37037036 },
    { time: 1111111111, expected: '050471', counter: 37037037 },
    { time: 1234567890, expected: '005924', counter: 41152263 },
    { time: 2000000000, expected: '279037', counter: 66666666 },
    { time: 20000000000, expected: '353130', counter: 666666666 },
  ];

  const resultsHtml = [];
  let allPass = true;

  for (const tv of testVectors) {
    try {
      const calculated = await generateTOTP(testSecret, 0, 30, 6, tv.time);
      const isPass = calculated === tv.expected;
      if (!isPass) allPass = false;

      resultsHtml.push(`
        <div class="test-row ${isPass ? 'pass' : 'fail'}">
          <div>
            <strong>Time: ${tv.time}s</strong> (T=${tv.counter})<br/>
            <small>계산값: ${calculated} · 기대값: ${tv.expected}</small>
          </div>
          <div>${isPass ? '✅ PASS' : '❌ FAIL'}</div>
        </div>
      `);
    } catch (err) {
      allPass = false;
      resultsHtml.push(`
        <div class="test-row fail">
          <div>Time: ${tv.time}s - 에러: ${err.message}</div>
          <div>❌ FAIL</div>
        </div>
      `);
    }
  }

  resultsHtml.unshift(`
    <div style="font-weight: 700; margin-bottom: 0.5rem; color: ${allPass ? 'var(--success)' : 'var(--danger)'}">
      ${allPass ? '🎉 모든 RFC 6238 공식 테스트 벡터 100% 통과!' : '⚠️ 일부 테스트 벡터 불일치'}
    </div>
  `);

  elements.selfTestResults.innerHTML = resultsHtml.join('');
}

// ============================================================================
// 이벤트 리스너 등록
// ============================================================================
function setupEventListeners() {
  // 발급자 변경
  if (elements.inputIssuer) {
    elements.inputIssuer.addEventListener('input', (e) => {
      state.issuer = e.target.value.trim() || 'Service';
      updateQRCodeAndUri();
    });
  }

  // 계정명 변경
  if (elements.inputAccount) {
    elements.inputAccount.addEventListener('input', (e) => {
      state.account = e.target.value.trim() || 'user';
      updateQRCodeAndUri();
    });
  }

  // 새 비밀 키 생성
  if (elements.btnGenerateSecret) {
    elements.btnGenerateSecret.addEventListener('click', () => {
      regenerateSecret();
    });
  }

  // 비밀 키 복사
  if (elements.btnCopySecret) {
    elements.btnCopySecret.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(state.secret);
        showToast('비밀 키가 클립보드에 복사되었습니다.');
      } catch {
        showToast('클립보드 접근 권한이 없습니다.');
      }
    });
  }

  // URI 복사 (버튼 및 박스 클릭)
  const copyUriHandler = async () => {
    const uri = generateOtpAuthUri(state.issuer, state.account, state.secret);
    try {
      await navigator.clipboard.writeText(uri);
      showToast('otpauth:// URI가 클립보드에 복사되었습니다.');
    } catch {
      showToast('클립보드 복사 실패');
    }
  };
  if (elements.btnCopyUri) elements.btnCopyUri.addEventListener('click', copyUriHandler);
  if (elements.displayUri) elements.displayUri.addEventListener('click', copyUriHandler);

  // 코드 검증 폼 제출
  if (elements.formVerify) {
    elements.formVerify.addEventListener('submit', handleVerify);
  }
  if (elements.btnVerify) {
    elements.btnVerify.addEventListener('click', handleVerify);
  }

  // 6자리 숫자 입력창 편의 기능 (숫자만 허용, 6자리 입력 시 자동 서브밋 고려)
  if (elements.inputVerifyCode) {
    elements.inputVerifyCode.addEventListener('input', (e) => {
      // 숫자 및 공백, 하이픈만 허용
      e.target.value = e.target.value.replace(/[^\d\s-]/g, '');
      const digitsOnly = e.target.value.replace(/[\s-]/g, '');
      if (digitsOnly.length === 6) {
        // 6자리 다 채우면 이전 결과 박스 숨기기
        if (elements.resultBox) elements.resultBox.classList.add('hidden');
      }
    });

    elements.inputVerifyCode.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleVerify();
      }
    });
  }

  // 자가진단 모달
  if (elements.btnSelfTest) {
    elements.btnSelfTest.addEventListener('click', () => {
      if (elements.modalSelfTest) {
        elements.modalSelfTest.showModal();
        runSelfTestInBrowser();
      }
    });
  }
  if (elements.btnCloseModal) {
    elements.btnCloseModal.addEventListener('click', () => {
      if (elements.modalSelfTest) elements.modalSelfTest.close();
    });
  }
  if (elements.btnConfirmModal) {
    elements.btnConfirmModal.addEventListener('click', () => {
      if (elements.modalSelfTest) elements.modalSelfTest.close();
    });
  }
  if (elements.btnRunSelfTestAgain) {
    elements.btnRunSelfTestAgain.addEventListener('click', () => {
      runSelfTestInBrowser();
    });
  }
}

// ============================================================================
// 애플리케이션 초기화 (초기 로드 시 즉시 활성화)
// ============================================================================
async function init() {
  setupEventListeners();

  // 1. 초기 비밀 키 생성 (160-bit Base32)
  state.secret = generateSecret(20);
  if (elements.displaySecret) {
    elements.displaySecret.value = state.secret;
  }

  // 2. QR 코드 및 URI 최초 렌더링
  updateQRCodeAndUri();

  // 3. 타이머 즉시 동기화 및 1초 주기 타이머 시작
  await syncTimerAndOtp(true);
  setInterval(syncTimerAndOtp, 1000);

  console.log('🛡️ 모바일 OTP 2FA 체험 스튜디오가 초기화되었습니다. (Zero-Transmission 활성화)');
}

// DOM 준비 완료 시 실행
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}

