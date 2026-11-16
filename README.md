# 모바일 OTP — RFC 6238 표준 기반 TOTP 2FA 체험 스튜디오 (`26-w11-mobile-otp`)

> 브라우저 내장 Web Crypto API만을 활용하여 외부 네트워크 통신 없이(Zero-Transmission) RFC 6238 표준 TOTP를 발급, QR 스캔 연동, 실시간 동기화 및 2FA 검증까지 완결하는 2단 반응형 보안 체험 스튜디오입니다.

---

## 🌟 프로젝트 소개
스마트폰의 Google Authenticator, Microsoft Authenticator, 2FAS와 동일한 규격(RFC 6238 / RFC 4648)으로 작동하는 모바일 OTP 2단계 인증 대시보드입니다.
- **좌측 패널 (Service Issuer)**: 160-bit 암호학적 난수 비밀 키 발급, 계정 정보(Issuer, Account) 수정 시 실시간 QR 코드 및 `otpauth://` URI 갱신
- **우측 패널 (Authenticator & Verifier)**: 30초 카운트다운 타이머 게이지, 대형 6자리 실시간 OTP 디스플레이, 2단계 인증 코드 검증기 (±1 Step 시간 오차 보정 지원)
- **표준 테스트 벡터 자가진단 (Self-Test)**: 브라우저 내부에서 RFC 6238 공식 Appendix B 테스트 벡터 6종을 즉시 검증하는 진단 도구 탑재

---

## 🧭 나의 AI 기획·구현 과정

1. **AI 협업 방식**:
   - **Antigravity IDE Implementation Plan 기반 대화형 설계**: 구현에 앞서 `/plan` 커맨드를 통해 Web Crypto API 기반 무전송 아키텍처, 64-bit Big-Endian 카운터 버퍼 연산, Dynamic Truncation 알고리즘, 로컬 QR 라이브러리 탑재 계획을 수립하고 승인받은 후 체계적으로 개발을 진행했습니다.
2. **화면과 상태 흐름 구상**:
   - 사용자가 처음 접속했을 때 빈 화면이 아닌 기본 계정(`Polytech-Sec`, `yr@security.kr`)과 160-bit 비밀 키, QR 코드, 실시간 OTP가 즉시 활성화되도록 구성했습니다.
   - 좌우 2단 카드 분할 레이아웃으로 발급자(서버) 역할과 검증자(인증기) 역할을 한눈에 비교할 수 있도록 설계했습니다.
3. **가장 막혔던 문제와 해결 과정 (스마트폰 앱 연동 디버깅 경험)**:
   - **스마트폰 Authenticator(Google/Microsoft) 연동 시 Base32 패딩 문제**:
     - 초기 Base32 인코딩 시 표준 패딩 문자(`=`)가 포함되어 있으면 Google Authenticator 앱에서 "비밀 키 형식이 올바르지 않습니다"라며 스캔 등록에 실패하거나 다른 OTP를 생성하는 문제가 있었습니다.
     - RFC 4648 명세와 Google Authenticator 호환성 표준을 분석하여, 160비트(20바이트) 난수를 5비트씩 분할하면 정확히 32글자로 떨어지므로 패딩 문자(`=`)를 완전히 제거(`replace(/=+$/, '')`)하여 전송하도록 수정함으로써 상용 Authenticator 앱과의 100% 호환성을 확보했습니다.
   - **Zero-Transmission 원칙 준수**:
     - 외부 QR 코드 생성 API(`qrserver` 등)를 호출하면 비밀 키가 외부 서버로 전송되는 치명적인 보안 취약점이 발생합니다. 이를 방지하기 위해 로컬 `public/qrcode.min.js`를 번들링하여 브라우저의 `<canvas>`/`<div>`에 직접 렌더링하도록 구현함으로써 Network 탭 외부 요청 0건을 달성했습니다.
   - **RFC 6238 64-bit Big-Endian 카운터 및 시간 오차(Time Drift) 보정**:
     - JavaScript의 기본 비트 연산자는 32비트 정수로 동작하므로 카운터 오버플로를 방지하기 위해 `ArrayBuffer(8)`과 `DataView.setBigUint64(0, BigInt(counter), false)`를 적용하여 RFC 명세와 정확히 일치시켰습니다.
     - PC 브라우저 시계와 사용자의 스마트폰 단말 시계 사이에 몇 초간의 미세 오차가 있을 때 인증이 실패하는 UX 문제를 해결하기 위해, RFC 권장 표준인 `±1 Step(앞뒤 30초 오차 보정)` 옵션을 추가하여 $T-1, T, T+1$ 스텝을 모두 검증할 수 있도록 구현했습니다.

---

## 🛡️ TOTP 원리 및 보안 점검 (사이버보안과 체크포인트)

### 1. 비밀 키 생성 시 `Math.random()` 대신 `crypto.getRandomValues()`를 사용해야 하는 이유
- `Math.random()`은 의사난수 생성기(PRNG)로 내부 시드(seed)나 이전 생성값을 바탕으로 다음 난수가 예측 가능하여 브루트포스나 시드 역추적으로 비밀 키가 탈취될 수 있습니다.
- 반면 `window.crypto.getRandomValues()`는 운영체제의 엔트로피 풀(하드웨어 인터럽트, 열잡음 등)을 이용하는 암호학적 의사난수 생성기(CSPRNG)이므로 예측이 불가능하여 암호화 키 생성에 필수적입니다.

### 2. 브라우저 내 연산(Web Crypto API / SubtleCrypto)의 보안상 이점 및 Network 탭 점검 결과
- 비밀 키와 OTP 번호가 외부 서버나 서드파티 API로 전송되지 않고 브라우저 클라이언트 메모리 내부에서만 HMAC-SHA1 연산 및 동적 절단이 이루어집니다.
- **Network 탭 점검 결과**: 개발자 도구(`F12`)의 Network 탭에서 비밀 키 생성, QR 코드 렌더링, OTP 계산, 코드 검증 전 과정 동안 외부 API 서버 호출이 **0건**임을 확인했습니다.
- **메모리 기반 보안**: XSS 공격 시 스토리지 덤프 탈취를 원천 차단하기 위해 `localStorage` / `sessionStorage`에 비밀 키를 저장하지 않고 JavaScript 클로저 상태 변수로만 격리 관리합니다.

### 3. 스마트폰 Authenticator 앱 연동 결과
- 모바일 Google Authenticator / Microsoft Authenticator / 2FAS 앱으로 화면의 QR 코드를 스캔한 즉시 계정이 등록되었으며, 스마트폰에 표시되는 6자리 번호와 웹 대시보드 우측 패널의 6자리 번호가 30초 주기로 완벽히 일치함을 확인했습니다.

---

## 🚀 실행 및 배포 링크

- **로컬 실행**:
  ```bash
  npm install
  npm run dev
  ```
- **테스트 및 검증**:
  ```bash
  npm test
  npm run lint
  npm run build
  ```
- **배포 링크**:
  - Netlify 배포 URL: *(배포 후 입력)*
  - GitHub Pages 배포 URL: *(배포 후 입력)*

---

## 💡 나만의 확장 기능
1. **RFC 6238 공식 테스트 벡터 브라우저 자가진단 (Self-Test)**:
   - 상단 `[🧪 표준 벡터 자가진단]` 버튼을 누르면 RFC 6238 Appendix B 공식 테스트 벡터(Time=59s, 1111111109s, 1234567890s 등 6개 시점)를 `crypto.subtle`로 즉시 계산하여 100% 일치 여부를 모달 다이얼로그로 시각화합니다.
2. **시간 오차 보정 (±1 Step 허용 토글)**:
   - 클라이언트 PC와 스마트폰 기기간의 미세한 시간 차이(최대 30초)를 보정할 수 있도록 $T-1, T, T+1$ 스텝을 검증하여 어떤 스텝에서 일치했는지 상세 사유(예: "이전 스텝 일치")를 피드백합니다.
3. **5초 이하 카운트다운 비상 시각 경고**:
   - 30초 주기 중 만료 5초 전부터 프로그레스 바와 초 표시 뱃지가 크림슨 레드 펄스 애니메이션으로 전환되어 사용자에게 직관적인 갱신 안내를 제공합니다.
4. **원클릭 클립보드 복사 및 토스트 알림**:
   - 비밀 키와 `otpauth://` URI를 원클릭으로 클립보드에 복사할 수 있는 편의 기능을 제공합니다.
