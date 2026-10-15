# urltriage — 피싱 URL/도메인 위험도 탐지 CLI

URL 하나 또는 목록을 받아 **도메인 나이, 타이포스쿼팅, URL 구조, 리다이렉트, SSL 인증서, (선택) HTML 콘텐츠**를
종합해 피싱 가능성 점수(0~100)와 등급(Low / Medium / High / Critical)을 산출합니다.
항목별로 **몇 점이 왜 기여했는지**를 표로 보여 주므로, 결과를 그대로 신뢰하기보다 근거를 검토하는 용도로 설계했습니다.

> ⚠️ **방어/탐지 목적 전용 도구입니다.** 페이지를 *읽기만* 하며 스크립트 실행·폼 제출·자격증명 수집 기능은 없습니다.
> 의심 URL을 분석하면 해당 서버에 HTTP/TLS 요청이 나가므로(→ 상대가 접속 사실을 알 수 있음), 접속 자체가 부담스럽다면
> `--offline` 으로 네트워크 없이 구조·타이포스쿼팅만 검사하세요.

---

## 설치

```bash
python -m venv .venv
.venv\Scripts\activate            # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
pip install -e .                  # 'urltriage' 명령 등록 (선택, 없으면 python -m urltriage)
```

Python 3.11+ (3.14에서 개발·검증). 의존성: `rich`, `httpx`, `python-whois`, `tldextract`, `beautifulsoup4` (테스트: `pytest`).

## 사용법

```bash
urltriage -u https://example.com                          # 단일 URL
urltriage -u g00gle-login.tk -u paypa1.com                # 여러 개 (-u 반복)
urltriage -f examples/urls.txt                            # 파일 (한 줄에 하나, '#' 줄 주석)
urltriage -f urls.txt --deep --json reports/result.json   # HTML 분석 + JSON 리포트
urltriage -f urls.txt --offline --summary-only            # 네트워크 없이, 요약 표만
urltriage -f urls.txt --fail-on high                      # High 이상이 있으면 종료코드 2 (CI/메일 게이트웨이 연동)
```

| 옵션 | 설명 | 기본값 |
|---|---|---|
| `-u, --url URL` | 검사할 URL (반복 가능, 스킴 생략 시 `http://` 가정) | |
| `-f, --file FILE` | URL 목록 파일 | |
| `--deep` | HTML 콘텐츠 분석(로그인 폼·폼 전송 도메인·파비콘) 추가 | 꺼짐 |
| `--offline` | whois/SSL/리다이렉트/HTML 생략, 구조+타이포스쿼팅만 | 꺼짐 |
| `-t, --timeout SEC` | 네트워크 호출별 타임아웃 | 5 |
| `-c, --concurrency N` | 동시에 분석할 URL 수 (asyncio 세마포어) | 10 |
| `--brands JSON` | 브랜드 목록 파일 교체 | `urltriage/data/brands.json` |
| `--json PATH` | 상세 JSON 리포트 저장 | |
| `--summary-only` | 항목별 상세 표 생략 | |
| `--fail-on LEVEL` | `medium`/`high`/`critical` 이상 발견 시 종료코드 2 | |
| `--no-color` | 색상 끄기 | |

종료 코드: `0` 정상, `2` 입력 오류(argparse) 또는 `--fail-on` 기준 초과.

### 출력 예시 (요약)

```
┌───┬────────────────────────────────────────┬───────────────┬────────┬─────────────────────────────────────────────┐
│ # │ URL                                    │   점수/등급   │커버리지│ 주요 근거                                     │
├───┼────────────────────────────────────────┼───────────────┼────────┼─────────────────────────────────────────────┤
│ 1 │ https://google.com                     │    0.0 Low    │  100%  │ 특이사항 없음                                 │
│ 4 │ http://g00gle-login.tk/verify          │ 75.6 Critical │   40%  │ 타이포스쿼팅 +53.1: 도메인 토큰 'g00gle'이(가) │
│   │                                        │               │        │   브랜드 'google' (동형문자)와 일치           │
│   │                                        │               │        │ URL 구조 분석 +22.5: 악용 빈도 높은 TLD (.tk) │
└───┴────────────────────────────────────────┴───────────────┴────────┴─────────────────────────────────────────────┘
```

상세 표에는 항목마다 `상태(판정/확인불가/해당없음) · 가중치(원래 → 재정규화) · 위험도 · 기여점수 · 근거`가 표시됩니다.

---

## 채점 방식

### 1) 항목별 위험도 → 가중 평균

각 체크는 **위험도 `risk ∈ [0, 1]`** 을 냅니다. 체크 안의 개별 근거(finding)들이 위험도를 더하고 1.0에서 상한을 둡니다.

```
기본점수 = Σ (가중치ᵢ × riskᵢ) / Σ 가중치ᵢ × 100        (Σ 는 '판정'된 항목만)
```

### 2) 확인불가 → 제외 후 재정규화

whois·HTTP·TLS 호출이 **타임아웃(기본 5초)/실패**하면 그 항목은 `확인불가`로 표시되고 **분모에서 빠집니다**.
예: 도메인이 DNS에 없어 네트워크 항목이 전부 확인불가이면 타이포스쿼팅(25)과 구조(15)만으로 계산 → 각각 62.5%, 37.5%로 재정규화.

함께 표시되는 **판정 커버리지** = 판정된 가중치 / 시도한 가중치. 50% 미만이면 "결과 신뢰도 낮음" 경고가 붙습니다.
(재정규화는 강한 신호를 살리는 대신 *적은 근거로 극단적 점수*가 나올 수 있으므로, 커버리지를 함께 보세요.)

### 3) 격상 규칙 (최소 점수 보장)

가중 평균은 "확실한 신호 하나"를 희석합니다(예: 브랜드 사칭만 1.0이고 나머지 0이면 25점 → Medium).
그래서 아래 조합에는 **최소 점수(floor)** 를 적용하며, 적용 시 출력에 규칙명이 표시됩니다.

| 조건 | 최소 점수 | 근거 |
|---|---|---|
| 타이포스쿼팅 ≥ 0.85 **그리고** 도메인 나이 ≥ 0.6 (90일 미만) | 85 (Critical) | 신규 등록 + 브랜드 사칭은 피싱의 전형적 조합 |
| 브랜드 외부 전송 로그인 폼 / 브랜드 파비콘 해시 도용 (콘텐츠 ≥ 0.8) | 60 (High) | 자격증명 탈취 페이지의 직접적 특징 |
| 타이포스쿼팅 ≥ 0.6 **그리고** 인증서 불일치/자체서명 (SSL ≥ 0.8) | 70 (High) | |
| 30일 미만 도메인 **그리고** URL 구조 ≥ 0.5 | 60 (High) | |
| 타이포스쿼팅 ≥ 0.85 (단독) | 55 (High) | 유명 브랜드와 거의 동일한 도메인은 단독으로도 고위험 |

### 4) 교차 보정: 방어적 등록

브랜드 유사 도메인이 **그 브랜드의 공식 도메인으로 리다이렉트**되면(예: `gooogle.com → google.com`),
브랜드가 오타 도메인을 선점한 것으로 보고 타이포스쿼팅 위험도를 80% 감산합니다. 실제로 `gooogle.com`은 이 보정으로 18.0점(Low, `--deep`)이 됩니다.

### 5) 등급

| 점수 | 등급 | 권장 대응 |
|---|---|---|
| 0 – 24.9 | **Low** | 특이 신호 없음 |
| 25 – 49.9 | **Medium** | 근거 확인 후 판단 |
| 50 – 74.9 | **High** | 클릭/입력 금지, 추가 조사 |
| 75 – 100 | **Critical** | 차단 권고 |

---

## 전체 채점 기준표

### 가중치와 근거

| 항목 | 키 | 가중치 | 왜 이 가중치인가 |
|---|---|---:|---|
| 타이포스쿼팅 | `typosquat` | **25** | 피싱의 본질은 *신뢰받는 브랜드 사칭*. 공식 도메인 목록과 비교하므로 오탐이 적고 신호가 강함 |
| 도메인 나이 | `domain_age` | **25** | 피싱 도메인의 상당수는 등록 후 며칠 안에 사용·폐기됨(APWG·Interisle 등 보고서에서 반복 관찰). 오래된 도메인은 탈취된 경우가 아니면 드묾 |
| URL 구조 | `structure` | 15 | 개별 휴리스틱(길이, 하이픈 등)은 약하고 정상 URL에서도 흔하지만, 여러 개가 겹치면 의미 있음. 네트워크 없이 항상 판정 가능 |
| HTML 콘텐츠 | `content` | 12 | 외부로 전송되는 비밀번호 폼은 매우 강한 신호지만 `--deep`에서만 실행되고, 클로킹(봇에겐 정상 페이지 표시)으로 회피되기 쉬움 |
| 리다이렉트 | `redirects` | 10 | 단축 URL·다단계 리다이렉트는 목적지 은닉에 쓰이지만 광고/로그인 흐름 등 정상 사용도 많음 |
| SSL 인증서 유효성 | `ssl` | 10 | 인증서 오류(불일치·자체서명·만료)는 강한 신호. 반대로 **유효한 인증서는 안전의 증거가 아님**(피싱 사이트 대부분도 HTTPS) → 감점 요인으로만 사용 |
| 인증서 발급기관 | `ssl_issuer` | **3** | Let's Encrypt 등 무료 CA는 피싱에 흔하지만 **정상 사이트 대다수도 사용**(예: naver.com). 단독으로는 거의 의미 없으므로 최소 가중치 |
| **합계** | | **100** | `--deep` 미사용 시 콘텐츠 12를 뺀 88 기준으로 재정규화 |

### 1. 도메인 나이 (`domain_age`, 25)

`python-whois`로 생성일 조회 → 실패/생성일 없음이면 **RDAP(rdap.org, JSON)로 재조회** → 둘 다 실패하면 확인불가.

| 도메인 나이 | 위험도 |
|---|---:|
| 30일 미만 | **1.0** |
| 30 – 89일 | 0.6 |
| 90 – 179일 | 0.4 |
| 180 – 364일 | 0.2 |
| 1년 이상 | 0 |

IP 주소 호스트는 `해당없음`. 미등록 도메인은 "확인불가"(조회 실패 사유에 `등록 정보 없음` 표시).

### 2. 타이포스쿼팅 (`typosquat`, 25)

브랜드 목록: [`urltriage/data/brands.json`](urltriage/data/brands.json) (google, naver, kakao, paypal, apple, microsoft, amazon, coupang, toss, upbit 등 20개).
`name`(비교 레이블) + `domains`(공식 등록 도메인) + 선택적 `favicon_sha256`. 항목 추가만으로 확장되고 `--brands`로 교체 가능.

비교 방법:
- **레벤슈타인 거리**(삽입/삭제/치환) + **OSA 거리**(인접 문자 교환 `goolge`도 1로 계산)
- **동형문자 정규화**: `0→o, 1→l/i, 3→e, 5→s, rn→m, vv→w`, 키릴/그리스 문자→라틴, 퓨니코드 디코딩
- 짧은 브랜드명은 오탐이 많으므로 허용 거리를 제한: 3자 이하 0, 4–6자 1, 7자 이상 2

| 패턴 | 예시 | 위험도 |
|---|---|---:|
| 공식 도메인 (서브도메인 포함) | `mail.google.com` | 0 |
| 동형문자 치환 시 브랜드와 동일 | `paypa1.com`, `rnicrosoft.com`, `аpple.com`(키릴) | **1.0** |
| 편집 거리 1 | `gooogle.com`, `goolge.com`, `naevr.com` | 0.9 |
| 편집 거리 2 (7자 이상 브랜드) | `micorsfot.com` | 0.6 |
| 도메인 토큰이 브랜드와 일치 (콤보스쿼팅) | `g00gle-login.tk`, `kakao-pay-event.xyz` | 0.85 |
| 서브도메인에 공식 도메인 삽입 | `paypal.com.secure-check.tk` | 0.85 |
| `@` 앞에 브랜드 위장 | `https://www.paypal.com@evil.tk/` | 0.85 |
| 도메인 토큰이 브랜드와 거리 1 | `paypai-login.com` | 0.75 |
| 브랜드명을 비공식 TLD에서 사용 | `google.tk` | 0.7 |
| 서브도메인 토큰이 브랜드와 일치 | `paypal.evil.tk` | 0.7 |
| 하이픈 없이 브랜드 포함 (6자 이상 브랜드만) | `paypalsecure.net` | 0.6 |
| 경로에 브랜드명 | `example.com/naver/login` | 0.3 |

가장 높은 매칭 1개만 점수에 반영하고, 나머지는 근거로만 기록합니다.

### 3. URL 구조 분석 (`structure`, 15)

네트워크 없이 항상 판정. 근거들의 위험도를 더하고 1.0 상한.

| 휴리스틱 | 위험도 | 비고 |
|---|---:|---|
| 도메인 대신 IP 주소 | 0.6 | 10진수(`3232235777`)·16진수(`0xC0.0xA8.0.1`) 난독화 표기도 인식 |
| `@` 포함 (userinfo) | 0.5 | 브라우저는 `@` 앞을 무시 → `paypal.com@evil.tk`는 evil.tk로 접속 |
| 서브도메인 4단계 이상 / 3단계 | 0.35 / 0.2 | `secure.login.account.verify.x.tk` |
| 퓨니코드(`xn--`) | 0.3 | IDN 동형문자 공격 |
| 등록 도메인 하이픈 2개 이상 / 1개 | 0.25 / 0.1 | 퓨니코드 구분자는 제외하고 셈 |
| 비표준 포트 | 0.25 | 80/443 외 |
| 민감 키워드 (login, verify, secure, account, update, webscr …) | 0.1 × 개수 (최대 0.25) | |
| URL 길이 > 100 / > 75 | 0.2 / 0.1 | |
| 악용 빈도 높은 TLD (.tk .ml .ga .cf .gq .xyz .top .zip …) | 0.2 | |
| 호스트에 퍼센트 인코딩 | 0.2 | |
| URL 단축 서비스 | 0.15 | 목적지는 리다이렉트 체크가 추적 |
| 호스트 전체 하이픈 4개 이상 | 0.15 | |
| `http://` 명시 / 경로에 `//` / 경로·쿼리에 `@` | 0.1 | |

### 4. 리다이렉트 체인 (`redirects`, 10)

httpx로 **한 단계씩 직접** 따라가며(최대 10회, 헤더만 읽음) 체인을 기록합니다.

| 신호 | 위험도 |
|---|---:|
| 최종 목적지 등록 도메인이 다름 (같은 브랜드 공식 도메인 간 이동은 제외) | 0.4 (단축 URL 출발은 0.2) |
| └ 최종 도메인이 브랜드 사칭 (타이포스쿼팅 재검사) | + 0.8 × 그 위험도 |
| 리다이렉트 6회 이상 / 3–5회 | 0.4 / 0.2 |
| 10회 초과(루프) | 0.6 |
| 최종 목적지가 IP | 0.5 |
| HTTPS → HTTP 다운그레이드 | 0.3 |

### 5. SSL 인증서 (`ssl` 10 + `ssl_issuer` 3)

시스템 신뢰 저장소로 TLS 핸드셰이크(호스트명 검증 포함) 후 인증서를 확인합니다.

| `ssl` 신호 | 위험도 |
|---|---:|
| 인증서 도메인 불일치 / 폐기 | 0.9 |
| 자체 서명 | 0.8 |
| 만료 / 신뢰할 수 없는 발급기관 | 0.7 |
| HTTPS 연결 거부(암호화 미제공) | 0.6 |
| 기타 검증 실패 / 핸드셰이크 실패 | 0.5–0.6 |
| 유효 | 0 |

| `ssl_issuer` 신호 | 위험도 | 실제 영향 |
|---|---:|---|
| 무료 자동발급 CA (Let's Encrypt, ZeroSSL, Buypass, cPanel) | 0.6 | 가중치 3 × 0.6 → **약 2점** |
| 발급 7일 이내 인증서 | 0.4 | |

### 6. HTML 콘텐츠 (`content`, 12, `--deep` 전용)

최종 목적지 HTML을 최대 2MB까지 받아 **파싱만** 합니다.

| 신호 | 위험도 |
|---|---:|
| 비밀번호 폼이 외부 도메인으로 전송 (같은 브랜드 공식 도메인 간은 제외) | **0.8** |
| 파비콘 SHA-256이 브랜드 공식 파비콘과 동일한데 도메인은 다름 | **0.8** |
| 파비콘을 브랜드 공식 도메인에서 직접 가져옴 (핫링크) | 0.7 |
| 폼이 `mailto:`로 전송 | 0.5 |
| HTTPS 페이지의 비밀번호 폼이 평문 HTTP로 전송 | 0.3 |
| `<title>`에 브랜드명 + 비공식 도메인 | 0.2 |
| 로그인(비밀번호) 폼 존재 (비공식 도메인) | 0.15 |
| 비밀번호 없는 폼이 외부 도메인으로 전송 | 0.15 |

브랜드 파비콘 해시는 공식 사이트에서 수집합니다(공식 도메인에만 접속):

```bash
python -m urltriage.favicons            # brands.json 의 favicon_sha256 갱신
```

---

## JSON 리포트

`--json PATH`로 저장. 구조:

```jsonc
{
  "tool": "urltriage", "version": "0.1.0", "generated_at": "2026-10-15T...",
  "options": {"timeout": 5.0, "deep": true, "offline": false, "concurrency": 10},
  "scoring": {"weights": {...}, "grades": {"Critical": 75, "High": 50, "Medium": 25, "Low": 0}},
  "summary": {"Critical": 4, "High": 1, "Medium": 0, "Low": 3, "error": 0},
  "results": [{
    "input": "http://g00gle-login.tk/verify", "registered_domain": "g00gle-login.tk",
    "score": 75.6, "grade": "Critical", "base_score": 75.6, "coverage": 0.4,
    "contributions": {"typosquat": 53.12, "structure": 22.5},
    "effective_weights": {"typosquat": 62.5, "structure": 37.5},
    "excluded": {"domain_age": "whois: 타임아웃(5초); rdap: ...", "ssl": "DNS 해석 실패 ..."},
    "escalations": [],
    "checks": {"typosquat": {"status": "ok", "risk": 0.85, "findings": [...], "data": {"matches": [...]}}, ...}
  }]
}
```

---

## 검증 결과

`examples/urls.txt` (안전한 사이트 3개 + 브랜드 방어 도메인 1개 + **DNS 미해석을 사전 확인한** 더미 피싱 패턴 5개), `--deep`:

| URL | 점수 | 등급 | 커버리지 | 주요 기여 |
|---|---:|---|---:|---|
| `https://google.com` | 0.0 | Low | 100% | – (1997년 생성, 유효 인증서) |
| `https://github.com/login` | 1.5 | Low | 100% | 구조 +1.5 (`login` 키워드). 로그인 폼은 자기 도메인 전송이라 감점 없음 |
| `https://www.naver.com` | 0.0 | Low | 100% | – |
| `gooogle.com` *(Google 소유 방어 도메인)* | 18.0 | Low | 97% | 방어적 등록 보정으로 타이포 0.9→0.18 (기여 +4.6), 443 인증서 불일치 +9.3 |
| `http://g00gle-login.tk/verify` | 75.6 | Critical | 40% | 타이포 +53.1, 구조 +22.5 |
| `https://paypa1-secure-verify.xyz/login` | 79.4 | Critical | 40% | 타이포 +53.1, 구조 +26.2 |
| `https://www.paypal.com@secure-check.tk/signin` | 90.6 | Critical | 40% | 타이포(`@` 위장) +53.1, 구조 +37.5 |
| `https://secure.login.account.verify.g00gle-login.tk/update` | 86.9 | Critical | 40% | 타이포 +53.1, 구조 +33.8 |
| `https://kakao-pay-event-2026.xyz` | 70.0 | High | 40% | 타이포 +53.1, 구조 +16.9 |

더미 도메인은 실제로 존재하지 않으므로 whois/SSL/리다이렉트/HTML은 확인불가 → 재정규화됨(커버리지 40%).

## 테스트

```bash
pytest                    # 오프라인 테스트 (네트워크 불필요, mock 사용)
pytest -m network         # 실제 접속 테스트: google.com whois/SSL, badssl.com 인증서 오류, bit.ly 리다이렉트
```

- 실제 피싱 사이트에는 접속하지 않습니다. 네트워크 테스트 대상은 google.com, `*.badssl.com`(인증서 오류 테스트용 공개 서비스), `bit.ly` 루트(→ bitly.com)뿐입니다.
- HTML 분석 테스트는 서버 없이 **최소 HTML 문자열**로 하며, 폼 action은 RFC 2606 예약 도메인(`.example`)만 사용합니다.
- whois 실패는 mock으로 재현합니다(타임아웃 → 확인불가, 예외 → RDAP 대체, 모두 실패 → 확인불가).

## 프로젝트 구조

```
urltriage/
├── cli.py            # argparse CLI, 진행 표시, 종료 코드
├── analyzer.py       # URL별 파이프라인 (asyncio 동시 실행, 교차 보정, 점수 산출)
├── scoring.py        # 가중치, 재정규화, 격상 규칙, 등급
├── report.py         # rich 표 / JSON 리포트
├── models.py         # CheckResult / Finding / Status
├── urlutils.py       # URL 파싱, 등록 도메인 추출(tldextract, 내장 PSL 스냅샷 → 오프라인 동작)
├── net.py            # DNS 해석, httpx 클라이언트
├── favicons.py       # 브랜드 파비콘 해시 수집기
├── data/brands.json  # 브랜드 목록 (확장 가능)
└── checks/
    ├── structure.py  ├── typosquat.py  ├── domain_age.py
    ├── ssl_cert.py   ├── redirects.py  └── content.py
```

## 한계

- **클로킹**: 피싱 키트는 봇/특정 국가/User-Agent에게 정상 페이지를 보여 줄 수 있어 `--deep` 결과가 깨끗할 수 있습니다.
- **탈취된 정상 도메인**: 오래된 도메인이 해킹되어 피싱에 쓰이면 도메인 나이·타이포 신호가 0입니다(구조·콘텐츠 신호에 의존).
- **브랜드 목록 밖**은 타이포스쿼팅을 탐지하지 못합니다 → 조직에 맞게 `brands.json`을 확장하세요.
- whois는 TLD마다 형식이 달라 생성일이 비어 있을 수 있습니다(RDAP 대체 조회로 보완).
- 단순 휴리스틱 + 고정 가중치 모델이며, 학습 기반 분류기나 위협 인텔리전스(블랙리스트) 조회를 대체하지 않습니다.
