# Security Testing Documentation

## 1. How to Run Security Scans

### 1.1 Static Application Security Testing (SAST)
- **Tool:** SonarQube
- **Steps:**
    1. Jalankan SonarQube server (`docker-compose up -d` atau via CLI).
    2. Tambahkan file `sonar-project.properties` pada root project.
    3. Jalankan perintah:
       ```bash
       sonar-scanner
       ```
    4. Buka dashboard SonarQube untuk melihat hasil analisis kode.

### 1.2 Software Composition Analysis (SCA)
- **Tool:** Trivy
- **Steps:**
    1. Scan dependency untuk mendeteksi library rentan:
       ```bash
       trivy fs .
       ```
    2. Scan container image:
       ```bash
       trivy image nama-image:tag
       ```
    3. Export hasil ke JSON/HTML jika perlu dokumentasi:
       ```bash
       trivy fs --format json --output report.json .
       ```

### 1.3 Dynamic Application Security Testing (DAST)
- **Tool:** OWASP ZAP
- **Steps:**
    1. Jalankan OWASP ZAP via Docker:
       ```bash
       docker run -u zap -p 8080:8080 -i owasp/zap2docker-stable zap.sh -daemon -port 8080 -host 0.0.0.0
       ```
    2. Gunakan mode active scan:
       ```bash
       zap-cli quick-scan --self-contained http://localhost:3000
       ```
    3. Export hasil scan ke report HTML:
       ```bash
       zap-cli report -o zap_report.html -f html
       ```

---

## 2. How to Interpret the Results

- **SAST (SonarQube)**
    - *Bugs:* Potensi error dalam kode.
    - *Vulnerabilities:* Masalah keamanan (e.g., SQL Injection).
    - *Code Smells:* Praktik coding yang buruk.

- **SCA (Trivy)**
    - *Severity Levels:* Critical / High / Medium / Low.
    - *Check CVE IDs:* Pastikan update ke versi patch terbaru.

- **DAST (OWASP ZAP)**
    - *Alerts:* Menampilkan temuan berdasarkan tingkat severity.
    - *Example:* Reflected XSS, SQLi, Insecure Headers.
    - *Action:* Cross-check apakah false positive, lalu tentukan fix.

---

## 3. Security Best Practices Followed

- **Coding Practices**
    - Input validation & sanitization.
    - Gunakan parameterized queries untuk database.
    - Hindari hard-coded secrets (gunakan `.env` / secret manager).

- **Dependency Management**
    - Gunakan versi library terbaru yang stabil.
    - Tambahkan proses CI/CD untuk scan otomatis (Trivy, Dependabot).

- **Application Security**
    - Terapkan HTTPS (TLS).
    - Gunakan security headers (CSP, X-Frame-Options, HSTS).
    - Batasi rate-limit untuk endpoint sensitif.
    - Logging dan monitoring untuk deteksi anomali.

- **Infrastructure**
    - Gunakan minimal base image (e.g., `alpine`).
    - Jalankan container dengan non-root user.
    - Terapkan least privilege access.

---