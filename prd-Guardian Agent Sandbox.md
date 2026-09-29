# PRD: Guardian Agent Sandbox (GAS)

| Metadata | Detail |
| :--- | :--- |
| **Project Name** | Guardian Agent Sandbox (`gas`) |
| **Version** | 1.0.0-Draft |
| **Author** | Jejo / Evelyn Research Team |
| **Date** | 29 September 2026 |
| **Status** | Draft / Ready for Dev |
| **Tech Stack** | Golang (Static Binary), POSIX Syscalls / Stdin-Stdout Proxy |
| **Target Platform** | Linux (Arch/Fedora preferred), Windows (WSL/Native via Sandboxie logic) |

## 1. Executive Summary
**Problem Statement:**
Agen AI lokal seperti Hermes, Opencode, dan OMP memiliki akses penuh ke filesystem tempat mereka dijalankan. Saat ini, tidak ada mekanisme bawaan (*native skill*) untuk membatasi direktori mana yang boleh dibaca atau ditulis oleh agen. Hal ini menimbulkan risiko kebocoran data pribadi (SSH keys, `.env`, dokumen finansial) jika agen secara tidak sengaja atau melalui prompt injection mengakses file di luar konteks proyek.

**Solution Overview:**
`Guardian Agent Sandbox` (GAS) adalah sebuah *wrapper* CLI ultra-ringan (<5MB RAM) yang bertindak sebagai *gatekeeper*. GAS meluncurkan proses agen (Hermes/Opencode) dalam lingkungan terisolasi secara logis atau sistemik, menerapkan kebijakan "Whitelist Directory" dan "Blacklist Pattern". Jika agen mencoba mengakses resource terlarang, GAS akan memblokir permintaan tersebut dan mengembalikan pesan error palsu kepada LLM agar alur percakapan tetap berjalan tanpa membocorkan struktur data asli.

**Key Value Proposition:**
*   **Zero Overhead:** Tidak memerlukan daemon latar belakang seperti Docker.
*   **Data Privacy First:** Memastikan data sensitif user tidak pernah masuk ke Context Window LLM.
*   **Auditability:** Mencatat setiap upaya akses ilegal untuk debugging keamanan.

## 2. User Personas & Use Cases

### Persona: The Minimalist Developer (Jejo)
*   **Karakteristik:** Menggunakan laptop spek rendah (8GB RAM), OS Linux/Windows LTSC, anti-bloatware, peduli privasi.
*   **Pain Point:** Takut agen AI membaca file `~/.ssh/id_rsa` atau folder `~/Documents/Taxes`.
*   **Goal:** Menjalankan coding agent dengan rasa aman total tanpa mengorbankan performa CPU/RAM.

### Use Case 1: Safe Coding Session
User menjalankan perintah `gas --project ./my-app hermes`. Agen hanya bisa melihat file di dalam `./my-app`. Jika user bertanya "Apa isi password wifi saya?", agen mencoba membaca `~/.config/wifi.conf`, GAS memblokirnya, dan agen merespons "Akses ditolak demi keamanan."

### Use Case 2: Multi-Agent Orchestration
User menjalankan OMP yang memanggil sub-agent. GAS memastikan bahwa seluruh rantai pemanggilan (parent & child processes) tunduk pada kebijakan sandbox yang sama.

## 3. Functional Requirements

### FR-1: Process Wrapping & Injection
*   Sistem harus dapat meluncurkan binary eksternal (misal: `hermes`, `opencode`, `omp`) sebagai anak proses.
*   Sistem harus menyuntikkan variabel lingkungan atau argumen wajib untuk memaksa agen bekerja dalam batas tertentu.

### FR-2: Access Control Policy Engine
Sistem harus mendukung dua mode proteksi:
1.  **Directory Whitelist (Allow-list):** Hanya path absolut yang terdaftar yang boleh diakses. Semua lainnya diblokir.
2.  **Pattern Blacklist (Deny-list):** Path spesifik yang dilarang meskipun berada di dalam whitelist (contoh: `.git/config`, `node_modules/.cache`).

### FR-3: Interception Mechanism (Hybrid Approach)
*   **Mode A (Linux - Recommended): Namespace Isolation.**
    Menggunakan `unshare` atau `chroot` minimal untuk membuat *mount namespace* baru. Filesystem host tidak terlihat kecuali yang di-bind-mount secara eksplisit. Ini adalah isolasi kernel-level yang paling aman dan ringan.
*   **Mode B (Cross-Platform/Dev Mode): Stdio Proxy.**
    Membaca stream JSON/Text dari stdin/stdout agen. Melakukan regex matching terhadap parameter `path` atau `file_name`. Jika melanggar policy, membalas dengan fake error response sebelum diteruskan ke agen.

### FR-4: Audit Logging
*   Setiap kali akses diblokir, sistem mencatat timestamp, agen yang meminta, path target, dan alasan blokir ke file log lokal (`~/.gas/logs/access_denied.log`).
*   Log harus berputar (rotate) otomatis agar tidak memakan disk space berlebih.

### FR-5: Configuration Management
*   Mendukung file konfigurasi global (`~/.gas/config.yaml`) dan per-proyek (`.gasignore` di root folder).
*   Perintah CLI sederhana: `gas init`, `gas run <agent>`, `gas status`.

## 4. Non-Functional Requirements (NFR)

| Kategori | Target | Justifikasi |
| :--- | :--- | :--- |
| **Performance** | Startup Time < 50ms | Harus terasa instan bagi developer. |
| **Memory Footprint** | < 10 MB RSS | Agar tidak menambah beban pada sistem 8GB RAM. |
| **Binary Size** | < 5 MB (Stripped) | Distribusi mudah, single file executable. |
| **Security** | Fail-Closed Default | Jika terjadi crash pada wrapper, agen harus mati, bukan lolos. |
| **Compatibility** | Linux Kernel > 5.0, Win10+ | Dukungan untuk Arch Linux dan Windows LTSC. |

## 5. Security Policies & Disk Rules (The Core Logic)

Ini adalah bagian terpenting sesuai permintaan Anda. Berikut adalah aturan default yang akan ditanamkan ke dalam `Gas`:

### A. Global Deny List (Never Touch These)
Terapkan pola glob berikut untuk semua agen, terlepas dari project dir:

```yaml
global_deny_patterns:
  # Credentials & Keys
  - "**/.ssh/**"
  - "**/.gnupg/**"
  - "**/.aws/credentials"
  - "**/.azure/**"
  - "**/.kube/config"
  
  # Environment Secrets
  - "**/.env"
  - "**/.env.*"
  - "**/secrets.json"
  - "**/*.pem"
  - "**/*.key"
  
  # System Criticals (Prevent Bricking)
  - "/etc/shadow"
  - "/etc/passwd"
  - "/proc/sys/kernel/core_pattern"
  - "C:\\Windows\\System32\\*" # On Windows
  
  # Personal Data Heuristics
  - "~/Documents/Financial/**"
  - "~/Pictures/Private/**"
  - "~/.bash_history"
  - "~/.zsh_history"
```

### B. Project Scope Allowance (White Box)
Hanya folder kerja yang diizinkan. Struktur standar:

```yaml
project_allow_roots:
  - "./src"
  - "./tests"
  - "./docs"
  - "./assets"
  - "./scripts"
  
# Exceptions within Project (Still Blocked)
project_internal_deny:
  - "**/node_modules/.bin/**" # Prevent executing random binaries
  - "**/.git/hooks/**"        # Prevent malicious git hooks execution
  - "**/vendor/**"            # Optional: block reading vendored libs if too large/noisy
```

### C. Network Restrictions (Optional but Recommended)
Jika agen memiliki kemampuan web-fetching:
*   **Block:** Localhost ports other than API endpoint (e.g., block `localhost:3306` MySQL access unless explicitly allowed).
*   **Block:** Internal IPs (`192.168.x.x`, `10.x.x.x`) to prevent lateral movement attacks on home network devices.

### D. Write Permissions
*   **Read-Only Mode:** Agen hanya boleh membaca file. Penulisan file diblokir kecuali ke folder `./output` atau `./temp`.
*   **Write-Allowed Paths:**
    ```yaml
    writable_paths:
      - "./src/**/*.go"
      - "./src/**/*.ts"
      - "./README.md"
      - "./CHANGELOG.md"
    ```
    *Semua write attempt ke luar daftar ini akan ditolak.*

## 6. Technical Architecture Design

### Component Diagram

```mermaid
graph TD
    User[Developer] -->|gas run hermes| CLI[Guardian CLI Wrapper]
    
    subgraph "Isolation Layer (Linux)"
        NS[Namespace Creator<br/>mnt/pid/net]
        BindMount[Bind Mount Only Allowed Dirs]
        DropCaps[Drop All Capabilities except NET_BIND_SERVICE]
    end
    
    subgraph "Policy Engine"
        ConfigLoader[Load .gasignore & config.yaml]
        Matcher[Glob/Regex Matcher]
        Logger[Audit Logger]
    end
    
    CLI --> NS
    NS --> Hermes[Hermes/Opencode Process]
    
    Hermes -->|Syscall: open/read/write| Kernel[Linux Kernel]
    Kernel -.->|Intercepted by Namespace| NS
    
    Hermes -->|Tool Call: read_file(path)| StdProxy[Stdin/Stdout Filter]
    StdProxy --> Matcher
    Matcher -->|Allowed| PassThrough[Forward to Real FS]
    Matcher -->|Blocked| FakeError[Return 'Permission Denied' JSON]
    
    FakeError --> Hermes
    Logger --> LogFile[(access_denied.log)]
```

### Implementation Strategy in Go

1.  **Library Selection:**
    *   `github.com/spf13/viper`: Untuk parsing YAML config.
    *   `github.com/bmatcuk/doublestar/v4`: Untuk pattern matching glob (`**/.ssh/*`) yang cepat.
    *   `golang.org/x/sys/unix`: Untuk syscall `unshare`, `pivot_root`, `bind mount` (Linux native isolation).
    *   `encoding/json`: Untuk parsing tool calls jika menggunakan metode proxy stdio.

2.  **Core Logic Flow (Main Function):**
    ```go
    func main() {
        // 1. Load Config
        cfg := loadConfig(".gas.yml")
        
        // 2. Validate Args
        agentCmd := os.Args[1:] // e.g., ["hermes", "--interactive"]
        
        // 3. Setup Isolation (Linux Best Practice)
        if runtime.GOOS == "linux" {
            setupNamespace(cfg.AllowDirs, cfg.DenyPatterns)
        } else {
            // Fallback to Stdio Proxy for Windows/Mac simplicity initially
            startStdioProxy(agentCmd, cfg)
        }
        
        // 4. Execute Child Process
        cmd := exec.Command(agentCmd[0], agentCmd[1:]...)
        cmd.Env = append(os.Environ(), "GAS_SANDBOX=true")
        cmd.Run()
    }
    ```

3.  **Handling False Positives:**
    *   Sediakan flag override darurat: `gas run --unsafe hermes` (dengan peringatan keras di terminal) untuk kasus debugging kritis.

## 7. Development Roadmap

### Phase 1: MVP (Minimum Viable Product) - Week 1-2
*   [ ] Implementasikan CLI dasar di Go.
*   [ ] Buat parser konfigurasi YAML.
*   [ ] Implementasikan **Stdio Proxy Method** (Metode B) karena lebih mudah cross-platform dan cepat dikembangkan.
*   [ ] Test blocking sederhana: Coba suruh agen baca `/etc/passwd`, pastikan return error.

### Phase 2: Native Linux Isolation - Week 3-4
*   [ ] Integrasikan `unix.Unshare(CLONE_NEWNS)` untuk mount namespace.
*   [ ] Implementasikan bind-mount dinamis berdasarkan `AllowDirs`.
*   [ ] Hapus dependency pada parsing JSON manual saat sudah stabil di level kernel.
*   [ ] Tambahkan audit logging ke file.

### Phase 3: Advanced Features & Polish - Week 5+
*   [ ] Integrasi dengan Telegram Bot (Eve/Jejo) untuk notifikasi real-time jika ada blokiran mencurigakan.
*   [ ] GUI Dashboard ringan (Web-based localhost) untuk visualize statistik akses.
*   [ ] Packaging: Build static binary untuk Arch Linux (AUR) dan Windows (.exe).

## 8. Risk Assessment

| Risiko | Dampak | Mitigasi |
| :--- | :--- | :--- |
| **Bypass via Shell Exec** | Agen memanggil `bash -c "cat ~/.ssh/key"` melewati filter JSON. | Gunakan Namespace Isolation (Phase 2) yang memblokir akses fisik ke file tersebut. Pada Phase 1, batasi izin eksekusi shell command di config agen itu sendiri. |
| **False Positive Blocking** | Agen gagal compile karena tidak bisa baca lib system. | Sediakan `--allow-system-libs` flag yang me-mount `/usr/lib` read-only. |
| **Performance Hit** | Parsing regex terlalu lambat. | Gunakan library `doublestar` yang dioptimalkan untuk glob patterns, hindari regex kompleks saat runtime. Pre-compile patterns saat startup. |

## 9. Conclusion
Proyek **Guardian Agent Sandbox** mengisi celah keamanan vital dalam ekosistem agen AI lokal. Dengan pendekatan Go yang efisien dan strategi isolasi bertingkat (mulai dari Proxy hingga Namespace), kita dapat memberikan perlindungan data tingkat enterprise dengan overhead hampir nol, sangat cocok untuk profil hardware dan filosofi minimalist Anda.