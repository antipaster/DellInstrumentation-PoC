#include <Windows.h>
#include <setupapi.h>
#include <newdev.h>
#include <cfgmgr32.h>
#include <cstdio>
#include <string>
#include <iostream>
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "newdev.lib")

// from the real INF
static const GUID ClassGuid = { 0xE1C7DABE, 0x63DE, 0x4630, {0xA4,0xDE,0xA4,0xAD,0xC0,0x50,0x3B,0xE3} };
static const wchar_t* HardwareId = L"Root\\DellInsDrv";
static const wchar_t* DeviceName = L"\\\\.\\Dell_Instrumentation";

static void stop_old_service() {
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;

    SC_HANDLE svc = OpenServiceW(scm, L"DellInstrumentation", SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS ss = {};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        // wait for it to actually stop
        for (int i = 0; i < 20; i++) {
            QueryServiceStatus(svc, &ss);
            if (ss.dwCurrentState == SERVICE_STOPPED) break;
            Sleep(250);
        }
        DeleteService(svc);
        CloseServiceHandle(svc);
        printf("[*] Stopped and deleted old service\n");

        // wait until service is fully gone
        for (int i = 0; i < 40; i++) {
            svc = OpenServiceW(scm, L"DellInstrumentation", SERVICE_QUERY_STATUS);
            if (!svc) break;
            CloseServiceHandle(svc);
            Sleep(250);
        }
        printf("[*] Service cleanup complete\n");
    }
    CloseServiceHandle(scm);
}

static bool device_node_exists() {
    HDEVINFO devs = SetupDiGetClassDevsW(&ClassGuid, NULL, NULL, 0);
    if (devs == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA did = { sizeof(did) };
    bool found = false;
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devs, i, &did); i++) {
        wchar_t hwid[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(devs, &did, SPDRP_HARDWAREID, NULL,
                (BYTE*)hwid, sizeof(hwid), NULL)) {
            if (_wcsicmp(hwid, HardwareId) == 0) {
                found = true;
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(devs);
    std::cin.get();
    return found;
}

static bool install_class(const wchar_t* inf_path) {
    if (!SetupDiInstallClassW(NULL, inf_path, 0, NULL)) {
        DWORD err = GetLastError();
        if (err == 0xE0000204) { // ERROR_CLASS_ALREADY_INSTALLED
            printf("[*] Class already registered\n");
            return true;
        }
        printf("[-] SetupDiInstallClass failed: %u (0x%08x)\n", err, err);
        return false;
    }
    printf("[+] Class registered from INF\n");
    return true;
}

static bool create_device_node() {
    HDEVINFO devs = SetupDiCreateDeviceInfoList(&ClassGuid, NULL);
    if (devs == INVALID_HANDLE_VALUE) {
        printf("[-] SetupDiCreateDeviceInfoList failed: %u\n", GetLastError());
        return false;
    }

    SP_DEVINFO_DATA did = { sizeof(did) };
    // pass just the device ID, not full instance path; DICD_GENERATE_ID adds the suffix
    if (!SetupDiCreateDeviceInfoW(devs, L"DellInsDrv",
            &ClassGuid, NULL, NULL, DICD_GENERATE_ID, &did)) {
        printf("[-] SetupDiCreateDeviceInfoW failed: %u (0x%08x)\n",
            GetLastError(), GetLastError());
        SetupDiDestroyDeviceInfoList(devs);
        return false;
    }

    // multi-sz: hwid + double null
    wchar_t mszHwid[64] = {};
    wcscpy_s(mszHwid, HardwareId);
    DWORD mszLen = (DWORD)((wcslen(HardwareId) + 2) * sizeof(wchar_t));

    if (!SetupDiSetDeviceRegistryPropertyW(devs, &did, SPDRP_HARDWAREID,
            (const BYTE*)mszHwid, mszLen)) {
        printf("[-] SetupDiSetDeviceRegistryProperty failed: %u\n", GetLastError());
        SetupDiDestroyDeviceInfoList(devs);
        return false;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, devs, &did)) {
        printf("[-] DIF_REGISTERDEVICE failed: %u\n", GetLastError());
        SetupDiDestroyDeviceInfoList(devs);
        return false;
    }

    SetupDiDestroyDeviceInfoList(devs);
    printf("[+] Device node created\n");
    return true;
}

static bool install_driver(const wchar_t* inf_path) {
    BOOL reboot = FALSE;
    if (!UpdateDriverForPlugAndPlayDevicesW(NULL, HardwareId, inf_path,
            INSTALLFLAG_FORCE, &reboot)) {
        printf("[-] UpdateDriverForPlugAndPlayDevices failed: %u\n", GetLastError());
        return false;
    }
    printf("[+] Driver installed%s\n", reboot ? " (reboot needed)" : "");
    return true;
}

static void remove_device_node() {
    HDEVINFO devs = SetupDiGetClassDevsW(&ClassGuid, NULL, NULL, 0);
    if (devs == INVALID_HANDLE_VALUE) return;

    SP_DEVINFO_DATA did = { sizeof(did) };
    for (DWORD i = 0; SetupDiEnumDeviceInfo(devs, i, &did); i++) {
        wchar_t hwid[256] = {};
        if (SetupDiGetDeviceRegistryPropertyW(devs, &did, SPDRP_HARDWAREID, NULL,
                (BYTE*)hwid, sizeof(hwid), NULL)) {
            if (_wcsicmp(hwid, HardwareId) == 0) {
                SetupDiCallClassInstaller(DIF_REMOVE, devs, &did);
                printf("[*] Device node removed\n");
                break;
            }
        }
    }
    SetupDiDestroyDeviceInfoList(devs);
}

static std::wstring get_inf_path() {
    wchar_t exe_path[MAX_PATH];
    GetModuleFileNameW(NULL, exe_path, MAX_PATH);

    std::wstring dir(exe_path);
    dir = dir.substr(0, dir.find_last_of(L'\\'));
    return dir + L"\\delldriver\\dellinstrumentation.inf";
}

int main(int argc, char* argv[]) {
    bool uninstall = (argc > 1 && strcmp(argv[1], "-u") == 0);

    if (uninstall) {
        printf("[*] Uninstalling...\n");
        stop_old_service();
        remove_device_node();
        printf("[+] Done\n");
        return 0;
    }

    printf("[*] Dell Instrumentation loader\n\n");

  
    std::wstring inf = get_inf_path();
    DWORD attr = GetFileAttributesW(inf.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        printf("[-] INF not found. Put delldriver\\ next to this exe.\n");
        printf("    Expected: ");
        wprintf(L"%s\n", inf.c_str());
        std::cin.get();
        return 1;
    }
    printf("[+] INF: ");
    wprintf(L"%s\n", inf.c_str());

    stop_old_service();


    if (!device_node_exists()) {
        printf("[*] Registering driver class...\n");
        if (!install_class(inf.c_str())) {
            return 1;
        }
        printf("[*] Creating device node...\n");
        if (!create_device_node()) {
            return 1;
        }
    } else {
        printf("[*] Device node already exists\n");
    }

    printf("[*] Installing driver...\n");
    if (!install_driver(inf.c_str())) {
        printf("[!] Install failed, cleaning up device node\n");
        remove_device_node();
        return 1;
    }

    printf("[*] Waiting for device...\n");
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 20; i++) {
        Sleep(250);
        h = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) break;
    }

    if (h != INVALID_HANDLE_VALUE) {
        printf("[+] Device opened! Handle=0x%p\n", h);
        CloseHandle(h);
        std::cin.get();
        return 0;
    }

    printf("[-] Device not accessible. err=%u\n", GetLastError());
    std::cin.get();
    return 1;
}
