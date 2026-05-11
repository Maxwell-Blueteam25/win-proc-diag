#include <errhandlingapi.h>
#include <handleapi.h>
#include <memoryapi.h>
#include <minwindef.h>
#include <ntdsapi.h>
#include <processthreadsapi.h>
#include <securitybaseapi.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wchar.h>
#include <windows.h>
#include <winerror.h>
#include <winnt.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")

typedef struct ProcessInformation {
  DWORD PID;
  DWORD PPID;
  wchar_t *Name;

  struct ProcessInformation **Children;
  size_t children_count;
  size_t children_capacity;
} ProcessInformation;

typedef struct _PROCESS_TELEMETRY_ID_INFORMATION {
  ULONG HeaderSize;
  ULONG ProcessId;
  ULONG64 ProcessStartKey;
  ULONG64 CreateTime;
  ULONG64 CreateInterruptTime;
  ULONG64 CreateUnbiasedInterruptTime;
  ULONG64 ProcessSequenceNumber;
  ULONG64 SessionCreateTime;
  ULONG SessionId;
  ULONG BootId;
  ULONG ImageChecksum;
  ULONG ImageTimeDateStamp;
  ULONG UserSidOffset;
  ULONG ImagePathOffset;
  ULONG PackageNameOffset;
  ULONG RelativeAppNameOffset;
  ULONG CommandLineOffset;
} PROCESS_TELEMETRY_ID_INFORMATION, *PPROCESS_TELEMETRY_ID_INFORMATION;

int checkIfProcessInMap(ProcessInformation **map, size_t map_count,
                        ProcessInformation *pi) {
  for (size_t i = 0; i < map_count; i++) {
    ProcessInformation *current = map[i];

    if (current->PID == pi->PID) {
      return 1;
    }
  }
  return 0;
}

void addToMap(ProcessInformation ***map, size_t *map_count,
              size_t *map_capacity, ProcessInformation *pi) {
  if (*map_count >= *map_capacity) {
    *map_capacity = (*map_capacity == 0) ? 4 : *map_capacity * 2;
    *map = realloc(*map, *map_capacity * sizeof(ProcessInformation *));
  }
  (*map)[*map_count] = pi;
  (*map_count)++;
}

int checkIfParentExists(ProcessInformation **map, size_t map_count,
                        ProcessInformation ***roots, size_t *roots_count,
                        size_t *roots_capacity, ProcessInformation *pi) {
  for (size_t i = 0; i < map_count; i++) {
    ProcessInformation *current = map[i];
    if (current->PID == pi->PPID && pi->PID != pi->PPID) {
      if (current->children_count >= current->children_capacity) {
        current->children_capacity = (current->children_capacity == 0)
                                         ? 4
                                         : current->children_capacity * 2;
        current->Children =
            realloc(current->Children,
                    current->children_capacity * sizeof(ProcessInformation *));
      }
      current->Children[current->children_count] = pi;
      current->children_count++;
      return 0;
    }
  }
  addToMap(roots, roots_count, roots_capacity, pi);
  return 0;
}

void freeProcessTree(ProcessInformation *pi) {
  if (pi == NULL)
    return;

  for (size_t i = 0; i < pi->children_count; i++) {
    freeProcessTree(pi->Children[i]);
  }

  if (pi->Children != NULL) {
    free(pi->Children);
  }

  if (pi->Name != NULL) {
    free(pi->Name);
  }

  free(pi);
}

void printProcessTree(ProcessInformation *pi, int level) {
  if (pi == NULL)
    return;

  for (int i = 0; i < level; i++) {
    wprintf(L"  ");
  }

  wprintf(L"|_ %ls (PID: %lu)\n", pi->Name, pi->PID);

  for (size_t i = 0; i < pi->children_count; i++) {
    printProcessTree(pi->Children[i], level + 1);
  }
}

HANDLE getProcessHandle(DWORD processID) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
  if (hProcess == NULL) {
    wprintf(L"Unable to Receive Process Handle: %lu\n", GetLastError());
    CloseHandle(hProcess);
    return hProcess;
  }
  return hProcess;
}

void getCommandLine(HANDLE hProcess) {
  PROCESS_BASIC_INFORMATION pbi;
  ULONG retlen;
  NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation,
                                              &pbi, sizeof(pbi), &retlen);
  if (status != 0) {
    CloseHandle(hProcess);
    wprintf(L"Error Receiving Process Information");
    return;
  }

  PEB peb;
  RTL_USER_PROCESS_PARAMETERS params;
  if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB),
                         NULL)) {
    wprintf(L"Error Reading PEB Process Memory. Error: %lu\n", GetLastError());
    CloseHandle(hProcess);
    return;
  }

  if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &params,
                         sizeof(params), NULL)) {
    CloseHandle(hProcess);
    wprintf(L"Error Reading Parameters from Memory\n");
    return;
  }

  USHORT len = params.CommandLine.Length;
  wchar_t *buffer = (wchar_t *)malloc(len + sizeof(wchar_t));
  memset(buffer, 0, len + sizeof(wchar_t));

  if (ReadProcessMemory(hProcess, params.CommandLine.Buffer, buffer, len,
                        NULL)) {
    wprintf(L"Command Line: %ls\n", buffer);
  }
  CloseHandle(hProcess);
  free(buffer);
}

int checkIfThreadInMap(THREADENTRY32 **map, size_t *map_count,
                       THREADENTRY32 te) {
  for (size_t i = 0; i <= *map_count; i++) {
    THREADENTRY32 *current = map[i];

    if (current->th32ThreadID == te.th32ThreadID) {
      return 1;
    }
  }
  return 0;
}

void addThreadToMap(THREADENTRY32 **map, size_t *map_count,
                    size_t *map_capacity, THREADENTRY32 *te) {
  if (*map_count >= *map_capacity) {
    *map_capacity = (*map_capacity == 0) ? 4 : *map_capacity * 2;
    *map = realloc(*map, *map_capacity * sizeof(THREADENTRY32));
  }
  (*map)[*map_count] = *te;
  (*map_count)++;
}
void getThreadList(DWORD pid) {
  THREADENTRY32 *map = NULL;
  size_t map_count = 0;
  size_t map_capacity = 0;
  HANDLE snapHandle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snapHandle == INVALID_HANDLE_VALUE) {
    CloseHandle(snapHandle);
    wprintf(L"Error Receiving Snapshot Handle: %lu\n", GetLastError());
    return;
  }
  THREADENTRY32 te;
  te.dwSize = sizeof(THREADENTRY32);
  if (!Thread32First(snapHandle, &te)) {
    CloseHandle(snapHandle);
    wprintf(L"Error Getting First Thread: %lu\n", GetLastError());
    return;
  }
  do {
    if (te.th32OwnerProcessID == pid) {
      addThreadToMap(&map, &map_count, &map_capacity, &te);
    }
  } while (Thread32Next(snapHandle, &te));

  for (size_t i = 0; i < map_count; i++) {
    HANDLE tHandle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE,
                                map[i].th32ThreadID);
    if (tHandle == NULL) {
      continue;
    }
    PWSTR data = NULL;
    HRESULT hr = GetThreadDescription(tHandle, &data);
    if (SUCCEEDED(hr) && data != NULL) {
      if (wcslen(data) > 0) {
        wprintf(L"  |__ ID: %lu [Name: %ls]\n", map[i].th32ThreadID, data);
      } else {
        wprintf(L"  |__ ID: %lu [Unnamed Thread]\n", map[i].th32ThreadID);
      }
      LocalFree(data);
    }
    CloseHandle(tHandle);
  }
  CloseHandle(snapHandle);
  free(map);
}

void getProcessIntegrity(DWORD pid) {
  PTOKEN_MANDATORY_LABEL tokenInfo = NULL;
  HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (hProcess == NULL) {
    wprintf(L"Unable to Receive Process Handle: %lu\n", GetLastError());
    CloseHandle(hProcess);
    return;
  }
  HANDLE tokenHandle;
  if (!OpenProcessToken(hProcess, TOKEN_QUERY, &tokenHandle)) {
    CloseHandle(hProcess);
    wprintf(L"Unable to receive tokenHandle: %lu\n", GetLastError());
    return;
  }
  DWORD requiredSize = 0;
  BOOL result = GetTokenInformation(tokenHandle, TokenIntegrityLevel, NULL, 0,
                                    &requiredSize);
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    printf("GetTokenInformation failed: %lu\n", GetLastError());
    return;
  }

  tokenInfo = (PTOKEN_MANDATORY_LABEL)malloc(requiredSize);
  result = GetTokenInformation(tokenHandle, TokenIntegrityLevel, tokenInfo,
                               requiredSize, &requiredSize);
  if (!result) {
    printf("Second call failed: %lu\n", GetLastError());
    CloseHandle(tokenHandle);
    CloseHandle(hProcess);
    free(tokenInfo);
    return;
  }

  DWORD integrityLevel = *GetSidSubAuthority(
      tokenInfo->Label.Sid,
      (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tokenInfo->Label.Sid) - 1));

  const wchar_t *levelName = L"Unknown";

  switch (integrityLevel) {
  case SECURITY_MANDATORY_UNTRUSTED_RID:
    levelName = L"Untrusted";
    break;
  case SECURITY_MANDATORY_LOW_RID:
    levelName = L"Low";
    break;
  case SECURITY_MANDATORY_MEDIUM_RID:
    levelName = L"Medium";
    break;
  case SECURITY_MANDATORY_MEDIUM_PLUS_RID:
    levelName = L"Medium +";
    break;
  case SECURITY_MANDATORY_HIGH_RID:
    levelName = L"High";
    break;
  case SECURITY_MANDATORY_SYSTEM_RID:
    levelName = L"System";
    break;
  case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
    levelName = L"Protected Process";
    break;
  }

  wprintf(L"Process %lu Integrity Level: %s (RID = %lu)\n", pid, levelName,
          integrityLevel);

cleanup:
  if (tokenInfo)
    free(tokenInfo);
  if (tokenHandle)
    CloseHandle(tokenHandle);
  if (hProcess)
    CloseHandle(hProcess);
}

int main(int argc, char *argv[]) {
  int showCommandLine = 0;
  int showThreads = 0;
  int showIntegrity = 0;
  DWORD targetPID = 0;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0) {
      printf("Process Tree & Diagnostic Tool\n\n");
      printf("Usage:\n");
      printf("  process_tree.exe [options]\n\n");
      printf("Options:\n");
      printf("  -pid <id>          Target a specific process ID\n");
      printf("  -commandline true  Show the command line of the target PID\n");
      printf("  -threads true      List threads for the target PID\n");
      printf(
          "  -integrity true    Show the integrity level of the target PID\n");
      printf("  --help             Show this help page\n\n");
      printf("Notes:\n");
      printf("  Run without flags to display the full system process tree.\n");
      return 0;
    } else if (strcmp(argv[i], "-commandline") == 0) {
      if (i + 1 < argc && strcmp(argv[i + 1], "true") == 0) {
        showCommandLine = 1;
        i++;
      }
    } else if (strcmp(argv[i], "-threads") == 0) {
      if (i + 1 < argc && strcmp(argv[i + 1], "true") == 0) {
        showThreads = 1;
        i++;
      }
    } else if (strcmp(argv[i], "-integrity") == 0) {
      if (i + 1 < argc && strcmp(argv[i + 1], "true") == 0) {
        showIntegrity = 1;
        i++;
      }
    } else if (strcmp(argv[i], "-pid") == 0) {
      if (i + 1 < argc) {
        targetPID = (DWORD)strtoul(argv[i + 1], NULL, 10);
        i++;
      }
    }
  }

  if (targetPID != 0) {
    if (showCommandLine || showThreads || showIntegrity) {
      if (showCommandLine) {
        HANDLE hProcess = getProcessHandle(targetPID);
        if (hProcess) {
          getCommandLine(hProcess);
        }
      }
      if (showThreads) {
        getThreadList(targetPID);
      }
      if (showIntegrity) {
        getProcessIntegrity(targetPID);
      }
      return 0;
    }
  }

  ProcessInformation **roots = NULL;
  size_t roots_count = 0, roots_capacity = 0;
  ProcessInformation **map = NULL;
  size_t map_count = 0, map_capacity = 0;

  HANDLE sHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (sHandle == INVALID_HANDLE_VALUE)
    return 1;

  PROCESSENTRY32W pe;
  pe.dwSize = sizeof(PROCESSENTRY32W);

  if (Process32FirstW(sHandle, &pe)) {
    do {
      ProcessInformation *pi =
          (ProcessInformation *)malloc(sizeof(ProcessInformation));
      pi->PID = pe.th32ProcessID;
      pi->PPID = pe.th32ParentProcessID;
      pi->Name = (wchar_t *)malloc(MAX_PATH * sizeof(wchar_t));
      wcscpy(pi->Name, pe.szExeFile);
      pi->Children = NULL;
      pi->children_count = 0;
      pi->children_capacity = 0;
      addToMap(&map, &map_count, &map_capacity, pi);
    } while (Process32NextW(sHandle, &pe));
  }
  CloseHandle(sHandle);

  for (size_t i = 0; i < map_count; i++) {
    checkIfParentExists(map, map_count, &roots, &roots_count, &roots_capacity,
                        map[i]);
  }

  wprintf(L"Process Tree:\n");
  for (size_t i = 0; i < roots_count; i++)
    printProcessTree(roots[i], 0);

  for (size_t i = 0; i < roots_count; i++)
    freeProcessTree(roots[i]);

  free(map);
  free(roots);

  return 0;
}
