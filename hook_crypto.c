/*
Cuckoo Sandbox - Automated Malware Analysis
Copyright (C) 2010-2014 Cuckoo Sandbox Developers

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include "hooking.h"
#include "ntapi.h"
#include "log.h"

static const char *category = "crypto";
static IS_SUCCESS_BOOL();

HOOKDEF(BOOL, WINAPI, CryptProtectData,
    _In_      DATA_BLOB *pDataIn,
    _In_      LPCWSTR szDataDescr,
    _In_      DATA_BLOB *pOptionalEntropy,
    _In_      PVOID pvReserved,
    _In_opt_  CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    _In_      DWORD dwFlags,
    _Out_     DATA_BLOB *pDataOut
) {
    ENSURE_STRUCT(pDataIn, DATA_BLOB);

    BOOL ret = 1;
    LOQ("b", "Buffer", pDataIn->cbData, pDataIn->pbData);
    return Old_CryptProtectData(pDataIn, szDataDescr, pOptionalEntropy,
        pvReserved, pPromptStruct, dwFlags, pDataOut);
}

HOOKDEF(BOOL, WINAPI, CryptUnprotectData,
    _In_        DATA_BLOB *pDataIn,
    _Out_opt_   LPWSTR *ppszDataDescr,
    _In_opt_    DATA_BLOB *pOptionalEntropy,
    _Reserved_  PVOID pvReserved,
    _In_opt_    CRYPTPROTECT_PROMPTSTRUCT *pPromptStruct,
    _In_        DWORD dwFlags,
    _Out_       DATA_BLOB *pDataOut
) {
    ENSURE_STRUCT(pDataOut, DATA_BLOB);
    ENSURE_STRUCT(pOptionalEntropy, DATA_BLOB);

    BOOL ret = Old_CryptUnprotectData(pDataIn, ppszDataDescr,
        pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut);
    LOQ("bb", "Entropy", pOptionalEntropy->cbData, pOptionalEntropy->pbData,
        "Buffer", pDataOut->cbData, pDataOut->pbData);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptProtectMemory,
    _Inout_  LPVOID pData,
    _In_     DWORD cbData,
    _In_     DWORD dwFlags
) {
    BOOL ret = 1;
    LOQ("bi", "Buffer", cbData, pData, "Flags", dwFlags);
    return Old_CryptProtectMemory(pData, cbData, dwFlags);
}

HOOKDEF(BOOL, WINAPI, CryptUnprotectMemory,
    _Inout_  LPVOID pData,
    _In_     DWORD cbData,
    _In_     DWORD dwFlags
) {
    BOOL ret = Old_CryptUnprotectMemory(pData, cbData, dwFlags);
    LOQ("bi", "Buffer", cbData, pData, "Flags", dwFlags);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecrypt,
    _In_     HCRYPTKEY hKey,
    _In_     HCRYPTHASH hHash,
    _In_     BOOL Final,
    _In_     DWORD dwFlags,
    _Inout_  BYTE *pbData,
    _Inout_  DWORD *pdwDataLen
) {
    BOOL ret = Old_CryptDecrypt(hKey, hHash, Final, dwFlags, pbData,
        pdwDataLen);
    LOQ("ppBi", "CryptKey", hKey, "CryptHash", hHash,
        "Buffer", pdwDataLen, pbData, "Final", Final);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEncrypt,
    _In_     HCRYPTKEY hKey,
    _In_     HCRYPTHASH hHash,
    _In_     BOOL Final,
    _In_     DWORD dwFlags,
    _Inout_  BYTE *pbData,
    _Inout_  DWORD *pdwDataLen,
    _In_     DWORD dwBufLen
) {
    BOOL ret = 1;
    LOQ("ppbi", "CryptKey", hKey, "CryptHash", hHash,
        "Buffer", dwBufLen, pbData, "Final", Final);
    return Old_CryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen,
        dwBufLen);
}

HOOKDEF(BOOL, WINAPI, CryptHashData,
    _In_  HCRYPTHASH hHash,
    _In_  BYTE *pbData,
    _In_  DWORD dwDataLen,
    _In_  DWORD dwFlags
) {
    BOOL ret = Old_CryptHashData(hHash, pbData, dwDataLen, dwFlags);
    LOQ("pb", "CryptHash", hHash, "Buffer", dwDataLen, pbData);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecodeMessage,
    _In_         DWORD dwMsgTypeFlags,
    _In_         PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    _In_         PCRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
    _In_         DWORD dwSignerIndex,
    _In_         const BYTE *pbEncodedBlob,
    _In_         DWORD cbEncodedBlob,
    _In_         DWORD dwPrevInnerContentType,
    _Out_opt_    DWORD *pdwMsgType,
    _Out_opt_    DWORD *pdwInnerContentType,
    _Out_opt_    BYTE *pbDecoded,
    _Inout_opt_  DWORD *pcbDecoded,
    _Out_opt_    PCCERT_CONTEXT *ppXchgCert,
    _Out_opt_    PCCERT_CONTEXT *ppSignerCert
) {
    BOOL ret = Old_CryptDecodeMessage(dwMsgTypeFlags, pDecryptPara,
        pVerifyPara, dwSignerIndex, pbEncodedBlob, cbEncodedBlob,
        dwPrevInnerContentType, pdwMsgType, pdwInnerContentType,
        pbDecoded, pcbDecoded, ppXchgCert, ppSignerCert);
    LOQ("B", "Buffer", pcbDecoded, pbDecoded);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptDecryptMessage,
    _In_         PCRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
    _In_         const BYTE *pbEncryptedBlob,
    _In_         DWORD cbEncryptedBlob,
    _Out_opt_    BYTE *pbDecrypted,
    _Inout_opt_  DWORD *pcbDecrypted,
    _Out_opt_    PCCERT_CONTEXT *ppXchgCert
) {
    BOOL ret = Old_CryptDecryptMessage(pDecryptPara, pbEncryptedBlob,
        cbEncryptedBlob, pbDecrypted, pcbDecrypted, ppXchgCert);
    LOQ("B", "Buffer", pcbDecrypted, pbDecrypted);
    return ret;
}

HOOKDEF(BOOL, WINAPI, CryptEncryptMessage,
    _In_     PCRYPT_ENCRYPT_MESSAGE_PARA pEncryptPara,
    _In_     DWORD cRecipientCert,
    _In_     PCCERT_CONTEXT rgpRecipientCert[],
    _In_     const BYTE *pbToBeEncrypted,
    _In_     DWORD cbToBeEncrypted,
    _Out_    BYTE *pbEncryptedBlob,
    _Inout_  DWORD *pcbEncryptedBlob
) {
    BOOL ret = 1;
    LOQ("b", "Buffer", cbToBeEncrypted, pbToBeEncrypted);
    return Old_CryptEncryptMessage(pEncryptPara, cRecipientCert,
        rgpRecipientCert, pbToBeEncrypted, cbToBeEncrypted, pbEncryptedBlob,
        pcbEncryptedBlob);
}

HOOKDEF(BOOL, WINAPI, CryptHashMessage,
    _In_         PCRYPT_HASH_MESSAGE_PARA pHashPara,
    _In_         BOOL fDetachedHash,
    _In_         DWORD cToBeHashed,
    _In_         const BYTE *rgpbToBeHashed[],
    _In_         DWORD rgcbToBeHashed[],
    _Out_        BYTE *pbHashedBlob,
    _Inout_      DWORD *pcbHashedBlob,
    _Out_opt_    BYTE *pbComputedHash,
    _Inout_opt_  DWORD *pcbComputedHash
) {
    DWORD length = 0;
    for (DWORD i = 0; i < cToBeHashed; i++) {
        length += rgcbToBeHashed[i];
    }

    uint8_t *mem = malloc(length);
    if(mem != NULL) {
        for (DWORD i = 0, off = 0; i < cToBeHashed; i++) {
            memcpy(mem + off, rgpbToBeHashed[i], rgcbToBeHashed[i]);
            off += rgcbToBeHashed[i];
        }
    }

    BOOL ret = Old_CryptHashMessage(pHashPara, fDetachedHash, cToBeHashed,
        rgpbToBeHashed, rgcbToBeHashed, pbHashedBlob, pcbHashedBlob,
        pbComputedHash, pcbComputedHash);
    LOQ("b", "Buffer", length, mem);

    if(mem != NULL) {
        free(mem);
    }
    return ret;
}
