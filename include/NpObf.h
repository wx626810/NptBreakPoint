#pragma once
// Light string obfuscation for R0 - XOR 0x5A + rolling, decrypt on stack
inline void NpObfDecryptW(const unsigned char* enc, size_t len, wchar_t* out){
    for(size_t i=0;i<len;i++){
        unsigned char b = enc[i] ^ 0x5A ^ (unsigned char)(i & 0xFF);
        out[i] = (wchar_t)b;
    }
    out[len]=0;
}
inline void* NpGetRoutineByHash(const char* hashName){
    // Simple hash lookup via MmGetSystemRoutineAddress with plain name for now (placeholder for hash)
    UNICODE_STRING u; RtlInitUnicodeString(&u, (PCWSTR)hashName); // placeholder - will be replaced by hash table
    return MmGetSystemRoutineAddress(&u);
}
