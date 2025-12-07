#ifndef DEFENSE_POLICY_H
#define DEFENSE_POLICY_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// 防禦等級抽象
typedef enum {
    DEFENSE_OFF   = 0, // 完全關閉防禦
    DEFENSE_LIGHT = 1, // 僅啟用 Self-Verify
    DEFENSE_FULL  = 2  // 啟用 Snapshot + Transition + Duplication 等
} DefenseLevel;

// Checksum / Hash 策略介面
typedef void (*ChecksumFunc)(const void *data, size_t len, uint8_t *out);

// 整體完整性策略
typedef struct {
    ChecksumFunc checksum_fn; // 當前使用的 Checksum/Hash
    size_t       hash_len;    // 有效 hash 長度（bytes）
    const char  *name;        // 策略名稱（logging 用）
} IntegrityPolicy;

// 全域防禦設定
typedef struct {
    DefenseLevel    level;
    IntegrityPolicy integrity;
    int             enable_self_verify;
    int             enable_duplication;
} DefenseConfig;

// ----------------- 實作兩種示範策略 -----------------

// 1. Weak：XOR checksum（快、可抓 stuck/zero，碰撞性弱）
static inline void strategy_xor_checksum(const void *data, size_t len, uint8_t *out) {
    uint8_t sum = 0;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        sum ^= p[i];
    }
    // 只將 sum 放在 out[0]，其餘填 0，避免未定義資料
    out[0] = sum;
    memset(out + 1, 0, 31);
}

// 2. Strong-ish：FNV-1a 32bit（示範用，非 cryptographic）
static inline void strategy_fnv1a_checksum(const void *data, size_t len, uint8_t *out) {
    uint32_t hash = 2166136261u;
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        hash ^= p[i];
        hash *= 16777619u;
    }
    // 將 32-bit hash 放在前 4 bytes，其餘清 0
    memcpy(out, &hash, 4);
    memset(out + 4, 0, 28);
}

// 初始化防禦設定（從環境變數載入）
static inline void defense_init_from_env(DefenseConfig *cfg) {
    if (!cfg) return;

    memset(cfg, 0, sizeof(*cfg));
    cfg->level = DEFENSE_OFF;

    // MLDSA_DEFENSE_LEVEL：OFF / LIGHT / FULL
    const char *lvl = getenv("MLDSA_DEFENSE_LEVEL");
    if (lvl) {
        if (strcmp(lvl, "LIGHT") == 0) cfg->level = DEFENSE_LIGHT;
        else if (strcmp(lvl, "FULL") == 0) cfg->level = DEFENSE_FULL;
        else cfg->level = DEFENSE_OFF;
    } else {
        cfg->level = DEFENSE_OFF;
    }

    // 預設策略：WEAK_XOR
    cfg->integrity.checksum_fn = strategy_xor_checksum;
    cfg->integrity.hash_len    = 1;
    cfg->integrity.name        = "WEAK_XOR";

    // MLDSA_INTEGRITY_POLICY：WEAK / STRONG
    const char *policy = getenv("MLDSA_INTEGRITY_POLICY");
    if (policy && strcmp(policy, "STRONG") == 0) {
        cfg->integrity.checksum_fn = strategy_fnv1a_checksum;
        cfg->integrity.hash_len    = 4;
        cfg->integrity.name        = "STRONG_FNV";
    }

    cfg->enable_self_verify  = (cfg->level >= DEFENSE_LIGHT);
    cfg->enable_duplication  = (cfg->level >= DEFENSE_FULL);

    fprintf(stderr, "[DEFENSE] Init: Level=%d, Policy=%s\n",
            cfg->level, cfg->integrity.name);
}

#endif // DEFENSE_POLICY_H