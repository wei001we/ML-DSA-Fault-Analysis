#ifndef DEFENSE_TRANSITION_H
#define DEFENSE_TRANSITION_H

#include "defense_policy.h"

// 狀態快照物件
typedef struct {
    uint8_t        hash[32];
    void          *addr;
    size_t         len;
    const DefenseConfig *cfg; // 不持有所有權，只是指向全域設定
} StateSnapshot;

// 建立快照（只在 FULL 模式下作用）
static inline void defense_snapshot_take(const DefenseConfig *cfg,
                                         StateSnapshot *snap,
                                         void *addr,
                                         size_t len) {
    if (!cfg || !snap || cfg->level < DEFENSE_FULL) return;
    if (!addr || len == 0) return;

    snap->addr = addr;
    snap->len  = len;
    snap->cfg  = cfg;
    memset(snap->hash, 0, sizeof(snap->hash));

    // 使用 volatile 防止編譯器優化掉讀取動作
    volatile const uint8_t *p = (volatile const uint8_t *)addr;
    cfg->integrity.checksum_fn((const void *)p, len, snap->hash);
}

// 簡單的「低熵」偵測：抓 Zeroing / Partial-zero 型錯誤
// 優化版：使用純整數運算避免 FPU 依賴
static inline int estimate_low_entropy(const void *data, size_t len) {
    if (!data || len < 32) {
        // 太短的資料不做低熵檢測，以避免誤判
        return 0;
    }
    const uint8_t *p = (const uint8_t *)data;
    size_t zero_count = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == 0) zero_count++;
    }
    
    // 門檻：若超過 90% 為 0 視為異常低熵 (zero_count * 10 > len * 9)
    return (zero_count * 10 > len * 9) ? 1 : 0;
}

// 驗證狀態轉移是否「合理」
// 1. Hash 完全不變 → Stuck fault / instruction skip
// 2. 內容極低熵 → Zeroing / Partial write fault
static inline int defense_validate_transition(StateSnapshot *snap,
                                              const char *context_name) {
    if (!snap || !snap->cfg || snap->cfg->level < DEFENSE_FULL) return 1;
    if (!snap->addr || snap->len == 0) return 1;

    const DefenseConfig *cfg = snap->cfg;
    uint8_t current_hash[32];
    memset(current_hash, 0, sizeof(current_hash));

    volatile const uint8_t *p = (volatile const uint8_t *)snap->addr;
    cfg->integrity.checksum_fn((const void *)p, snap->len, current_hash);

    size_t hlen = cfg->integrity.hash_len;
    if (hlen > sizeof(current_hash)) hlen = sizeof(current_hash);

    const char *ctx = context_name ? context_name : "UNKNOWN";

    // 1. Stuck fault 檢測：Hash 一模一樣
    // 假設狀態必須改變 (例如 RNG)，如果沒變就是異常
    if (memcmp(snap->hash, current_hash, hlen) == 0) {
        fprintf(stderr,
                "[DEFENSE] Alert: State STUCK in %s! (Instruction Skip / No Update)\n",
                ctx);
        return 0;
    }

    // 2. Low-entropy 檢測：大部分為 0
    // 這代表記憶體被清空或未正確寫入
    if (estimate_low_entropy((const void *)p, snap->len)) {
        fprintf(stderr,
                "[DEFENSE] Alert: Low Entropy in %s! (Zeroing / Partial Write)\n",
                ctx);
        return 0;
    }

    return 1; // 通過檢查
}
 
#endif // DEFENSE_TRANSITION_H