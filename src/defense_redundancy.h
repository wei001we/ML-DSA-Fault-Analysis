#ifndef DEFENSE_REDUNDANCY_H
#define DEFENSE_REDUNDANCY_H

#include "defense_policy.h"

// 關鍵運算介面：out_len / in_len 分開
typedef void (*CriticalOp2)(uint8_t *out, size_t out_len,
                            const uint8_t *in, size_t in_len);

// 可選：簡單的隨機 delay，降低兩次執行被同一個 glitch 擊中的機率
static inline void defense_random_delay(void) {
    int loops = rand() % 32; // 0~31
    volatile int dummy = 0;
    for (int i = 0; i < loops; i++) {
        dummy ^= i;
    }
}

// 雙重執行檢查 (No-Malloc 版本)
// work_buf1, work_buf2: 必須由 Caller 提供，大小至少為 out_len
static inline int defense_duplicate_check_no_malloc(
                            const DefenseConfig *cfg,
                            CriticalOp2 op,
                            uint8_t *real_out, size_t out_len,
                            const uint8_t *in, size_t in_len,
                            uint8_t *work_buf1,
                            uint8_t *work_buf2) {
    if (!cfg || !op || !real_out) return 0;

    // 若未啟用 duplication，直接執行一次
    if (!cfg->enable_duplication) {
        op(real_out, out_len, in, in_len);
        return 1;
    }

    // 第一次執行
    op(work_buf1, out_len, in, in_len);

    // 插入輕量隨機 delay，降低相關性
    defense_random_delay();

    // 第二次執行
    op(work_buf2, out_len, in, in_len);

    // 常數時間比較（避免 memcmp 最佳化導致時序洩漏）
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < out_len; i++) {
        diff |= (uint8_t)(work_buf1[i] ^ work_buf2[i]);
    }

    if (diff != 0) {
        fprintf(stderr,
                "[DEFENSE] Critical Alert: Computation Mismatch! (Transient Fault)\n");
        // 安全清除暫存區
        memset(work_buf1, 0, out_len);
        memset(work_buf2, 0, out_len);
        return 0; // 失敗
    }

    // 結果一致 → 寫回 real_out
    memcpy(real_out, work_buf1, out_len);

    // 清除敏感資料
    memset(work_buf1, 0, out_len);
    memset(work_buf2, 0, out_len);
    return 1;
}
  
#endif // DEFENSE_REDUNDANCY_H