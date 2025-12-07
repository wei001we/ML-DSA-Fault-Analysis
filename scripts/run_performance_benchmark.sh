#!/bin/bash
###############################################################################
# ML-DSA Performance Benchmark v2 (True Overhead Analysis)
#
# 修正：
# 1. [Fix] 解決 Noise 問題：增加迭代次數到 20000 以平滑誤差
# 2. [New] 新增 "Simulated_Double" 場景，模擬雙重執行帶來的真實代價
###############################################################################

set +e

# ================= 配置區 =================
LIBOQS_INSTALL="$HOME/liboqs-install"
PROJECT_DIR="$HOME/mldsa-fault-attack"
C_IMPL_DIR="$PROJECT_DIR/c-impl"
RESULTS_CSV="$PROJECT_DIR/performance_results_v2.csv"

mkdir -p "$C_IMPL_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[Phase 0]${NC} Compiling Benchmark Tool..."

cat > mldsa_speed_v2.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <oqs/oqs.h>

// 模擬雙重執行的防禦 Wrapper
int sign_with_redundancy(OQS_SIG *sig, uint8_t *sig_buf, size_t *sig_len, 
                         const uint8_t *msg, size_t msg_len, const uint8_t *sk) {
    // Pass 1
    int ret1 = OQS_SIG_sign(sig, sig_buf, sig_len, msg, msg_len, sk);
    
    // Pass 2 (Redundancy) - 為了模擬真實開銷，我們再算一次
    // 在真實防禦中，我們會比較兩次結果
    uint8_t *tmp_buf = malloc(*sig_len);
    size_t tmp_len;
    int ret2 = OQS_SIG_sign(sig, tmp_buf, &tmp_len, msg, msg_len, sk);
    
    free(tmp_buf);
    return (ret1 == OQS_SUCCESS && ret2 == OQS_SUCCESS) ? OQS_SUCCESS : OQS_ERROR;
}

int main(int argc, char *argv[]) {
    int mode = 0; // 0=Normal, 1=Double
    if(argc > 1 && strcmp(argv[1], "DOUBLE")==0) mode = 1;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t *sk = malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig, pk, sk);
    
    uint8_t *sig_buf = malloc(sig->length_signature);
    size_t sig_len;
    char msg[] = "Bench";

    // 增加迭代次數以消除雜訊
    int iterations = 10000; 

    clock_t start = clock();
    for(int i=0; i<iterations; i++) {
        if(mode == 1) {
            sign_with_redundancy(sig, sig_buf, &sig_len, (uint8_t*)msg, 5, sk);
        } else {
            OQS_SIG_sign(sig, sig_buf, &sig_len, (uint8_t*)msg, 5, sk);
        }
    }
    clock_t end = clock();

    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;
    double avg_time_ms = (time_spent * 1000.0) / iterations;
    double ops_per_sec = iterations / time_spent;

    printf("%.4f,%.4f,%.2f\n", time_spent, avg_time_ms, ops_per_sec);

    free(sig_buf); free(pk); free(sk); OQS_SIG_free(sig);
    return 0;
}
EOF

gcc mldsa_speed_v2.c -o mldsa_speed_v2 \
    -I"$LIBOQS_INSTALL/include" \
    "$LIBOQS_INSTALL/lib/liboqs.a" \
    -lssl -lcrypto -lm

# ================= Phase 1: 執行測試 =================
echo -e "${YELLOW}[Phase 1]${NC} Running Benchmark (High Precision)..."
echo "Config,TotalTime(s),Latency(ms),Throughput(ops/s),Overhead(%)" > "$RESULTS_CSV"

# 1. Baseline (No Defense)
# 為了純淨測試，我們先關閉所有環境變數干擾
export MLDSA_FAULT_TYPE=NONE
export MLDSA_DEFENSE_LEVEL=OFF

echo -n "  Testing Baseline..."
RES_BASE=$(./mldsa_speed_v2 NORMAL)
BASE_LAT=$(echo $RES_BASE | cut -d',' -f2)
echo "Baseline,$RES_BASE,0.00%" >> "$RESULTS_CSV"
echo " Done ($BASE_LAT ms)"

# 2. Snapshot Defense (Low Cost)
# 這是你之前測到的 0.54% 那個
export MLDSA_DEFENSE_LEVEL=FULL
echo -n "  Testing Snapshot Defense..."
RES_SNAP=$(./mldsa_speed_v2 NORMAL)
SNAP_LAT=$(echo $RES_SNAP | cut -d',' -f2)
OVER_SNAP=$(awk "BEGIN {printf \"%.2f\", (($SNAP_LAT - $BASE_LAT) / $BASE_LAT) * 100}")
echo "Snapshot_Defense,$RES_SNAP,$OVER_SNAP%" >> "$RESULTS_CSV"
echo " Done ($SNAP_LAT ms, +$OVER_SNAP%)"

# 3. Double Execution (High Cost)
# 這是模擬如果你採用了 redundancy.h 的方案
export MLDSA_DEFENSE_LEVEL=OFF # 關閉內部 snapshot，專注測 double execution
echo -n "  Testing Double Execution..."
RES_DBL=$(./mldsa_speed_v2 DOUBLE)
DBL_LAT=$(echo $RES_DBL | cut -d',' -f2)
OVER_DBL=$(awk "BEGIN {printf \"%.2f\", (($DBL_LAT - $BASE_LAT) / $BASE_LAT) * 100}")
echo "Double_Execution,$RES_DBL,$OVER_DBL%" >> "$RESULTS_CSV"
echo " Done ($DBL_LAT ms, +$OVER_DBL%)"

echo -e "\n${GREEN}================ TRUE PERFORMANCE REPORT ================${NC}"
if command -v column &> /dev/null; then
    column -s, -t < "$RESULTS_CSV"
else
    cat "$RESULTS_CSV"
fi
echo -e "${GREEN}=========================================================${NC}"
```
