#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

// 檢查 buffer 是否全為 0
int is_all_zero(const uint8_t *buf, size_t len) {
    for(size_t i=0; i<len; i++) if(buf[i] != 0) return 0;
    return 1;
}

int main() {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    uint8_t *pk=malloc(sig->length_public_key), *sk=malloc(sig->length_secret_key);
    OQS_SIG_keypair(sig,pk,sk);
    
    uint8_t *buf=malloc(sig->length_signature);
    size_t sl;
    char msg[]="Fixed";
    uint8_t **rec=calloc(100,sizeof(uint8_t*));
    
    int gen=0, blk=0, col=0;
    
    for(int i=0;i<100;i++){
        memset(buf,0,sig->length_signature);
        
        int ret = OQS_SIG_sign(sig, buf, &sl, (uint8_t*)msg, 5, sk);
        
        // [CRITICAL FIX] 
        // 如果 ret 成功，但 buffer 還是全 0，代表底層提早 return 了 (Implicit Block)
        if (ret == OQS_SUCCESS && is_all_zero(buf, sig->length_signature)) {
            ret = OQS_ERROR; // 視為錯誤
        }

        if(ret == OQS_SUCCESS) {
            gen++;
            int dup=0;
            for(int j=0;j<i;j++){
                if(rec[j] && memcmp(rec[j],buf,sig->length_signature)==0){
                    col++; dup=1; break;
                }
            }
            if(!dup){
                rec[i]=malloc(sig->length_signature);
                memcpy(rec[i],buf,sig->length_signature);
            }
        } else {
            blk++; 
        }
    }
    printf("100,%d,%d,%d\n", gen, blk, col);
    return 0;
}
