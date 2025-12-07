#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        // 這裡呼叫 liboqs，如果防禦生效，會回傳非 Success
        int r=OQS_SIG_sign(sig,buf,&sl,(uint8_t*)msg,5,sk);
        
        if(r==OQS_SUCCESS){
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
            blk++; // Blocked by defense
        }
    }
    printf("100,%d,%d,%d\n", gen, blk, col);
    return 0;
}
