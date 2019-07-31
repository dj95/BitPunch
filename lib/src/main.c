#include <bitpunch/bitpunch.h>
#include "bitpunch/tools.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <bitpunch/crypto/hash/sha512.h>
#include <bitpunch/asn1/asn1.h>
#include <bitpunch/math/bigint.h>
#include <bitpunch/math/uni.h>


int testKeyGenEncDec(BPU_T_Mecs_Ctx * ctx) {
    BPU_T_GF2_Vector *ct, *pt_in, *pt_out;

    printf(":: Starting key generation...\n");

    // key pair generation
    if (BPU_mecsGenKeyPair(ctx)) {
        BPU_printError("Key generation error");

        return 1;
    }

    printf(":: Choosing random plain text\n");

    // prepare plain text, allocate memory and init random plaintext
    if (BPU_gf2VecMalloc(&pt_in, ctx->pt_len)) {
        BPU_printError("PT initialisation error");

        return 1;
    }

    BPU_gf2VecRand(pt_in, 0);

    // alocate cipher text vector
    if (BPU_gf2VecMalloc(&ct, ctx->ct_len)) {
        BPU_printError("CT vector allocation error");

        BPU_gf2VecFree(&pt_in);
        return 1;
    }

    // prepare plain text, allocate memory and init random plaintext
    if (BPU_gf2VecMalloc(&pt_out, ctx->pt_len)) {
        BPU_printError("PT out initialisation error");

        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt_in);
        return 1;
    }

    BPU_gf2VecRand(pt_out, 0);

    // BPU_encrypt plain text
    printf(":: Encryption...\n");

    if (BPU_mecsEncrypt(ct, pt_in, ctx)) {
        BPU_printError("Encryption error");

        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt_in);
        BPU_gf2VecFree(&pt_out);
        return 1;
    }

    // decrypt cipher text
    printf(":: Decryption...\n");

    if (BPU_mecsDecrypt(pt_out, ct, ctx)) {
        BPU_printError("Decryption error");

        BPU_gf2VecFree(&ct);
        BPU_gf2VecFree(&pt_in);
        BPU_gf2VecFree(&pt_out);
        return 1;
    }

    // check for correct decryption
    printf(":: Verifying the encryption and decryption worked\n");

    char *result = "  ✅ - Input plain text is equal to output plain text\n";

    if (BPU_gf2VecCmp(pt_in, pt_out)) {
        result = "  🔴 - Output plain text differs from input\n";
    } 

    printf("%s", result);

    // clean up
    printf(":: Cleaning up...\n");

    BPU_gf2VecFree(&ct);
    BPU_gf2VecFree(&pt_in);
    BPU_gf2VecFree(&pt_out);

    return 0;
}


int main(int argc, char **argv) {
    // MUST BE NULL
    BPU_T_Mecs_Ctx *ctx = NULL;
    BPU_T_UN_Mecs_Params params;

    // plant the seed... 🌻
    srand(time(NULL));

    // default arguments
    int m = 11;
    int t = 50;
    int save = 0;

    // parse command line arguments
    for (int i=0; i<argc; i++) {
        if (strcmp(argv[i], "-h") == 0) {
            printf("Usage: %s -m M -t T -s\n", argv[0]);
    
            return 0;
        }


        if (strcmp(argv[i], "-m") == 0) {
            m = atoi(argv[++i]);
        }

        if (strcmp(argv[i], "-t") == 0) {
            t = atoi(argv[++i]);
        }

        if (strcmp(argv[i], "-s") == 0) {
            save = 1;
        }
    }

    // print some stats
    printf(":: Using the following parameters:\n");
    printf("    m = %d\t n = %d\n", m, 1 << m);
    printf("    t = %d\t k = %d\n", t, (1 << m) - (m*t));

    // initialize gopper parameter
    if (BPU_mecsInitParamsGoppa(&params, m, t, 0)) {
        return 1;
    }

    // initialize gopper context
    if (BPU_mecsInitCtx(&ctx, &params, BPU_EN_MECS_BASIC_GOPPA)) {
        return 1;
    }

    // test the key generation, encryption and decryption
    if(testKeyGenEncDec(ctx)) {
        printf("  🔴 KeyGenEncDec failed\n");
    }

    // save the keys if the command line flag is set
    if (save) {
        printf(":: saving keys to prikey.der and pubkey.der\n");

        if (BPU_asn1SaveKeyPair(ctx, "prikey.der", "pubkey.der")) {
            printf("  🔴 cannot save keys to file\n");
        }

        printf("  ✅ successfully saved keys to file\n");
    }

    BPU_mecsFreeCtx(&ctx);
}

