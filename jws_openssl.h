#ifndef BETTER_AUTH_V_JWS_OPENSSL_H
#define BETTER_AUTH_V_JWS_OPENSSL_H

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "Better Auth V RSA/ECDSA support requires OpenSSL 3 or newer"
#endif

/* The shim handles EVP primitives, key material and signature encodings. JWT claims,
 * algorithm selection, key selection, persistence and authorization live in V. */
static int ba_ec_width(const char *alg) {
    if (!strcmp(alg,"ES256")) return 32;
    if (!strcmp(alg,"ES384")) return 48;
    if (!strcmp(alg,"ES512")) return 66;
    return 0;
}
static const char *ba_ec_group(const char *alg) {
    if (!strcmp(alg,"ES256")) return "prime256v1";
    if (!strcmp(alg,"ES384")) return "secp384r1";
    if (!strcmp(alg,"ES512")) return "secp521r1";
    return NULL;
}
static const char *ba_ec_curve(const char *alg) {
    if (!strcmp(alg,"ES256")) return "P-256";
    if (!strcmp(alg,"ES384")) return "P-384";
    if (!strcmp(alg,"ES512")) return "P-521";
    return NULL;
}
static int ba_rsa_alg(const char *alg) {
    return !strcmp(alg,"RS256") || !strcmp(alg,"RS384") || !strcmp(alg,"RS512") ||
           !strcmp(alg,"PS256") || !strcmp(alg,"PS384") || !strcmp(alg,"PS512");
}
static const EVP_MD *ba_digest(const char *alg) {
    if (strstr(alg,"256")) return EVP_sha256();
    if (strstr(alg,"384")) return EVP_sha384();
    if (strstr(alg,"512")) return EVP_sha512();
    return NULL;
}
static int ba_b64url(const unsigned char *in, size_t n, char *out, size_t cap) {
    if (n > 4096 || cap < 4*((n+2)/3)+1) return -1;
    int len = EVP_EncodeBlock((unsigned char*)out,in,(int)n);
    while (len > 0 && out[len-1]=='=') --len;
    for (int i=0;i<len;i++) { if (out[i]=='+') out[i]='-'; else if(out[i]=='/') out[i]='_'; }
    out[len]=0;
    return len;
}
static int ba_unb64url(const char *in, unsigned char *out, size_t cap) {
    size_t n=strlen(in), pad=(4-n%4)%4;
    if (n==0 || n>5460 || n%4==1 || cap < 3*((n+pad)/4)) return -1;
    unsigned char tmp[5465];
    for(size_t i=0;i<n;i++) {
        unsigned char c=(unsigned char)in[i];
        if (!((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='-'||c=='_')) return -1;
        tmp[i]=c=='-'?'+':c=='_'?'/':c;
    }
    for(size_t i=0;i<pad;i++) tmp[n+i]='=';
    int len=EVP_DecodeBlock(out,tmp,(int)(n+pad));
    if(len<0 || (size_t)len<pad) return -1;
    return len-(int)pad;
}
static int ba_append(char *out,size_t cap,size_t *used,const char *text) {
    size_t n=strlen(text);
    if(*used>=cap || n>=cap-*used) return 0;
    memcpy(out+*used,text,n); *used+=n; out[*used]=0; return 1;
}
static int ba_append_part(char *out,size_t cap,size_t *used,const char *name,const unsigned char *data,size_t len) {
    char value[5465], prefix[64];
    if(ba_b64url(data,len,value,sizeof(value))<0) return 0;
    int n=snprintf(prefix,sizeof(prefix),",\"%s\":\"",name);
    if(n<0 || (size_t)n>=sizeof(prefix)) return 0;
    return ba_append(out,cap,used,prefix)&&ba_append(out,cap,used,value)&&ba_append(out,cap,used,"\"");
}
static int ba_export_bn(EVP_PKEY *key,const char *param,const char *name,int width,char *out,size_t cap,size_t *used) {
    BIGNUM *bn=NULL; unsigned char data[4096]; int len;
    if(!EVP_PKEY_get_bn_param(key,param,&bn)) return 0;
    len=width?width:BN_num_bytes(bn);
    if(len<=0 || len>(int)sizeof(data) || BN_bn2binpad(bn,data,len)!=len) { BN_clear_free(bn); return 0; }
    int ok=ba_append_part(out,cap,used,name,data,(size_t)len);
    OPENSSL_cleanse(data,sizeof(data)); BN_clear_free(bn); return ok;
}
static int ba_export_key(EVP_PKEY *key,const char *alg,int priv,char *out,size_t cap,size_t *used) {
    int width=ba_ec_width(alg);
    if(width) {
        char prefix[80]; snprintf(prefix,sizeof(prefix),"{\"kty\":\"EC\",\"crv\":\"%s\"",ba_ec_curve(alg));
        if(!ba_append(out,cap,used,prefix)||!ba_export_bn(key,OSSL_PKEY_PARAM_EC_PUB_X,"x",width,out,cap,used)||
           !ba_export_bn(key,OSSL_PKEY_PARAM_EC_PUB_Y,"y",width,out,cap,used)) return 0;
        if(priv&&!ba_export_bn(key,OSSL_PKEY_PARAM_PRIV_KEY,"d",width,out,cap,used)) return 0;
    } else {
        if(!ba_append(out,cap,used,"{\"kty\":\"RSA\"")||!ba_export_bn(key,OSSL_PKEY_PARAM_RSA_N,"n",0,out,cap,used)||
           !ba_export_bn(key,OSSL_PKEY_PARAM_RSA_E,"e",0,out,cap,used)) return 0;
        if(priv) {
            const char *params[]={OSSL_PKEY_PARAM_RSA_D,OSSL_PKEY_PARAM_RSA_FACTOR1,OSSL_PKEY_PARAM_RSA_FACTOR2,
                OSSL_PKEY_PARAM_RSA_EXPONENT1,OSSL_PKEY_PARAM_RSA_EXPONENT2,OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
            const char *names[]={"d","p","q","dp","dq","qi"};
            for(int i=0;i<6;i++) if(!ba_export_bn(key,params[i],names[i],0,out,cap,used)) return 0;
        }
    }
    return ba_append(out,cap,used,"}");
}
static int ba_generate_jwk(const char *alg,int bits,unsigned char *out,size_t cap,size_t *length) {
    int ec=ba_ec_width(alg), ok=0; EVP_PKEY *key=NULL; EVP_PKEY_CTX *ctx=NULL; size_t used=0;
    if(!ec&&!ba_rsa_alg(alg)) return 0;
    if(!ec&&(bits<2048||bits>8192)) return 0;
    ctx=EVP_PKEY_CTX_new_from_name(NULL,ec?"EC":"RSA",NULL);
    if(!ctx||EVP_PKEY_keygen_init(ctx)<=0) goto done;
    if(ec) { if(EVP_PKEY_CTX_set_group_name(ctx,ba_ec_group(alg))<=0) goto done; }
    else if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx,bits)<=0) goto done;
    if(EVP_PKEY_generate(ctx,&key)<=0) goto done;
    if(!ba_append((char*)out,cap,&used,"{\"public\":")||!ba_export_key(key,alg,0,(char*)out,cap,&used)||
       !ba_append((char*)out,cap,&used,",\"private\":")||!ba_export_key(key,alg,1,(char*)out,cap,&used)||
       !ba_append((char*)out,cap,&used,"}")) goto done;
    *length=used; ok=1;
done:
    EVP_PKEY_free(key); EVP_PKEY_CTX_free(ctx); return ok;
}

/* fields: n,e,d,p,q,dp,dq,qi,x,y. Empty private fields are valid for public import. */
static EVP_PKEY *ba_import_jwk(const char *alg,const char **fields,int priv) {
    int width=ba_ec_width(alg), count=0, ok=0; EVP_PKEY *key=NULL; EVP_PKEY_CTX *ctx=NULL,*check=NULL;
    OSSL_PARAM_BLD *builder=NULL; OSSL_PARAM *params=NULL; BIGNUM *bns[8]={0};
    unsigned char decoded[4096], point[133];
    if(!width&&!ba_rsa_alg(alg)) return NULL;
    builder=OSSL_PARAM_BLD_new(); if(!builder) goto done;
    if(width) {
        point[0]=4;
        if(ba_unb64url(fields[8],decoded,sizeof(decoded))!=width) goto done;
        memcpy(point+1,decoded,(size_t)width);
        if(ba_unb64url(fields[9],decoded,sizeof(decoded))!=width) goto done;
        memcpy(point+1+width,decoded,(size_t)width);
        if(!OSSL_PARAM_BLD_push_utf8_string(builder,OSSL_PKEY_PARAM_GROUP_NAME,ba_ec_group(alg),0)||
           !OSSL_PARAM_BLD_push_octet_string(builder,OSSL_PKEY_PARAM_PUB_KEY,point,(size_t)(1+width*2))) goto done;
        if(priv) {
            int n=ba_unb64url(fields[2],decoded,sizeof(decoded)); if(n!=width) goto done;
            bns[count]=BN_bin2bn(decoded,n,NULL); if(!bns[count]) goto done;
            if(!OSSL_PARAM_BLD_push_BN(builder,OSSL_PKEY_PARAM_PRIV_KEY,bns[count++])) goto done;
        }
    } else {
        const char *names[]={OSSL_PKEY_PARAM_RSA_N,OSSL_PKEY_PARAM_RSA_E,OSSL_PKEY_PARAM_RSA_D,
            OSSL_PKEY_PARAM_RSA_FACTOR1,OSSL_PKEY_PARAM_RSA_FACTOR2,OSSL_PKEY_PARAM_RSA_EXPONENT1,
            OSSL_PKEY_PARAM_RSA_EXPONENT2,OSSL_PKEY_PARAM_RSA_COEFFICIENT1};
        for(int i=0;i<(priv?8:2);i++) {
            int n=ba_unb64url(fields[i],decoded,sizeof(decoded)); if(n<=0) goto done;
            bns[count]=BN_bin2bn(decoded,n,NULL); if(!bns[count]) goto done;
            if(!OSSL_PARAM_BLD_push_BN(builder,names[i],bns[count++])) goto done;
        }
    }
    params=OSSL_PARAM_BLD_to_param(builder); if(!params) goto done;
    ctx=EVP_PKEY_CTX_new_from_name(NULL,width?"EC":"RSA",NULL);
    if(!ctx||EVP_PKEY_fromdata_init(ctx)<=0||EVP_PKEY_fromdata(ctx,&key,priv?EVP_PKEY_KEYPAIR:EVP_PKEY_PUBLIC_KEY,params)<=0) goto done;
    if(!width && EVP_PKEY_get_bits(key)<2048) goto done;
    check=EVP_PKEY_CTX_new_from_pkey(NULL,key,NULL);
    if(!check || (priv ? EVP_PKEY_pairwise_check(check) : EVP_PKEY_public_check(check))<=0) goto done;
    ok=1;
done:
    OPENSSL_cleanse(decoded,sizeof(decoded));
    for(int i=0;i<8;i++) BN_clear_free(bns[i]);
    OSSL_PARAM_free(params); OSSL_PARAM_BLD_free(builder); EVP_PKEY_CTX_free(ctx); EVP_PKEY_CTX_free(check);
    if(!ok) { EVP_PKEY_free(key); key=NULL; } return key;
}
static int ba_jws_padding(EVP_PKEY_CTX *ctx,const char *alg) {
    if(!ba_rsa_alg(alg)) return 1;
    int pss=alg[0]=='P';
    if(EVP_PKEY_CTX_set_rsa_padding(ctx,pss?RSA_PKCS1_PSS_PADDING:RSA_PKCS1_PADDING)<=0) return 0;
    return !pss||EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx,RSA_PSS_SALTLEN_DIGEST)>0;
}
static int ba_sign_jwk(const char *alg,const char **fields,const unsigned char *message,size_t n,unsigned char *out,size_t cap,size_t *length) {
    int ok=0, width=ba_ec_width(alg); EVP_PKEY *key=ba_import_jwk(alg,fields,1); EVP_MD_CTX *ctx=NULL;
    EVP_PKEY_CTX *pctx=NULL; ECDSA_SIG *ecsig=NULL; unsigned char sig[2048]; size_t len=sizeof(sig);
    if(!key) goto done;
    ctx=EVP_MD_CTX_new();
    if(!ctx||EVP_DigestSignInit(ctx,&pctx,ba_digest(alg),NULL,key)<=0||!ba_jws_padding(pctx,alg)||
       EVP_DigestSign(ctx,sig,&len,message,n)<=0) goto done;
    if(width) {
        const unsigned char *start=sig; const BIGNUM *r,*s;
        ecsig=d2i_ECDSA_SIG(NULL,&start,(long)len);
        if(!ecsig||cap<(size_t)width*2) goto done;
        ECDSA_SIG_get0(ecsig,&r,&s);
        if(BN_bn2binpad(r,out,width)!=width||BN_bn2binpad(s,out+width,width)!=width) goto done;
        *length=(size_t)width*2;
    } else {
        if(cap<len) goto done;
        memcpy(out,sig,len); *length=len;
    }
    ok=1;
done:
    EVP_PKEY_free(key); EVP_MD_CTX_free(ctx); ECDSA_SIG_free(ecsig); return ok;
}
static int ba_verify_jwk(const char *alg,const char **fields,const unsigned char *message,size_t n,const unsigned char *sig,size_t len) {
    int ok=0,width=ba_ec_width(alg); EVP_PKEY *key=ba_import_jwk(alg,fields,0); EVP_MD_CTX *ctx=NULL;
    EVP_PKEY_CTX *pctx=NULL; ECDSA_SIG *ecsig=NULL; unsigned char *der=NULL; int derlen;
    if(!key) goto done;
    if(width) {
        if(len!=(size_t)width*2) goto done;
        BIGNUM *r=BN_bin2bn(sig,width,NULL),*s=BN_bin2bn(sig+width,width,NULL);
        ecsig=ECDSA_SIG_new();
        if(!r||!s||!ecsig) { BN_free(r); BN_free(s); goto done; }
        if(!ECDSA_SIG_set0(ecsig,r,s)) { BN_free(r); BN_free(s); goto done; }
        derlen=i2d_ECDSA_SIG(ecsig,&der); if(derlen<=0) goto done;
        sig=der; len=(size_t)derlen;
    }
    ctx=EVP_MD_CTX_new();
    if(!ctx||EVP_DigestVerifyInit(ctx,&pctx,ba_digest(alg),NULL,key)<=0||!ba_jws_padding(pctx,alg)) goto done;
    ok=EVP_DigestVerify(ctx,sig,len,message,n)==1;
done:
    OPENSSL_free(der); ECDSA_SIG_free(ecsig); EVP_MD_CTX_free(ctx); EVP_PKEY_free(key); return ok;
}
/* HChaCha20 runs in V. This boundary handles only IETF ChaCha20-Poly1305 AEAD.
 * Encrypt: output ciphertext || tag. Decrypt: authenticate before returning any
 * plaintext and cleanse the output buffer on failure. Inputs are length-checked
 * before OpenSSL's int-sized update API is called. */
static int ba_chacha_encrypt(const unsigned char *key,const unsigned char *iv,const unsigned char *data,size_t length,unsigned char *out) {
    if(length > INT_MAX) return 0;
    EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); int n=0,tail=0,ok=0;
    if(!ctx) return 0;
    if(EVP_EncryptInit_ex(ctx,EVP_chacha20_poly1305(),NULL,key,iv)!=1) goto done;
    if(EVP_EncryptUpdate(ctx,out,&n,data,(int)length)!=1 || n!=(int)length) goto done;
    if(EVP_EncryptFinal_ex(ctx,out+n,&tail)!=1 || tail!=0) goto done;
    if(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_GET_TAG,16,out+length)!=1) goto done;
    ok=1;
done:
    EVP_CIPHER_CTX_free(ctx); return ok;
}
static int ba_chacha_decrypt(const unsigned char *key,const unsigned char *iv,const unsigned char *data,size_t length,unsigned char *out) {
    if(length<16 || length-16>INT_MAX) return 0;
    size_t size=length-16; EVP_CIPHER_CTX *ctx=EVP_CIPHER_CTX_new(); int n=0,tail=0,ok=0;
    if(!ctx) return 0;
    if(EVP_DecryptInit_ex(ctx,EVP_chacha20_poly1305(),NULL,key,iv)!=1) goto done;
    if(EVP_CIPHER_CTX_ctrl(ctx,EVP_CTRL_AEAD_SET_TAG,16,(void *)(data+size))!=1) goto done;
    if(EVP_DecryptUpdate(ctx,out,&n,data,(int)size)!=1 || n!=(int)size) goto done;
    if(EVP_DecryptFinal_ex(ctx,out+n,&tail)!=1 || tail!=0) goto done;
    ok=1;
done:
    if(!ok && size) OPENSSL_cleanse(out,size);
    EVP_CIPHER_CTX_free(ctx); return ok;
}

#endif
