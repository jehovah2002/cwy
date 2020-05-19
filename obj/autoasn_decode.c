#include "autoasn.h"
#include "common.h"


int DecodeSubjectAttribute(const char *OPTIONAL,const char *pubkeyx,const char *pubkeyy,unsigned char *outstr)
{
/*
typedef struct SubjectAttribute {
    char Optional[LUint8];
	PublicVerifyKey_t verificationKey;
	PublicEncryptionKey_t *encryptionKey;	// OPTIONAL
	MotCert_SubjectAssurance_t *assuranceLevel;// OPTIONAL
	SequenceOfitsAidList_t	*itsAidList;	// OPTIONAL
	SequenceOfitsAidSspList_t *itsAidSspList;	// OPTIONAL
} SubjectAttribute_t;


*/
    int str_len=0;
    int str_len_verificationKey=0;
    char out_buf[256]={0};


    return str_len;
}

int DecodeSignPublicVerifyKey(const int EccCurve,const int ECCPoint,const char *pubkeyx,const char *pubkeyy,unsigned char *outstr)
{
    /* 
    //PublicVerifyKey 
    typedef struct PublicVerifyKey {
        char ExAttr[LUint8];//={"00"}; for SEQUENCE ...
        char curve[LENUME];
        MotBaseTypes_ECCPoint_t  key;
    } PublicVerifyKey_t;

    //ECCPoint
    typedef struct MotBaseTypes_ECCPoint {
    	char Choice[LENUME];
    	union MotBaseTypes_ECCPoint_u {
    		char sm2_x_only[LKey];
    		char *sm2_fill;//NULL
    		char sm2_compressed_y_0[LKey];
    		char sm2_compressed_y_1[LKey];
    		UncompressedP256_t	 sm2_uncompressedP256;
    	} choice;
    } MotBaseTypes_ECCPoint_t;
    */

    int str_len=0;
    int exattr=0;
    char out_buf[2+2+64+64]={0};

    return str_len;
}

int DecodeSubjectInfo(const int subjectType,const char *subjectname,unsigned char *outstr)
{
/*
//SubjectInfo 
typedef struct SubjectInfo {
	char subjectType[LENUME];//=00
	OCTET_STRING_t subjectName;//subjectName 00~FF

} SubjectInfo_t;

typedef struct OCTET_STRING {
    char bufsize[LUint8];
	uint8_t *buf;
} OCTET_STRING_t;

*/
    char out_buf[128]={0};
    char buf_name[64]={0};
    int str_len=0;
    

    return str_len;
}

