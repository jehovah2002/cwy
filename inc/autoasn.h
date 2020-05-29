#ifndef _AUTOASN_H_
#define _AUTOASN_H_


#ifdef  __cplusplus
  extern "C" {
#endif



#include <stddef.h>



typedef	unsigned char	uint8_t;
typedef	unsigned short	uint16_t;
typedef	unsigned int	uint32_t;
//#define	ssize_t SSIZE_T

typedef struct asn_struct_ctx_s {
	short phase;		/* Decoding phase */
	short step;		/* Elementary step of a phase */
	int context;		/* Other context information */
	void *ptr;		/* Decoder-specific stuff (stack elements) */
	//ssize_t left;	/* Number of bytes left, -1 for indefinite */
	unsigned long left;
} asn_struct_ctx_t;

#ifdef __cplusplus
#define A_SET_OF(type)                   \
    struct {                             \
        type **array;                    \
        int count; /* Meaningful size */ \
        int size;  /* Allocated size */  \
        void (*free)(decltype(*array));  \
    }
#else   /* C */
#define A_SET_OF(type)                   \
    struct {                             \
        type **array;                    \
        int count; /* Meaningful size */ \
        int size;  /* Allocated size */  \
        void (*free)(type *);    \
    }
#endif

#define	A_SEQUENCE_OF(type)	A_SET_OF(type)



#define PWDFILE "./passwordkey"
#define LENUME 2*2+1
#define LVERSION 2+1
#define LCHOICE 2+1
#define LLENGTHO 2+1
#define LOPAQUELENGTH 4+1
#define LHASHID 2+1
#define LTIME 4*2+1
#define LUint8 2+1
#define LUint16 4+1
#define LUint32 8+1
#define LUint64 16+1
#define LUint128 32+1
#define LKey 64+1



#define OCTETSTRING 4096

typedef enum SubjectType {
	SubjectType_enrollmentCredential	= 0,
	SubjectType_authorizationTicket	= 1,
	SubjectType_authorizationAuthority	= 2,
	SubjectType_enrollmentAuthority	= 3,
	SubjectType_rootCa	= 4,
	SubjectType_crlSigner	= 5,
	SubjectType_pgAuthority	= 6,
	SubjectType_misbehaviorAuthority	= 7,
	SubjectType_icaAuthority	= 8,
	SubjectType_asAuthority	= 9
} e_SubjectType;

typedef enum IssuerId_PR {
	IssuerId_PR_NOTHING,	/* No components present */
	IssuerId_PR_self = 80,
	IssuerId_PR_certificateDigest
	/* Extensions may appear below */
	
} IssuerId_PR;


typedef enum CScmsSecureData_Payload_PR {
	CScmsSecureData_Payload_PR_NOTHING,	/* No components present */
	CScmsSecureData_Payload_PR_unSecuredData = 80,
	CScmsSecureData_Payload_PR_signedData,
	CScmsSecureData_Payload_PR_encData,
	CScmsSecureData_Payload_PR_signedCertificateRequest
} CScmsSecureData_Payload_PR;


typedef enum MotCert_ValidityPeriod_PR {
	PR_timeEnd = 80,
	PR_timeStartAndEnd
} MotCert_ValidityPeriod_PR;


typedef enum CompressType {
	asnxonly = 80,
    asnfill,
    asncompressedy0,
    asncompressedy1,
    asnuncompressedP256
} e_CompressType;


typedef enum EccCurve {
	sgdsm2 =0,
    nistP256,
    brainpoolP256r
} e_EccCurve;

typedef enum SymmAlgorithm { 
    sgdsm4ecb=0,
    sgdsm4cbc,
    sgdsm4cfb,
    sgdsm4ofb,
    aes128Ccm
} e_SymmAlgorithm;

typedef enum CScmsCertificate_PR {
	CScmsCertificate_PR_NOTHING,	/* No components present */
	CScmsCertificate_PR_x509 = 80,
	CScmsCertificate_PR_ieee1609,
	CScmsCertificate_PR_cicv,
	CScmsCertificate_PR_mot
} CScmsCertificate_PR;

typedef enum CScmsCertificateTbs_PR {
	CScmsCertificateTbs_PR_NOTHING,	/* No components present */
	CScmsCertificateTbs_PR_ieee1609 = 80,
	CScmsCertificateTbs_PR_cicv,
	CScmsCertificateTbs_PR_mot
} CScmsCertificateTbs_PR;

typedef enum EndEntityAsInterfacePDU_PR {
	NOTHING,	/* No components present */
	eeAsPseudonymCertProvisioningRequest = 80,
	asEePseudonymCertProvisioningAck,
	eeAsAuthenticatedDownloadRequest
	/* Extensions may appear below */
	
} EndEntityAsInterfacePDU_PR;

typedef enum EcaEndEntityInterfacePDU_PR {
	EcaEndEntityInterfacePDU_PR_NOTHING,	/* No components present */
	EcaEndEntityInterfacePDU_PR_eeEcaCertRequest = 80,
	EcaEndEntityInterfacePDU_PR_ecaEeCertResponse
	/* Extensions may appear below */
	
} EcaEndEntityInterfacePDU_PR;


typedef enum CScmsPDUContent_PR {
	CScmsPDUContent_PR_NOTHING,	/* No components present */
	CScmsPDUContent_PR_eca_ee = 80,
	CScmsPDUContent_PR_ee_ma,
	CScmsPDUContent_PR_ee_as
	/* Extensions may appear below */
	
} CScmsPDUContent_PR;

typedef enum CScmsSecureData_SignerInfo_PR {
	CScmsSecureData_SignerInfo_PR_NOTHING,	/* No components present */
	CScmsSecureData_SignerInfo_PR_self =80,
	CScmsSecureData_SignerInfo_PR_certificate = 81
	/* Extensions may appear below */
	
} CScmsSecureData_SignerInfo_PR;

typedef enum EndEntityMaInterface_Payload_PR {
	EndEntityMaInterface_Payload_PR_unSecuredData=80,
	EndEntityMaInterface_Payload_PR_signedData,
	EndEntityMaInterface_Payload_PR_encData,
	EndEntityMaInterface_Payload_PR_SecuredMessage,
} EndEntityMaInterface_Payload_PR;


typedef struct OCTET_STRING {
    int bufsize;//DEC Buf direct length
	uint8_t buf[256+1];	/* Buffer with consecutive OCTET_STRING bits */
} OCTET_STRING_t;

typedef struct OCTET_LONG_STRING {
    int bufsize;//DEC Buf direct length
	uint8_t buf[4096];	/* Buffer with consecutive OCTET_STRING bits */
} OCTET_LONG_STRING_t;


typedef struct IEEE1609dot2_ToBeSignedCertificate {

    char *_asn_ctx;

}IEEE1609dot2_ToBeSignedCertificate_t;
typedef IEEE1609dot2_ToBeSignedCertificate_t	 IeeeCertificateTbs_t;

typedef struct CICVCert_ToBeSignedCertificate {

    char  *_asn_ctx;

} CICVCert_ToBeSignedCertificate_t;
typedef CICVCert_ToBeSignedCertificate_t	 CicvCertificateTbs_t;

/* SubjectInfo */
typedef struct SubjectInfo {
	int subjectType;//=00
	OCTET_STRING_t subjectName;

} SubjectInfo_t;

/* UncompressedP256 */
typedef struct UncompressedP256 {
	char x[64+1];
	char y[64+1];
} UncompressedP256_t;


/* ECCPoint */
typedef struct MotBaseTypes_ECCPoint {
	int Choice;
	union MotBaseTypes_ECCPoint_u {
		char sm2_x_only[LKey];
		char *sm2_fill;//NULL
		char sm2_compressed_y_0[LKey];
		char sm2_compressed_y_1[LKey];
		UncompressedP256_t	 sm2_uncompressedP256;
	} MotBaseTypes_ECCPoint_u;
} MotBaseTypes_ECCPoint_t;


/* PublicVerifyKey */
typedef struct PublicVerifyKey {
    int ExAttr;//={"00"}; for OPTIONAL ...
	int curve;
	MotBaseTypes_ECCPoint_t	 key;
} PublicVerifyKey_t;

/* PublicVerifyKey */
typedef struct PublicEncryptionKey {
    int SymmAlgorithm;
	int curve;
	MotBaseTypes_ECCPoint_t	 key;
} PublicEncryptionKey_t;


/* SequenceOfitsAidList */
typedef struct SequenceOfitsAidSspList {
	char ItsAid[LUint64];
    OCTET_STRING_t serviceSpecificPermissions;
} SequenceOfitsAidSspList_t;

/* TimeStartAndEnd */
typedef struct MotCert_TimeStartAndEnd {
	long startValidity;
	long endValidity;
} MotCert_TimeStartAndEnd_t;

/* ValidityPeriod */
typedef struct MotCert_ValidityPeriod {
	int Choice;
	union MotCert_ValidityPeriod_u {
		long timeEnd;
		MotCert_TimeStartAndEnd_t	 timeStartAndEnd;
	} MotCert_ValidityPeriod_u;
} MotCert_ValidityPeriod_t;

/* TwoDLocation */
typedef struct MotBaseTypes_TwoDLocation {
	char latitude[LUint64];
	char longitude[LUint64];
} MotBaseTypes_TwoDLocation_t;


/* CircularRegion */
typedef struct MotCert_CircularRegion {
	MotBaseTypes_TwoDLocation_t	 center;
	char radius[LUint16];
} MotCert_CircularRegion_t;

/* RectangularRegion */
typedef struct MotBaseTypes_RectangularRegion {
	MotBaseTypes_TwoDLocation_t	 northWest;
	MotBaseTypes_TwoDLocation_t	 southEast;
	
} MotCert_RectangularRegion_t;


/* SequenceOfRectangularRegion */
typedef struct MotCert_SequenceOfRectangularRegion {
	struct MotBaseTypes_RectangularRegion RectangularRegionlist[128];

} MotCert_SequenceOfRectangularRegion_t;

/* PolygonalRegion */
typedef struct MotCert_PolygonalRegion {
	struct MotBaseTypes_RectangularRegion PolygonalRegionlist[128]; //(3...MAX)
} MotCert_PolygonalRegion_t;


/* GeographicRegion */
typedef struct MotBaseTypes_GeographicRegion {
	int Choice;
	union MotBaseTypes_GeographicRegion_u {
		MotCert_CircularRegion_t	 circularRegion;
		MotCert_SequenceOfRectangularRegion_t	 rectangularRegion;
		MotCert_PolygonalRegion_t	 polygonalRegion;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} MotBaseTypes_GeographicRegion_u;
} MotBaseTypes_GeographicRegion_t;

/* ValidityRestriction */

typedef struct ValidityRestriction {
    char Optional[LUint8];
	MotCert_ValidityPeriod_t validityPeriod;
	MotBaseTypes_GeographicRegion_t region	/* OPTIONAL */;
} ValidityRestriction_t;


/* SequenceOfitsAidList */
typedef struct SequenceOfitsAidList {
	char ItsAid[LUint64];
} SequenceOfitsAidList_t;

typedef OCTET_STRING_t	 MotCert_SubjectAssurance_t;


typedef struct SubjectAttribute {
    char Optional[LUint8];
	PublicVerifyKey_t verificationKey;
	PublicEncryptionKey_t encryptionKey	/* OPTIONAL */;
	char assuranceLevel[2+1];/* OPTIONAL */;
	SequenceOfitsAidList_t	itsAidList;	/* OPTIONAL */;
	SequenceOfitsAidSspList_t itsAidSspList	/* OPTIONAL */;
} SubjectAttribute_t;


/* TbsCert */
typedef struct TbsCert {
	SubjectInfo_t	 subjectInfo;
	SubjectAttribute_t	 subjectAttributes;
	ValidityRestriction_t	 validityRestrictions;
} TbsCert_t;


/* CScmsCertificateTbs */
typedef struct CScmsCertificateTbs {
	int Choice;
	union CScmsCertificateTbs_u {
		IeeeCertificateTbs_t	 ieee1609;
		CicvCertificateTbs_t	 cicv;
		TbsCert_t	 mot;
	} CScmsCertificateTbs_u;
} CScmsCertificateTbs_t;



/* EeEcaCertRequest */
typedef struct EeEcaCertRequest {
    int ExAttr;//={"00"}; for SEQUENCE ...
	int version;
	long currentTime;
	CScmsCertificateTbs_t   tbsData;
}EeEcaCertRequest_t;

/* PrivateKeyReconstruction */
typedef struct PrivateKeyReconstruction {
	int Choice;
	union PrivateKeyReconstruction_u {
		char sm2[LKey];
		char ecc[LKey];
	} choice;
} PrivateKeyReconstruction_t;


typedef struct MotBaseTypes_Opaque{
	int  LengthChoice;//82
    OCTET_LONG_STRING_t x509_Opaque;
}MotBaseTypes_Opaque_t;

/* Signature */
typedef struct MotCert_Signature {
	int curve;
	MotBaseTypes_ECCPoint_t	 r;
	char s[LKey];
} MotCert_Signature_t;

/* CertificateDigest */
typedef struct MotCert_CertificateDigest {
	int algorithm;//sm3 00
	char digest[LUint64]; //16
} MotCert_CertificateDigest_t;


/* IssuerId */
typedef struct IssuerId {
	int IssuerIdChoice;
	union IssuerId_u {
		char *self;//NULL
		MotCert_CertificateDigest_t	 certificateDigest;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} IssuerId_u;
} IssuerId_t;


/* Certificate */
typedef struct MotCert_Certificate {
	int version;
	IssuerId_t	 issuerId;
	TbsCert_t	 tbs;
	MotCert_Signature_t signature;

} MotCert_Certificate_t;


/* CScmsCertificate */
typedef struct CScmsCertificate {
	int  CScmsCertificateChoice;
	union CScmsCertificate_u {
		MotBaseTypes_Opaque_t	 x509;
		OCTET_LONG_STRING_t	 ieee1609;
		OCTET_LONG_STRING_t	 cicv;
		MotCert_Certificate_t	 mot;
	} CScmsCertificate_u;
} CScmsCertificate_t;


/* EcaEeCertResponse */
typedef struct EcaEeCertResponse {
    char Optional[LUint8];
	int  version;//2
	char requestHash[LUint64];//16
	CScmsCertificate_t ecaCert;
	CScmsCertificate_t enrollmentCert;
	struct PrivateKeyReconstruction	*privKeyReconstruction	/* OPTIONAL */;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
} EcaEeCertResponse_t;


/* EcaEndEntityInterfacePDU */
typedef struct EcaEndEntityInterfacePDU {
    int Choice;
	union EcaEndEntityInterfacePDU_u {
		EeEcaCertRequest_t	 eeEcaCertRequest;
		EcaEeCertResponse_t	 ecaEeCertResponse;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	}EcaEndEntityInterfacePDU_u;
} EcaEndEntityInterfacePDU_t;

/* ProximityPlausibility */
typedef struct ProximityPlausibility {
	char Choice[LCHOICE];
	union ProximityPlausibility_u {
		char *Default;//NULL
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
} ProximityPlausibility_t;

/* WarningReport */
typedef struct WarningReport {
	char Choice[LCHOICE];
	union WarningReport_u {
		char *Default;//NULL
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
} WarningReport_t;

/* ReportType */
typedef struct ReportType {
	char Choice[LCHOICE];
	union ReportType_u {
		ProximityPlausibility_t proximityPlausibility;
		WarningReport_t warningReport;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
} ReportType_t;



/* MisbehaviorReportContents */
typedef struct MisbehaviorReportContents {
    int ExAttr;//={"00"};  for OPTIONAL ...
	char version[LVERSION];
	char generationTime[LUint32];
	OCTET_STRING_t policyFilename;
	ReportType_t reportType;
	OCTET_STRING_t Evidence;//to be continue...
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
} MisbehaviorReportContents_t;


/* EndEntityMaInterfacePDU */
typedef struct EndEntityMaInterfacePDU {
	char Choice[LCHOICE];
	union EndEntityMaInterfacePDU_u {
		MisbehaviorReportContents_t	 misbehaviorReport;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
} EndEntityMaInterfacePDU_t;

/* ClientPartialPubKey */
typedef struct ClientPartialPubKey {
	int Choice;
	union ClientPartialPubKey_u {
		MotBaseTypes_ECCPoint_t	 sm2;
		MotBaseTypes_ECCPoint_t	 ecc;
	} choice;
} ClientPartialPubKey_t;


/* EeAsPseudonymCertProvisioningRequest */
typedef struct EeAsPseudonymCertProvisioningRequest {
    int ExAttr;//={"00"}; for OPTIONAL ...
	int version;
	ClientPartialPubKey_t	 clientPublicKey;
	char current_time[LUint32];
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
} EeAsPseudonymCertProvisioningRequest_t;

/* PseudonymCertProvisioningAck */
typedef struct PseudonymCertProvisioningAck {
    int ExAttr;//={"00"}; for OPTIONAL ...
	char certDLTime[LUint32];
	OCTET_LONG_STRING_t certDLURL;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
} PseudonymCertProvisioningAck_t;


/* AsEePseudonymCertProvisioningAckReply */
typedef struct AsEePseudonymCertProvisioningAckReply {
	int Choice;
	union AsEePseudonymCertProvisioningAckReply_u {
		PseudonymCertProvisioningAck_t	 ack;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
} AsEePseudonymCertProvisioningAckReply_t;

/* AsEePseudonymCertProvisioningAck */
typedef struct AsEePseudonymCertProvisioningAck {
    int ExAttr;//={"00"}; for OPTIONAL ...
	int version;
	char requestHash[LUint64];
	AsEePseudonymCertProvisioningAckReply_t	 reply;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
	
	/* Context for parsing across buffer boundaries */
} AsEePseudonymCertProvisioningAck_t;

/* AuthenticatedDownloadRequest */
typedef struct AuthenticatedDownloadRequest {
    char ExAttr[LENUME];//={"00"}; for OPTIONAL ...
	char timestamp[LUint32];
	OCTET_STRING_t filename;
	/*
	 * This type is extensible,
	 * possible extensions are below.
	 */
} AuthenticatedDownloadRequest_t;


/* EndEntityAsInterfacePDU */
typedef struct EndEntityAsInterfacePDU {
	char EEAsPduChoice[LCHOICE];
	union EndEntityAsInterfacePDU_u {
		EeAsPseudonymCertProvisioningRequest_t	 eeAsPseudonymCertProvisioningRequest;
		AsEePseudonymCertProvisioningAck_t	 asEePseudonymCertProvisioningAck;
		AuthenticatedDownloadRequest_t	 eeAsAuthenticatedDownloadRequest;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} EndEntityAsInterfacePDU_t;


typedef struct {
    int SPUDversion;
    int SPDUChoice;
	union CScmsPDUContent_u {
		EcaEndEntityInterfacePDU_t	 eca_ee;
		EndEntityMaInterfacePDU_t	 ee_ma;
		EndEntityAsInterfacePDU_t	 ee_as;
	} CScmsPDUContent_u;
}CScmsPDU_t;



typedef OCTET_LONG_STRING_t	 IeeeCertificate_t; //to be continue...
typedef OCTET_LONG_STRING_t	 CicvCertificate_t; //to be continue...


/* SignerInfo */
typedef struct CScmsSecureData_SignerInfo {
	int SignerInfoChoice;
	union CScmsSecureData_SignerInfo_u {
		char *self;//NULL
		CScmsCertificate_t	 certificate;
		/*
		 * This type is extensible,
		 * possible extensions are below.
		 */
	} CScmsSecureData_SignerInfo_u;
} CScmsSecureData_SignerInfo_t;

typedef CScmsPDU_t	 ScopedCertificateRequest_t;

typedef struct {
	int HashId;
	CScmsPDU_t TbsRequest;
	CScmsSecureData_SignerInfo_t SignerInfo;
	MotCert_Signature_t Signature;
}SignedCertificateRequest_t;

/* TBSData */
typedef struct MotSecureData_TBSData {
	char TbsDataOptional[4];
	OCTET_LONG_STRING_t	data;
	char extHash[64]/* OPTIONAL */;
} MotSecureData_TBSData_t;


typedef struct EndEntityMaInterface_SignedData {
	CScmsSecureData_SignerInfo_t	 signer;
	MotSecureData_TBSData_t	 tbs;
	MotCert_Signature_t	 sign;
} EndEntityMaInterface_SignedData_t;//to do

typedef struct MotSecureData_EncryptedData {
	//MotSecureData_SequenceOfRecipientInfo_t	 recipients;
	//SymmetricCipherText_t	 cipherText;
	
	/* Context for parsing across buffer boundaries */
    //...
	asn_struct_ctx_t _asn_ctx;
} MotSecureData_EncryptedData_t;//to do

typedef struct SignedCertReqOpaque{
    int LengthChoice;//82
	int Length;
    SignedCertificateRequest_t          SignedCertificateRequest;
}SignedCertReqOpaque_t;


typedef struct {
	int SecMversion;
	int SecMPlayloadChoice;
    union EndEntityMaInterface_Payload_u {
		MotBaseTypes_Opaque_t	            unSecuredData;
		EndEntityMaInterface_SignedData_t	signedData;
		MotSecureData_EncryptedData_t	    encData;
        SignedCertReqOpaque_t               SignedCertReqOpaque;
	}EndEntityMaInterface_Payload_u;
}SecuredMessage_t;


typedef SecuredMessage_t SignedEeEnrollmentCertRequest_t;

int CreatECTbsCert(const char *SubjectName,const char *EndTime,const char *pubkeyx,const char *pubkeyy,unsigned char *outstr);


int Encode_ValidityPeriod(const MotCert_ValidityPeriod_t *MotCertTime,unsigned char *outstr);// 10-18
int Encode_ValidityRestriction(const ValidityRestriction_t *ValidityRestriction,unsigned char *outstr); //4-20
int Encode_SignECCPoint(const MotBaseTypes_ECCPoint_t *inECCPoint,unsigned char *outstr);//2-130
int Encode_SignPublicVerifyKey(const PublicVerifyKey_t *inPublicVerifyKey,unsigned char *outstr);//6-134
int Encode_SubjectAttribute(const SubjectAttribute_t *SubjectAttribute,unsigned char *outstr);//8-136
int Encode_SubjectInfo(const SubjectInfo_t *subjectinfo,unsigned char *outstr); //2-34
int Encode_TbsCert(const TbsCert_t *TbsCert,unsigned char *outstr);//14-190
int Encode_CScmsCertificateTbs(const CScmsCertificateTbs_t *CertificateTbs,unsigned char *outstr);//16-192
int Encode_EeEcaCertRequest(const EeEcaCertRequest_t *EcaEECertReq,unsigned char *outstr);//20-196
int Encode_EcaEndEntityInterfacePDU(const EcaEndEntityInterfacePDU_t *EcaEEPDU,unsigned char *outstr);//24-200
int Encode_CScmsPDU(const CScmsPDU_t *CScmsPDU,unsigned char *outstr);//28-204
//int Encode_MotCertCertificate(const MotCert_Certificate_t *MotCert,unsigned char *outstr);
int Encode_MotCertificate(const MotCert_Certificate_t *certificate,unsigned char *outstr);

int Encode_CScmsCertificate(const CScmsCertificate_t *certificate,unsigned char *outstr);//8-2048
int Encode_SignerInfo(const CScmsSecureData_SignerInfo_t *SignerInfo,unsigned char *outstr);//10-2048
int Encode_Signature(const MotCert_Signature_t *Signature,unsigned char *outstr);//68-196
int Encode_SignedCertificateRequest(const SignedCertificateRequest_t *SignedCertReq,unsigned char *outstr);
int Encode_SecuredMessage(const SecuredMessage_t *SecuredMessage,unsigned char *outstr);


int SetEeEcaCertRequest_CICV_MOT(const char *subjectName,const char *pubkx,const char *pubky,const long time_end,EeEcaCertRequest_t *outstr);

int SetSubjectInfo(int subjectType,const char *subjectName,SubjectInfo_t *outstr);
int SetPublicVerifyKey(const int curve,const int ECCPoint,const char *pubkx,const char *pubky,PublicVerifyKey_t *outstr);

int SetSubjectAttributes_PublicVerifyKey_Only(const char *OPTIONAL,int curve,int ECCPoint,const char *pubkx,const char *pubky,SubjectAttribute_t *outstr);
int SetValidityPeriod(const int Choice,const long time_start,const long time_end,MotCert_ValidityPeriod_t *outstr);

int SetValidityRestriction_ValidityPeriod_Only(const char *OPTIONAL,const int Choice,const long time_start,const long time_end,ValidityRestriction_t *outstr);

int SetTbsCert_CICV(const int subjecttype,const char *subattrOptional,const char *subjectName,const char *pubkx,const char *pubky,const long time_end,TbsCert_t *outstr);

int SetCScmsPDU_CICV_ECA(const char *subjectName,const char *pubkx,const char *pubky,const long time_end,CScmsPDU_t *outstr);

int SetSignerInfo_X509(const char *X509,CScmsSecureData_SignerInfo_t *outstr);

int SetSignature(const char *r,const char *s,MotCert_Signature_t *outstr);

int SetSignedCertificateRequest(const char *SubjectName,
                                            const long EndTime,
                                            const char *LTC_prikey,
                                            const char *LTC_pubkey,
                                            const char *OBU_pubkeyx,
                                            const char *OBU_pubkeyy,
                                            const char *LTC_CertStr,
                                            SignedCertificateRequest_t *SignedCertRequest);

int CreatCicvECSecuredMessage(const char *SubjectName,
                                            const long EndTime,
                                            const char *LTC_prikey,
                                            const char *LTC_pubkey,
                                            const char *OBU_pubkeyx,
                                            const char *OBU_pubkeyy,
                                            const char *LTC_CertStr,
                                            unsigned char *outstr);



//return outstr length





int Decode_SecuredMessage(const char *instr,SecuredMessage_t *outstruct,char *outstr);
int Decode_CertificateDigest(const char *instr,MotCert_CertificateDigest_t *outstruct,char *outstr);

extern CScmsPDU_t ScopedEeEnrollmentCertResponse;



#ifdef  __cplusplus
  }
#endif

#endif

