#ifndef _SM2_SIGN_AND_VERIFY_COMPUTATION_H_
#define _SM2_SIGN_AND_VERIFY_COMPUTATION_H_


#ifdef  __cplusplus
  extern "C" {
#endif

int test_sm2_sign_and_verify(const char *msg,const char *ida);


/**************************************************
* Name: sm2_sign_data
* Function: compute SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    pri_key[in]      SM2 private key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
* Notes:
1. The user id value cannot be NULL. If the specific 
   value is unknown, the default user id "1234567812345678" 
   can be used.
2. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32-byte length.
3. "pri_key" is a octet string of 32 byte length.
**************************************************/
int sm2_sign_data(const unsigned char *message,
                  			const int message_len,
		  					const unsigned char *id,
		  					const int id_len,
		  					const unsigned char *pub_key,
		  					const unsigned char *pri_key,
		  					SM2_SIGNATURE_STRUCT *sm2_sig);
int sm2_sign(const unsigned char *message,
					const int keytype,
					const unsigned char *id,
					const unsigned char *pub_key,
					const unsigned char *pri_key,
					SM2_SIGNATURE_STRUCT *sm2_sig);


/**************************************************
* Name: sm2_verify_sig
* Function: verify SM2 signature
* Parameters:
    message[in]      input message
    message_len[in]  input message length, size in bytes
    id[in]           user id
    id_len[in]       user id length, size in bytes
    pub_key[in]      SM2 public key
    sm2_sig[out]     SM2 signature
* Return value:
    0:                signature passes verification
    any other value:  an error occurs
* Notes:
1. "pub_key" is a octet string of 65 byte length. It 
   is a concatenation of 04 || X || Y. X and Y both are 
   SM2 public key coordinates of 32-byte length.
**************************************************/
int sm2_verify_sig(const unsigned char *message,
                   const int message_len,
		   const unsigned char *id,
		   const int id_len,
		   const unsigned char *pub_key,
		   SM2_SIGNATURE_STRUCT *sm2_sig);

  int sm2_verify(const unsigned char *message,
					  const int keytype,
					  const unsigned char *id,
					  const unsigned char *pub_key,
					  const unsigned char *r,
					  const unsigned char *s);


#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_SIGN_AND_VERIFY_COMPUTATION_H */
