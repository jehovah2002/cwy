#ifndef _SM2_CREATE_KEY_PAIR_H_
#define _SM2_CREATE_KEY_PAIR_H_


#ifdef  __cplusplus
  extern "C" {
#endif

/**************************************************
* Name: sm2_create_key_pair
* Function: create SM2 key pair, including private key
    and public key
* Parameters:
    key_pair[in]  SM2 key pair
* Return value:
    0:                function executes successfully
    any other value:  an error occurs
**************************************************/
int sm2_create_key_pair(SM2_KEY_PAIR *key_pair);

#ifdef  __cplusplus
  }
#endif

#endif  /* end of HEADER_SM2_CREATE_KEY_PAIR_H */