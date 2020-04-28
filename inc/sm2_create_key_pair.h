/**************************************************
* File name: sm2_create_key_pair.h
* Author: HAN Wei
* Author's blog: https://blog.csdn.net/henter/
* Date: Nov 18th, 2018
* Description: declare SM2 key pair creation function
**************************************************/

#ifndef HEADER_SM2_CREATE_KEY_PAIR_H
#define HEADER_SM2_CREATE_KEY_PAIR_H


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