#ifndef _SM2_POINT2OCT_H_
#define _SM2_POINT2OCT_H_

#ifdef  __cplusplus
  extern "C" {
#endif

void sm2_point2oct (unsigned char ucType, unsigned char* pucInX, unsigned char* pucOutXY );
int untar_x_to_y(const int ucType, const char* pucInX, unsigned char* pucOutXY);




#ifdef  __cplusplus
  }
#endif


#endif






