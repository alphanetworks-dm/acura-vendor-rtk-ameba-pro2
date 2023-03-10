/**
 ******************************************************************************
 *This file contains sensor configurations for AmebaPro platform
 ******************************************************************************
*/


#ifndef __SENSOR_H
#define __SENSOR_H

#ifdef __cplusplus
extern "C" {
#endif



/**
@code
 The table below gives an overview of the hardware resources supported by each
 AmebaPro EVAL board.
     - Sensor board:

 =================================================================================================================+
   AmebaPro EVAL  | Sensor board |
 =================================================================================================================+
   AmebaPro2-EVAL   |  SC2053      |
 -----------------------------------------------------------------------------------------------------------------+
   AmebaPro2-EVAL   |  SC2336      |
 -----------------------------------------------------------------------------------------------------------------+
   AmebaPro2-EVAL   |  PS5258      |
 -----------------------------------------------------------------------------------------------------------------+
 =================================================================================================================+
@endcode
*/
#define SENSOR_DUMMY        0x00 //For dummy sensor, no support fast camera start
#define SENSOR_GC4023		0x01
#define SENSOR_PS5420		0x02
#define SENSOR_PS5270		0x03
#define SENSOR_SC2333		0x04
#define SENSOR_GC4653		0x05
#define SENSOR_SC301		0x06
#define SENSOR_JXF51		0x07

#define MULTI_DISABLE       0x00
#define MULTI_ENABLE        0x01

#define MULTI_SENSOR  		MULTI_DISABLE
#define USE_SENSOR      	SENSOR_GC4023
#define NONE_FCS_MODE       0
#define FW1_IQ_ADDR        0xF20000
#define FW2_IQ_ADDR        0xF60000
#define FW_IQ_SIZE         256*1024
#define FW_SENSOR_SIZE     16*1024
#define FW_VOE_SIZE        600*1024
#define VIDEO_MPU_VOE_HEAP  0
#define SENSOR_SINGLE_DEFAULT_SETUP     0x00
#define SENSOR_MULTI_DEFAULT_SETUP      0X01
#define SENSOR_MULTI_SAVE_VALUE         0X02
#define SENSOR_MULTI_SETUP_PROCEDURE	0X03
#ifdef __cplusplus
}
#endif


#endif /* __AMEBAPRO_SENSOR_EVAL_H */
