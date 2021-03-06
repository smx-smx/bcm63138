/***************************************************************************
*    Copyright (c) 2000-2013 Broadcom                             
*                                                                           
*    This program is the proprietary software of Broadcom and/or
*    its licensors, and may only be used, duplicated, modified or           
*    distributed pursuant to the terms and conditions of a separate, written
*    license agreement executed between you and Broadcom (an Authorized     
*    License).  Except as set forth in an Authorized License, Broadcom      
*    grants no license (express or implied), right to use, or waiver of any 
*    kind with respect to the Software, and Broadcom expressly reserves all 
*    rights in and to the Software and all intellectual property rights     
*    therein.  IF YOU HAVE NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO 
*    USE THIS SOFTWARE IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM   
*    AND DISCONTINUE ALL USE OF THE SOFTWARE.                               
*                                                                           
*                                                                           
*    Except as expressly set forth in the Authorized License,               
*                                                                           
*    1.     This program, including its structure, sequence and             
*    organization, constitutes the valuable trade secrets of Broadcom, and  
*    you shall use all reasonable efforts to protect the confidentiality    
*    thereof, and to use this information only in connection with your use  
*    of Broadcom integrated circuit products.                               
*                                                                           
*    2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS PROVIDED
*    AS IS AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,              
*    REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY, OR  
*    OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY        
*    DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,    
*    NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,    
*    ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR         
*    CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING OUT  
*    OF USE OR PERFORMANCE OF THE SOFTWARE.                                 
*                                                                           
*    3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL       
*    BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL, INCIDENTAL, 
*    SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER ARISING OUT OF OR IN
*    ANY WAY RELATING TO YOUR USE OF OR INABILITY TO USE THE SOFTWARE EVEN  
*    IF BROADCOM HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES; OR    
*    (ii) ANY AMOUNT IN EXCESS OF THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE 
*    ITSELF OR U.S. $1, WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY 
*    NOTWITHSTANDING ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.
*
****************************************************************************
*
*    Filename: FlexiCalc.h
*
****************************************************************************
*    Description:
*
*    FlexiCalc output constants for the following inputs:
*
*       BCM6838                          
*       SLIC = Silicon Labs Si32392      
*       R1 = 270 ohms
*       R2 = 910 ohms
*       C1 = 120 nano Farads 
*       DLP = -10dB
*       ELP = -4dB
*       HWDACgain = 0dB
*       HW_impedance = 680 ohms
*       Protection resistor = 10 ohms
*       Ringing frequency = 25 hertz
*       Ringing amplitude = 45Vrms
*
*    Flexicalc Version: 3.8
*
****************************************************************************/

#ifndef FLEXICALC_FINLAND_32392_H
#define FLEXICALC_FINLAND_32392_H

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
** Flexicalc Values Structure                                              **
****************************************************************************/

#if !VRG_COUNTRY_CFG_FINLAND
#define flexicalcFINLANDArchive32392 ((const APM6838_FLEXICALC_CFG*) NULL)
#else
const APM6838_FLEXICALC_CFG flexicalcFINLANDArchive32392[] =
{
{
   0x32392,          /* Slic type: Si32392 */
   45,               /* Ring Voltage (RMS) */
   -10,               /* DLP - Decode Level Point (receive loss) in dB */
   -4,               /* ELP - Encode Level Point (transmitt loss) in dB */
   0x0007,           /* eq_rx_shft */
   0x000B,           /* eq_tx_shft */
   0,                /* eq_imp_resp */

   /*
   ** Y-filter Coefficients
   */
   1,                /* yfltr_en */
   {  /* IIR 2 Filter Coefficients */
      0x04966,   /* Y IIR2 filter b0 */
      0x061FA,   /* Y IIR2 filter b1 */
      0x04966,   /* Y IIR2 filter b2 */
      0x4E1DC,   /* Y IIR2 filter a1 */
      0xE28AB    /* Y IIR2 filter a2 */
   },
   0x77,             /* y_iir2_filter_shift */
   {  /* Fir Filter Coefficients */
      0xD158A,   /* YFIR1_VAL */
      0x60927,   /* YFIR2_VAL */
      0xE5338,   /* YFIR3_VAL */
      0xDD91A,   /* YFIR4_VAL */
      0xFE866,   /* YFIR5_VAL */
      0x1416F,   /* YFIR6_VAL */
      0x0C8C7,   /* YFIR7_VAL */
      0xF8ABA,   /* YFIR8_VAL */
      0xF0229,   /* YFIR9_VAL */
      0xF9096,   /* YFIR10_VAL */
      0x06B62,   /* YFIR11_VAL */
      0x0A509,   /* YFIR12_VAL */
      0x01A7D,   /* YFIR13_VAL */
      0xF748E,   /* YFIR14_VAL */
      0xF6C03,   /* YFIR15_VAL */
      0x0320C,   /* YFIR16_VAL */
      0x1792A,   /* YFIR17_VAL */
      0xF0D8A    /* YFIR18_VAL */
   },
   0x06,               /* y_fir_filter_shift */
   0x7FFFF,            /* yfltr_gain */
   {0x6F08F},          /* y_iir1_filter[1] */
   0x96,               /* y_iir1_filter_shift */

   /* Hybrid Balance Coefficients */
   7,                  /* hybal_shft */
   {0xB8E6, 0x6CD6, 0x9E4A, 0x7CD8, 0xB0F5},    /* hybal_audio_fir[5] */
   {0x0000, 0x0000, 0x0000, 0x0000, 0x0000},    /* hybal_pm_fir[5] */
   1,                  /* hybal_en */

   {  /* Rx Equalization Coefficents */
      0x56C0, 0xD601, 0x0857, 0xFA98, 0x0239, 0xFDD5, 0x0095, 0xFEBC,
      0x0027, 0xFF1F, 0xFFFE, 0xFF65, 0xFFF3, 0xFF90, 0xFFF5, 0xFFB0,
      0xFFFA, 0xFFC4, 0x0002, 0xFFD1, 0x0002, 0xFFDE, 0x0007, 0xFFDE,
      0x0001, 0xFFE5, 0xFFFF, 0xFFE8, 0x0001, 0xFFEC, 0xFFFB, 0xFFF0,
      0xFFFD, 0xFFED, 0x0000, 0xFFF1, 0x0000, 0xFFF5, 0x0004, 0xFFF6,
      0x0005, 0x0000, 0x0001, 0x0000, 0x0001, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
   },

   {  /* Tx Equalization Coefficents */
      0x41FA, 0xFBC2, 0x0099, 0xFE75, 0x002A, 0xFF6D, 0xFFEA, 0xFF98,
      0xFFDC, 0xFFB1, 0xFFDB, 0xFFC6, 0xFFE1, 0xFFD4, 0xFFEA, 0xFFE0,
      0xFFF2, 0xFFE9, 0xFFF7, 0xFFEF, 0xFFF8, 0xFFF2, 0xFFFA, 0xFFF3,
      0xFFFB, 0xFFF5, 0xFFF9, 0xFFF7, 0xFFFA, 0xFFF8, 0xFFFB, 0xFFF8,
      0xFFFC, 0xFFF9, 0xFFFE, 0xFFFA, 0xFFFE, 0xFFFC, 0x0000, 0xFFFE,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
   },

   0x0003,           /* cic_int_shft */
   0x0004,           /* cic_dec_shft */
   0x6A9A,           /* asrc_int_scale */
   0x0BBA,           /* asrc_dec_scale */
   0,                /* vtx_pg */
   1,                /* vrx_pg */
   0,                /* hpf_en */
   6,                /* hybal_smpl_offset */

}
};
#endif

#ifdef __cplusplus
}
#endif

#endif  /* FLEXICALC_FINLAND_32392_H */
