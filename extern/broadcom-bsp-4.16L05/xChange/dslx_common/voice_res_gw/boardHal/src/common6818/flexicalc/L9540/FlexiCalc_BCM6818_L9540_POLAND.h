/***************************************************************************
*    Copyright (c) 2000-2011 Broadcom                             
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
*       BCM6818                          
*       SLIC = Zarlink             
*       R1 = 600 ohms
*       R2 = 0 ohms
*       C1 = 0 nano Farads 
*       DLP = -6dB
*       ELP = -4dB
*       HWDACgain = 0dB
*       HW_impedance = 600 ohms
*       Protection resistor = 50 ohms
*       Ringing frequency = 25 hertz
*       Ringing amplitude = 45Vrms
*
*    Flexicalc Version: 3.7
*
****************************************************************************/

#ifndef FLEXICALC_BCM6818_L9540_POLAND_H
#define FLEXICALC_BCM6818_L9540_POLAND_H

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
** Flexicalc Values Structure                                              **
****************************************************************************/

#if !VRG_COUNTRY_CFG_POLAND
#define flexicalcPOLANDArchive9540 ((const APM6818_FLEXICALC_CFG*) NULL)
#else
const APM6818_FLEXICALC_CFG flexicalcPOLANDArchive9540[] =
{
{
   0x9540,           /* Slic type:  */
   45,               /* Ring Voltage (RMS) */
   -6,               /* DLP - Decode Level Point (receive loss) in dB */
   -4,               /* ELP - Encode Level Point (transmitt loss) in dB */
   0x0007,           /* eq_rx_shft */
   0x000A,           /* eq_tx_shft */
   0,                /* eq_imp_resp */

   /*
   ** Y-filter Coefficients
   */
   1,                /* yfltr_en */
   {  /* IIR 2 Filter Coefficients */
      0x16860,   /* Y IIR2 filter b0 */
      0x28E0B,   /* Y IIR2 filter b1 */
      0x16860,   /* Y IIR2 filter b2 */
      0x4A22B,   /* Y IIR2 filter a1 */
      0xDFB13    /* Y IIR2 filter a2 */
   },
   0x66,             /* y_iir2_filter_shift */
   {  /* Fir Filter Coefficients */
      0xB9B6B,   /* YFIR1_VAL */
      0x6C9EA,   /* YFIR2_VAL */
      0xD68E6,   /* YFIR3_VAL */
      0x166A0,   /* YFIR4_VAL */
      0xFAB68,   /* YFIR5_VAL */
      0xE399E,   /* YFIR6_VAL */
      0x09CB1,   /* YFIR7_VAL */
      0xFF9C4,   /* YFIR8_VAL */
      0xFB062,   /* YFIR9_VAL */
      0x10153,   /* YFIR10_VAL */
      0x00C82,   /* YFIR11_VAL */
      0xF8E9D,   /* YFIR12_VAL */
      0x03E49,   /* YFIR13_VAL */
      0xF99E5,   /* YFIR14_VAL */
      0xFBED1,   /* YFIR15_VAL */
      0x08043,   /* YFIR16_VAL */
      0x00A93,   /* YFIR17_VAL */
      0xFDD9D    /* YFIR18_VAL */
   },
   0x05,               /* y_fir_filter_shift */
   0x7FFFF,            /* yfltr_gain */
   {0x7EDC1},          /* y_iir1_filter[1] */
   0x86,               /* y_iir1_filter_shift */

   /* Hybrid Balance Coefficients */
   4,                  /* hybal_shft */
   {0x79D9, 0xA45E, 0x0828, 0x50A6, 0xCDAF},    /* hybal_audio_fir[5] */
   {0x0000, 0x0000, 0x0000, 0x0000, 0x0000},    /* hybal_pm_fir[5] */
   1,                  /* hybal_en */

   {  /* Rx Equalization Coefficents */
      0x7F23, 0xFD34, 0xFE04, 0xFDC2, 0xFDF6, 0xFE07, 0xFE29, 0xFE41,
      0xFE6E, 0xFE8C, 0xFEAE, 0xFED1, 0xFEF5, 0xFF11, 0xFF35, 0xFF52,
      0xFF69, 0xFF7D, 0xFF95, 0xFFA2, 0xFFAA, 0xFFB6, 0xFFBF, 0xFFC1,
      0xFFC5, 0xFFCA, 0xFFC9, 0xFFC9, 0xFFCF, 0xFFCE, 0xFFCE, 0xFFD4,
      0xFFDA, 0xFFDC, 0xFFE1, 0xFFE7, 0xFFEA, 0xFFEF, 0xFFF6, 0xFFF9,
      0xFFFB, 0x0004, 0x0004, 0x0003, 0x0003, 0x0002, 0x0002, 0x0002,
      0x0002, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001,
      0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
   },

   {  /* Tx Equalization Coefficents */
      0x7F9B, 0xFE50, 0xFEF0, 0xFEBA, 0xFEDD, 0xFEE3, 0xFEFB, 0xFF0C,
      0xFF22, 0xFF36, 0xFF4B, 0xFF5F, 0xFF73, 0xFF84, 0xFF98, 0xFFA4,
      0xFFB5, 0xFFBC, 0xFFC9, 0xFFCF, 0xFFD4, 0xFFD8, 0xFFDA, 0xFFDD,
      0xFFDD, 0xFFE0, 0xFFE1, 0xFFE3, 0xFFE4, 0xFFE5, 0xFFE8, 0xFFE9,
      0xFFEC, 0xFFED, 0xFFF1, 0xFFF2, 0xFFF5, 0xFFF8, 0xFFFA, 0xFFFD,
      0xFFFE, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0001, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
      0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
   },

   0x0004,           /* cic_int_shft */
   0x0004,           /* cic_dec_shft */
   0x70A7,           /* asrc_int_scale */
   0x0ABC,           /* asrc_dec_scale */
   1,                /* vtx_pg */
   1,                /* vrx_pg */
   0,                /* hpf_en */
   4,                /* hybal_smpl_offset */

}
};
#endif

#ifdef __cplusplus
}
#endif

#endif  /* FLEXICALC_BCM6818_L9540_POLAND_H */
