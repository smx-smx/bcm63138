/****************************************************************************
*
*     Copyright (c) 2002-2004 Broadcom
*           All Rights Reserved
*
*     No portions of this material may be reproduced in any form without the
*     written permission of:
*
*           Broadcom
*           16215 Alton Parkway
*           Irvine, California 92619-7013
*
*     All information contained in this document is Broadcom
*     company private, proprietary, and trade secret.
*
****************************************************************************
*  $Id: dma1103.h,v 1.4 2004/06/08 17:23:52 ddjurovic Exp $
*****************************************************************************
*
*  PURPOSE:
*
*     This file contains global definitions for the BCM3368 DMA controllers.
*
*  NOTES:
*
****************************************************************************/

#ifndef DMA6362_H
#define DMA6362_H

#ifdef __cplusplus
  extern "C" {
#endif

/* ---- Include Files ---------------------------------------------------- */
/* ---- Constants and Types ---------------------------------------------- */
/*
** PCM / IUDMA Channel associations
*/

#define      BCM6362_DMA_UBUS_BYTES    8  /* 6362 Ubus is 64bits/8ytes wide */


/* Wrap common types to chip-specific types using defines */
#define BCM6362_IUDMA_DESC                BCM_IUDMA_DESC
#define BCM6362_IUDMA_DESC_STATUS_OWN     BCM_IUDMA_DESC_STATUS_OWN
#define BCM6362_IUDMA_DESC_STATUS_EOP     BCM_IUDMA_DESC_STATUS_EOP
#define BCM6362_IUDMA_DESC_STATUS_SOP     BCM_IUDMA_DESC_STATUS_SOP
#define BCM6362_IUDMA_DESC_STATUS_WRAP    BCM_IUDMA_DESC_STATUS_WRAP
#define BCM6362_IUDMA_DESC_STATUS_PERIPH  BCM_IUDMA_DESC_STATUS_PERIPH


/* ---- Variable Externs ------------------------------------------------- */
/* ---- Function Prototypes ---------------------------------------------- */

#ifdef __cplusplus
}
#endif

#endif /* DMA6362_H */
