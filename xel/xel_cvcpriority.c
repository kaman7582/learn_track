/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_cvcpriority.c,v $
 * $Revision: 1.21 $
 * 
 * \file  xel_cvcpriority.c
 * \brief Priority regeneration management API
 * 
 * Description:
 * API for managing priority regeneration tables on ingress and egress.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_cvcpriority.h"
#include "memory.h"
#include "prio_regen.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "xel_endian.h"

int xel_cvc_set_prio_regen_egress(uint8_t xid,
                                  uint16_t cvc_eg_prio_regen_ref,
                                  struct xel_cvc_prio_regen_table* table_1,
                                  struct xel_cvc_prio_regen_table* table_2)
{
    uint16_t address;
    struct prio_regen_egress_resp resp;
    uint8_t i;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if ((cvc_eg_prio_regen_ref % 2) != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if ((!table_1) || (!table_2))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Clear response data */
    memset(&resp, 0, sizeof(resp));

    /*
     * Address = PriorityRegRef / 2
     */
    address = cvc_eg_prio_regen_ref / 2 + PRIO_REGEN_EGRESS_ADDR;
    if (address >= (PRIO_REGEN_EGRESS_ADDR + PRIO_REGEN_EGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Placement of the bits.
     *
     * Prio bits are stored 2 + 1 According to:
     *  5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |7 7 6 6 5 5 4 4 3 3 2 2 1 1 0 0|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |7 6 5 4 3 2 1 0|7 6 5 4 3 2 1 0|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |7 7 6 6 5 5 4 4 3 3 2 2 1 1 0 0|
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *
     * The three bit prio at Index i is calculated as:
     * if (PriorityRegRef%2)
     *   prio = (Prio0_lsb>>i)&0x1 + ((Prio0_msb>>i*2)&0x3)<<1
     * else
     *   prio = (Prio1_lsb>>i)&0x1 + ((Prio1_msb>>i*2)&0x3)<<1
     */

    /* Prio values 0 to 7. */
    for (i = 0; i < 8; i++)
    {
        resp.prio_0_msb |= (((table_1->regenerated_prio[i] & 0x06) >> 1) << (i * 2));
        resp.prio_0_lsb |= ((table_1->regenerated_prio[i] & 0x01) << i);

        resp.prio_1_msb |= (((table_2->regenerated_prio[i] & 0x06) >> 1) << (i * 2));
        resp.prio_1_lsb |= ((table_2->regenerated_prio[i] & 0x01) << i);
    }

    const char* prio_regen_egress_resp_conv = PRIO_REGEN_EGRESS_RESP;    
    CONVERT_ENDIAN(prio_regen_egress_resp, &resp);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE2;
    xcm.Addr = htonl(address);
    xcm.ReqCode = SRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile      = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp), &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    ret = msgflow_flush(flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int XEL_CVCEgPrioRegenSet(uint8_t  iXid, uint16_t rqCVCEgPrioRegenRef,
                          struct X_CVCPrioRegenTable* rsTable1,
                          struct X_CVCPrioRegenTable* rsTable2)
{
    return(xel_cvc_set_prio_regen_egress(iXid, rqCVCEgPrioRegenRef,
                                         (struct xel_cvc_prio_regen_table*)rsTable1,
                                         (struct xel_cvc_prio_regen_table*)rsTable2));
}

