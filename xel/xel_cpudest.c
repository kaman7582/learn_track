/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_cpudest.c,v $
 * $Revision: 1.23 $
 * 
 * \file xel_cpudest.c
 * \brief Set CPU destination.
 * 
 * Description:
 * API for managing destination id for packets to CPU.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <byteswap.h>

#include "drv_driver.h"
#include "xel_cpudest.h"
#include "memory.h"
#include "engine_operations.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

int xel_set_tm_to_cpu_dest(uint8_t xid,
                           uint16_t destination)
{
    msgprof_t            profile;
    struct XCM_Header    xcm;
    
    int                  ret       = 0;
    msgflow_t            flow      = drv_get_flow(xid);
    uint16_t             dest      = destination;
    
    dest = BSWAP16(dest);
    memset(&xcm, 0, sizeof(struct XCM_Header));
    
    xcm.SUID      = SUID_SE4;
    xcm.Addr      = htonl(TO_CPU_DEST_ADDR);
    xcm.ReqCode   = SRAM4_Write64;
    xcm.RW        = XCM_WRITE;
    xcm.UID       = drv_get_uid(xid, xcm.SUID, TO_CPU_DEST_ADDR);
    profile       = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(dest), &dest);
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

/*
 *
 */
int XEL_TMtoCPUDestinationSet(uint8_t   iXid,
                              uint16_t  rsDestination)
{
    return(xel_set_tm_to_cpu_dest(iXid, rsDestination));
}
