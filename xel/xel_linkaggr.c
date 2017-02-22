/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_linkaggr.c,v $
 * $Revision: 1.26 $
 * 
 * \file  xel_linkaggr.c
 * \brief Link aggregation management API
 * 
 * Description:
 * API for managing link aggregation table.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_linkaggr.h"
#include "memory.h"
#include "link_aggregation.h"
#include "trunk_multicast.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

int xel_link_aggr_set(uint8_t xid,
                      uint16_t trunk_number,
                      uint32_t* link_to_q_refs)
{
    int i;
    uint32_t address;
    struct link_aggr_resp resp;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if (!link_to_q_refs)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structure. */
    memset(&resp, 0, sizeof(resp));
    
    for (i = 0; i < 16; i++) {
        address = trunk_number * 16 + i + LINK_AGGR_ADDR;
        if (address >= (LINK_AGGR_ADDR + LINK_AGGR_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        
        resp.link_to_q_ref = link_to_q_refs[i];

        const char * link_aggr_resp_conv = LINK_AGGR_RESP;
        CONVERT_ENDIAN(link_aggr_resp, &resp);

        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_SE4;
        xcm.Addr = htonl(address);
        xcm.ReqCode = SRAM4_Write64;
        xcm.RW = XCM_WRITE;
        xcm.UID = drv_get_uid(xid, xcm.SUID, address);
        profile = drv_get_profile(xid, DRV_PROF_0);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp), &resp);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
    }

    ret = msgflow_flush(flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        

    /* Ignore number of messages remaining */
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}

int xel_link_queue_set(uint8_t xid,
                       uint32_t link_to_q_ref,
                       uint16_t dest_id_selector,
                       struct xel_link_queue* destinations)
{
    uint32_t address;
    struct link_queue_resp resp;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    int ret = 0;

    if (!destinations)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structure. */
    memset(&resp, 0, sizeof(resp));

    /* Address */
    address = link_to_q_ref + (dest_id_selector >> 2) + LINK_QUEUE_ADDR;
    if (address >= (LINK_QUEUE_ADDR + LINK_QUEUE_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Response. */
    resp.dest_id_0 = destinations->destination_0;
    resp.dest_id_1 = destinations->destination_1;
    resp.dest_id_2 = destinations->destination_2;
    resp.dest_id_3 = destinations->destination_3;

    const char * link_queue_resp_conv = LINK_QUEUE_RESP;    
    CONVERT_ENDIAN(link_queue_resp, &resp);
        
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

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

    /* Ignore number of messages remaining */
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}

int xel_link_flood_set(uint8_t xid,
                       uint16_t mcast_id,
                       uint16_t* dest_ids)
{
    int i;
    int ret = 0;
    uint32_t address;
    struct link_queue_resp resp;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if (!dest_ids)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structure. */
    memset(&resp, 0, sizeof(resp));

    for (i = 0; i < 4; i++)
    {
        /* Address */
        address = mcast_id * 4 + i + FLOOD_LINK_ADDR;
        if (address >= (FLOOD_LINK_ADDR + FLOOD_LINK_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }

        /* Response. */
        resp.dest_id_0 = dest_ids[i * 4];
        resp.dest_id_1 = dest_ids[(i * 4) + 1];
        resp.dest_id_2 = dest_ids[(i * 4) + 2];
        resp.dest_id_3 = dest_ids[(i * 4) + 3];

        const char * link_queue_resp_conv = LINK_QUEUE_RESP;
        CONVERT_ENDIAN(link_queue_resp, &resp);
        
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS2;
        xcm.Addr = htonl(address);
        xcm.ReqCode = LASRAM2_Write64;
        xcm.RW = XCM_WRITE;
        xcm.UID = drv_get_uid(xid, xcm.SUID, address);
        profile = drv_get_profile(xid, DRV_PROF_0);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp), &resp);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
    }

    ret = msgflow_flush(flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        

    /* Ignore number of messages remaining */
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}

int xel_link_mcast_id_set(uint8_t xid,
                          uint16_t trunk_number,
                          uint16_t mcast_id)
{
    uint16_t address;
    struct trunk_mcast_resp resp;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    /* Clear data structure. */
    memset(&resp, 0, sizeof(resp));

    /* Address */
    address = trunk_number + TRUNK_MCAST_ADDR;
    if (address >= (TRUNK_MCAST_ADDR + TRUNK_MCAST_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Response */
    resp.mcast_id = mcast_id;

    const char * trunk_mcast_resp_conv = TRUNK_MCAST_RESP;    
    CONVERT_ENDIAN(trunk_mcast_resp, &resp);
        
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE4;
    xcm.Addr = htonl(address);
    xcm.ReqCode = SRAM4_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

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

    /* Ignore number of messages remaining */
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Set an entry in the link aggregation table.
 */
int
XEL_LinkAggrSet(uint8_t  iXid,
                uint16_t rqTrunkNumber,
                uint32_t *rsLinkToQRefs)
{
    return(xel_link_aggr_set(iXid, rqTrunkNumber, rsLinkToQRefs));
}

/**
 * Set an entry in the LinkToQ table.
 */ 
int XEL_LinkQueueSet(uint8_t  iXid,
                     uint32_t rqLinkToQRef,
                     uint16_t rqDestIdSelector,
                     struct X_LinkQueueType *rsDestinations)
{
    return(xel_link_queue_set(iXid, rqLinkToQRef, rqDestIdSelector, (struct xel_link_queue*)rsDestinations));
}

/**
 * Set an entry in the flood link aggregation table.
 */ 
int XEL_FloodLinkAggrSet(uint8_t  iXid,
                         uint16_t rqMcastId,
                         uint16_t *rsDestIds)
{
    return(xel_link_flood_set(iXid, rqMcastId, rsDestIds));
}

/*
 * Add an entry to the trunk Multicast Id table.
 * This table enables learned MAC addresses to be distributed 
 * between ports in a trunk. 
 * 
 */
int XEL_LinkAggrMcastIdSet(uint8_t  iXid,
                           uint16_t rqTrunkNumber,
                           uint16_t rsMcastId)
{
    return(xel_link_mcast_id_set(iXid, rqTrunkNumber, rsMcastId));
}
