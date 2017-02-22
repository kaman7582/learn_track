/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_instance.c,v $
 * $Revision: 1.27 $
 * 
 * @file xel_instance.c
 * @brief Instance table API
 * 
 * Description:
 * API for managing instance table
 *--------------------------------------------------------------------------*/

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_instance.h"
#include "xel_endian.h"
#include "fpa_types.h"
#include "engine_operations.h"
#ifdef MAC_IN_RAM
#include "instance_table.h"
#endif
#include "memory.h"
#include "fpa_endian_conv_strings.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

int xel_instance_set(uint8_t xid,
                     struct xel_instance_req_data* rq_data,
                     struct xel_instance_resp_data* rs_data)
{
    int ret = 0;
#ifdef MAC_IN_RAM
    uint32_t address;
    struct instance_table_resp resp;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    
    if (!rq_data || !rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&resp, 0, sizeof(resp));

    /* Address */
    address = INSTANCE_TABLE_ADDR + (rq_data->port_id * 4096 + rq_data->svid) * 2;
    if (address >= (INSTANCE_TABLE_ADDR + INSTANCE_TABLE_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* SID and CBPPrioRegenRef */
    resp.sid_hi = (rs_data->sid >> 16) & 0xff;
    resp.sid_low = rs_data->sid & 0xffff;
    resp.cbp_prio_reg_ref = rs_data->cbp_prio_regen_ref;

    /* VSID */
    resp.vsid = rs_data->vsid;
    resp.vsid_msb = (rs_data->vsid >> 16) & 0x3;

    /* SVID and CNP untagged */
    resp.svid = rs_data->svid;
    if ((rs_data->flags & X_IC_CNP_IN_UNTAGGED_SET) != 0)
    {
        resp.cnp_untagged_set = 1;
    }

    /* BVID and CBP untagged */
    resp.bvid = rs_data->bvid;
    if ((rs_data->flags & X_IC_CBP_IN_UNTAGGED_SET) != 0)
    {
        resp.cbp_untagged_set= 1;
    }

    /* LearnDestId, VIP untagged, CNP member and CNP port state */
    resp.learn_dest_id = rs_data->learn_dest_id;
    if ((rs_data->flags & X_IC_VIP_IN_UNTAGGED_SET) != 0)
    {
        resp.vip_untagged_set = 1;
    }
    if ((rs_data->flags & X_IC_CNP_IN_MEMBER_SET) != 0)
    {
        resp.cnp_member_set = 1;
    }

    if (rs_data->port_state)
    {
        switch(rs_data->port_state->port_state)
        {
        case X_FORWARDING:
            resp.cnp_port_state = PORTSTATE_FORWARDING;
            break;
        case X_DISCARDING:
            resp.cnp_port_state = PORTSTATE_DISCARDING;
            break;
        case X_LEARNING:
            resp.cnp_port_state = PORTSTATE_LEARNING;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }
    else
    {
        resp.cnp_port_state = PORTSTATE_DISCARDING;
    }

    /* SuppressionMeterAddr, point to point and VIPIngressEgress */
    resp.sup_meter_addr = rs_data->suppression_meter_addr;
    if ((rs_data->flags & X_IC_USE_METER) != 0)
    {
        resp.use_meter = 1;
    }
    if ((rs_data->flags & X_IC_POINT_TO_POINT) != 0)
    {
        resp.p_to_p = 1;
    }
    if ((rs_data->flags & X_IC_VIP_INGRESS_ALLOWED) != 0)
    {
        resp.in_eg_allowed = 2;
    }
    if ((rs_data->flags & X_IC_VIP_EGRESS_ALLOWED) != 0)
    {
        resp.in_eg_allowed |= 1;
    }

    /* Counter address */
    resp.counter_addr = rs_data->packet_counter_addr;
    if ((rs_data->flags & X_IC_USE_COUNTER) != 0)
    {
        resp.use_counter = 1;
    }
    
    const char * instance_table_resp_conv = INSTANCE_TABLE_RESP;
    CONVERT_ENDIAN(instance_table_resp, &resp);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM0_Write128;
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
    if (ret > 0)
        ret = 0;
    
 out:
#endif
    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int
XEL_InstanceSet(uint8_t             iXid,
                uint16_t            rqPortID,
                uint16_t            rqSVID,
                uint32_t            rsSID,
                uint16_t            rsBVID,
                uint16_t            rsSVID,
                uint32_t            rsVSID,
                uint8_t             rsCBPPrioRegenRef,
                uint16_t            rsLearnDestId,
                struct X_PortState* rsPortState,
                uint16_t            rsFlags,
                uint16_t            rsSuppressionMeterAddr,
                uint16_t            rsPacketCounterAddr)
{
    struct xel_instance_req_data rq_data;
    struct xel_instance_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.svid = rqSVID;

    rs_data.sid = rsSID;
    rs_data.bvid = rsBVID;
    rs_data.svid = rsSVID;
    rs_data.vsid = rsVSID;
    rs_data.cbp_prio_regen_ref = rsCBPPrioRegenRef;
    rs_data.learn_dest_id = rsLearnDestId;
    rs_data.port_state = (struct xel_port_state*)rsPortState;
    rs_data.flags = rsFlags;
    rs_data.suppression_meter_addr = rsSuppressionMeterAddr;
    rs_data.packet_counter_addr = rsPacketCounterAddr;
    
    return(xel_instance_set(iXid, &rq_data, &rs_data));
}

