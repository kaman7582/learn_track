/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_cvidregistration.c,v $
 * $Revision: 1.34 $
 * 
 * \file  xel_cvidregistration.c
 * \brief VID management API
 * 
 * Description:
 * API for managing C-VID registration tables on ingress and egress.
 *--------------------------------------------------------------------------*/

#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "drv_driver.h"
#include "cvid_registration.h"
#include "cvid_filtering.h"
#include "fpa_types.h"
#include "xel_cvidregistration.h"
#include "xel_vidtranslation.h"
#include "memory.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "xel_endian.h"
#ifdef USE_L3
#include "mpls_route.h"
#endif

int xel_cvid_registration_set_ingress(uint8_t xid,
                                      struct xel_cvid_reg_ingress_req_data* rq_data,
                                      struct xel_cvid_reg_ingress_resp_data* rs_data)
{
    uint32_t address;
    struct cvid_registration_ingress_resp resp;
    uint16_t index;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    struct svid_entry filter_resp;
    uint8_t data[4];
#ifdef USE_L3
    uint8_t bittbl_data[2];
#endif
    
    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Clear data structures. */
    memset(&resp, 0, sizeof(resp));

    /* Address */
    address = VID_TRANSLATION_INGRESS_ADDR + (rq_data->port_id * 4096 + rq_data->cvid) * 2;
    if (address >= (VID_TRANSLATION_INGRESS_ADDR + VID_TRANSLATION_INGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Response */
    resp.vsid  = rs_data->vsid;
    resp.svid = rs_data->svid;
    resp.learn_dest_id = rs_data->learn_dest_id;

    if ((rs_data->flags & X_VT_IP4_NO_ROUTE) != 0)
        resp.ipv4ucast_no_route = 1;

    if ((rs_data->flags & X_VT_IP4_MCAST_NO_ROUTE) != 0)
        resp.ipv4mcast_no_route = 1;

    if ((rs_data->flags & X_VT_IP6_NO_ROUTE) != 0)
        resp.ipv6ucast_no_route = 1;

    if ((rs_data->flags & X_VT_IP6_MCAST_NO_ROUTE) != 0)
        resp.ipv6mcast_no_route = 1;
    
    if ((rs_data->flags & X_VT_USE_METER) != 0)
    {
        resp.suppression_meter_addr = rs_data->suppression_meter_addr;
        resp.use_meter = 1;
    }
    if ((rs_data->flags & X_VT_USE_COUNTER) != 0)
    {
        resp.counter_addr = rs_data->packet_counter_addr;
        resp.use_counter = 1;
    }
    if ((rs_data->flags & X_VT_UNTAGGED_PEP) != 0)
    {
        resp.untagged_pep = 1;
    }

    if (rs_data->port_state)
    {
        switch(rs_data->port_state->port_state)
        {
        case X_FORWARDING:
            resp.port_state = PORTSTATE_FORWARDING;
            break;
        case X_DISCARDING:
            resp.port_state = PORTSTATE_DISCARDING;
            break;
        case X_LEARNING:
            resp.port_state = PORTSTATE_LEARNING;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    
        if (rs_data->port_state->is_member != 0)
        {
            resp.is_in_port_member_set = 1;
        }
    }
    else
    {
        resp.port_state = PORTSTATE_DISCARDING;
    }

    resp.prio_reg_ref = rs_data->prio_reg_ref;

    const char * ingress_cvid_reg_resp_conv = CVID_REGISTRATION_INGRESS_RESP;    
    CONVERT_ENDIAN(ingress_cvid_reg_resp, &resp);
    
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

    /* Write to filter table */

    /* Clear data structures. */
    memset(&filter_resp, 0, sizeof(filter_resp));
    memset(&data, 0, sizeof(data));
    
    /* Address */
    address = CVID_FILTERING_ADDR + (rq_data->port_id * 4096 + rq_data->cvid) / 4;
    if (address >= (CVID_FILTERING_ADDR + CVID_FILTERING_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        goto out;
    }

    /* Response data */
    
    index = 3 - (rq_data->cvid % 4);
    filter_resp.svid = rs_data->svid;
    if ((rs_data->flags & X_VT_UNTAGGED_CEP) != 0)
    {
        filter_resp.svid_cep_untagged_set = 1;
    }

    const char * svid_entry_conv = "h";    
    CONVERT_ENDIAN(svid_entry, &filter_resp);

    data[1] = index;
    memcpy(&data[2], &filter_resp, sizeof(struct svid_entry));
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM0_SetWord;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(data), &data);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

#ifdef USE_L3
    /* Write to MPLS route bit table. */

    address = MPLS_ROUTE_BITS_ADDR + rq_data->cvid;
    if (address >= (MPLS_ROUTE_BITS_ADDR + MPLS_ROUTE_BITS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        goto out;
    }

    index = 63 - rq_data->port_id;
    bittbl_data[0] = index;
    if ((rs_data->flags & X_VT_MPLS_NO_ROUTE) != 0)
        bittbl_data[1] = 1;
    else
        bittbl_data[1] = 0;
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = SRAM0_SetBit;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(bittbl_data), &bittbl_data);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }
#endif
    
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

int xel_cvid_registration_set_egress(uint8_t xid,
                                     struct xel_cvid_reg_egress_req_data* rq_data,
                                     struct xel_cvid_reg_egress_resp_data* rs_data)
{
    struct cvid_registration_egress_resp resp;
    uint32_t address;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    
    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&resp, 0, sizeof(struct cvid_registration_egress_resp));

    address = VID_TRANSLATION_EGRESS_ADDR + rq_data->port_id * 4096 + rq_data->svid;
    if (address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    resp.svid = rs_data->cvid;
    if ((rs_data->flags & X_VT_USE_COUNTER) != 0)
    {
        resp.counter_addr = rs_data->packet_counter_addr;
        resp.use_counter = 1;
    }

    if (rs_data->port_state)
    {
        if (rs_data->port_state->is_tagged)
        {
            resp.in_tagged_set = 1;
        }
        switch(rs_data->port_state->port_state)
        {
        case X_FORWARDING:
            resp.port_state = PORTSTATE_FORWARDING;
            break;
        case X_DISCARDING:
            resp.port_state = PORTSTATE_DISCARDING;
            break;
        case X_LEARNING:
            resp.port_state = PORTSTATE_LEARNING;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }
    else
    {
        resp.port_state = PORTSTATE_DISCARDING;
    }

    if ((rs_data->flags & X_VT_ENABLE_FILTER) != 0)
    {
        resp.enable_filter = 1;
    }
    
    switch(rs_data->filter)
    {
    case X_ADMIT_ONLY_VLAN_TAGGED:
        resp.acceptable_frames = ADMIT_ONLY_VLAN_TAGGED_FRAMES;
        break;
    case X_ADMIT_ONLY_UNTAGGED_PRIO_TAGGED:
        resp.acceptable_frames = ADMIT_ONLY_UNTAGGED_AND_PRIORITY_TAGGED_FRAMES;
        break;
    case X_ADMIT_ONLY_UNTAGGED:
        resp.acceptable_frames = ADMIT_ONLY_UNTAGGED_FRAMES;
        break;
    case X_ADMIT_ALL:
        resp.acceptable_frames = ADMIT_ALL_FRAMES;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        break;
    }

    resp.priority = rs_data->priority;
    resp.prio_reg_ref = rs_data->cvc_eg_prio_reg_ref;

    const char * egress_cvid_reg_resp_conv = CVID_REGISTRATION_EGRESS_RESP;    
    CONVERT_ENDIAN(egress_cvid_reg_resp, &resp);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM2_Write64;
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

int xel_cvid_registration_init(uint8_t xid,
                               uint16_t port_id,
                               enum xel_cvid_reg_init_mode mode)
{
    int ret = 0;
    int i;
    struct cvid_registration_ingress_resp ing_resp;
    struct cvid_registration_egress_resp eg_resp;
    uint32_t address;
    uint16_t count;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

#ifdef RDK
    count = 4096;
#else
    count = 100;
#endif

    memset(&ing_resp, 0, sizeof(ing_resp));
    for (i = 0; i < count; i++) {
        switch (mode) {
        case X_CVID_REG_DEFAULT_INIT:
            /* default */
            ing_resp.svid  = 0;
            ing_resp.port_state = PORTSTATE_DISCARDING;
            break;
        case X_CVID_REG_QUNTAGGED_INIT:
            /* Q-Bridge mode Untagged CEP = 1 */
            ing_resp.svid  = i;
            ing_resp.untagged_pep = 1;
            break;
        case X_CVID_REG_QTAGGED_INIT:
            /* Q-Bridge mode Untagged CEP = 0 */
            ing_resp.svid  = i;
            break;
        default:
            break;
        };

        address = (i + 4096 * port_id) * 2 + VID_TRANSLATION_INGRESS_ADDR;
        if (address >= (VID_TRANSLATION_INGRESS_ADDR + VID_TRANSLATION_INGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }

        const char * ingress_cvid_reg_resp_conv = CVID_REGISTRATION_INGRESS_RESP;
        CONVERT_ENDIAN(ingress_cvid_reg_resp, &ing_resp);
    
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS0;
        xcm.Addr = htonl(address);
        xcm.ReqCode = LASRAM0_Write128;
        xcm.RW = XCM_WRITE;
        xcm.UID = drv_get_uid(xid, xcm.SUID, address);
        profile = drv_get_profile(xid, DRV_PROF_0);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(ing_resp), &ing_resp);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
    }

    memset(&eg_resp, 0, sizeof(eg_resp));
    for (i = 0; i < count; i++) {
        switch (mode) {
        case X_CVID_REG_DEFAULT_INIT:
            /* default */
            eg_resp.svid  = 0;
            eg_resp.port_state = PORTSTATE_DISCARDING;
            break;
        case X_CVID_REG_QUNTAGGED_INIT:
            eg_resp.svid   = i;
            eg_resp.port_state = PORTSTATE_DISCARDING;
            break;
        case X_CVID_REG_QTAGGED_INIT:
            eg_resp.svid   = i;
            eg_resp.port_state = PORTSTATE_DISCARDING;
            break;
        default:
            break;
        };

        address = i + 4096 * port_id + VID_TRANSLATION_EGRESS_ADDR;
        if (address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }

        const char * egress_cvid_reg_resp_conv = CVID_REGISTRATION_EGRESS_RESP;    
        CONVERT_ENDIAN(egress_cvid_reg_resp, &eg_resp);
    
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS2;
        xcm.Addr = htonl(address);
        xcm.ReqCode = LASRAM2_Write64;
        xcm.RW = XCM_WRITE;
        xcm.UID = drv_get_uid(xid, xcm.SUID, address);
        profile = drv_get_profile(xid, DRV_PROF_0);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(eg_resp), &eg_resp);
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
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}

#ifdef USE_L3
int xel_mpls_route_init(uint8_t xid)
{
    int ret = 0;
    int i;
    struct mpls_route_bits_resp resp;
    uint32_t address;
    uint16_t count;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

#ifdef RDK
    count = 4096;
#else
    count = 100;
#endif

    memset(&resp, 0, sizeof(resp));
    for (i = 0; i < count; i++)
    {

        address = i + MPLS_ROUTE_BITS_ADDR;
        if (address >= (MPLS_ROUTE_BITS_ADDR + MPLS_ROUTE_BITS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }

        const char * mpls_route_bits_resp_conv = MPLS_ROUTE_BITS_RESP;    
        CONVERT_ENDIAN(mpls_route_bits_resp, &resp);
    
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_SE0;
        xcm.Addr = htonl(address);
        xcm.ReqCode = SRAM0_Write64;
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
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}
#endif

/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int XEL_CVIDRegistrationSetIngress(uint8_t             iXid,
                                   uint16_t            rqPortID,
                                   uint16_t            rqCVID,
                                   uint16_t            rsSVID,
                                   uint32_t            rsVSID,
                                   uint16_t            rsLearnDestId,
                                   uint16_t            rsPrioRegRef,
                                   struct X_PortState* rsPortState,
                                   uint16_t            rsFlags,
                                   uint16_t            rsSuppressionMeterAddr,
                                   uint16_t            rsPacketCounterAddr)
{
    struct xel_cvid_reg_ingress_req_data rq_data;
    struct xel_cvid_reg_ingress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.cvid = rqCVID;

    rs_data.svid = rsSVID;
    rs_data.vsid = rsVSID;
    rs_data.learn_dest_id = rsLearnDestId;
    rs_data.prio_reg_ref = rsPrioRegRef;
    rs_data.port_state = (struct xel_port_state*)rsPortState;
    rs_data.flags = rsFlags;
    rs_data.suppression_meter_addr = rsSuppressionMeterAddr;
    rs_data.packet_counter_addr = rsPacketCounterAddr;

    return(xel_cvid_registration_set_ingress(iXid, &rq_data, &rs_data));
}

int XEL_CVIDRegistrationSetEgress(uint8_t             iXid,
                                  uint16_t            rqPortID,
                                  uint16_t            rqSVID,
                                  uint16_t            rsCVID,
                                  uint8_t             rsPriority,
                                  uint16_t            rsCVCEgPrioRegenRef,
                                  uint16_t            rsFlags,
                                  enum X_Frames       rsFilter,
                                  struct X_PortState* rsPortState,
                                  uint16_t            rsPacketCounterAddr)
{
    struct xel_cvid_reg_egress_req_data rq_data;
    struct xel_cvid_reg_egress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.svid = rqSVID;

    rs_data.cvid = rsCVID;
    rs_data.priority = rsPriority;
    rs_data.cvc_eg_prio_reg_ref = rsCVCEgPrioRegenRef;
    rs_data.flags = rsFlags;
    rs_data.filter = rsFilter;
    rs_data.port_state = (struct xel_port_state*)rsPortState;
    rs_data.packet_counter_addr = rsPacketCounterAddr;

    return(xel_cvid_registration_set_egress(iXid, &rq_data, &rs_data));
}

/*
 * Initialize table.
 */
int XEL_CVIDRegistrationInit(uint8_t iXid, uint16_t rqPortID, 
                             enum CVIDRegInitMode iMode)
{
    return(xel_cvid_registration_init(iXid, rqPortID, iMode));
}
