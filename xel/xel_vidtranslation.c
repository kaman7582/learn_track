/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_vidtranslation.c,v $
 * $Revision: 1.38 $
 * 
 * \file xel_vidtranslation.c
 * \brief VID management API
 * 
 * Description:
 * API for managing VID translation tables on ingress and egress.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "vid_translation.h"
#include "fpa_types.h"
#include "fpa_ecmheader.h"
#include "xel_vidtranslation.h"
#include "vid_translation.h"
#include "memory.h"
#include "engine_operations.h"
#include "cvid_filtering.h"

#ifdef USE_ECM_PROGRAM
#include "pkg.h"
#endif
#include "fpa_endian_conv_strings.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "xel_endian.h"

int xel_vid_translation_set_ingress(uint8_t xid,
                                    struct xel_vid_trans_ingress_req_data* rq_data,
                                    struct xel_vid_trans_ingress_resp_data* rs_data)
{
    uint32_t address;
    struct vid_translation_ingress_resp resp;
    uint8_t i;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structures. */
    memset(&resp, 0, sizeof(resp));

    /* Address */
    address = VID_TRANSLATION_INGRESS_ADDR + (rq_data->port_id * 4096 + (rq_data->local_svid & 0x0fff)) * 2;
    if (address >= (VID_TRANSLATION_INGRESS_ADDR + VID_TRANSLATION_INGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Response */
    resp.vsid = rs_data->vsid;
    resp.svid = rs_data->relay_svid;
    resp.learn_dest_id = rs_data->learn_dest_id;

    if ((rs_data->flags & X_VT_USE_METER) != 0) {
        resp.suppression_meter_addr = rs_data->suppression_meter_addr;
        resp.use_suppression_meter = 1;
    }
    if ((rs_data->flags & X_VT_USE_COUNTER) != 0) {
        resp.counter_addr = rs_data->packet_counter_addr;
        resp.use_counter = 1;
    }
    if ((rs_data->flags & X_VT_COPY_SECOND_TAG) != 0)
        resp.copy_second_tag = 1;

    if ((rs_data->flags & X_VT_DISABLE_LEARNING) != 0)
        resp.fwd_only = 1;
        
    if (rs_data->port_state) {
        switch(rs_data->port_state->port_state) {
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
            resp.is_in_port_member_set = 1;
    } else
        resp.port_state = PORTSTATE_DISCARDING;

    /* 8 md levels in the variable. */
    for (i = 0; i < 8; i++)
    {
        switch ((rs_data->md_levels >> (i * 2)) & 0x3)
        {
        case X_VT_CFM_FORWARD:
            resp.md_level |= SVID_CFM_FORWARD << (i * 2);
            break;
        case X_VT_CFM_PROCESS_FP:
            resp.md_level |= SVID_CFM_PROCESS_FP << (i * 2);
            break;
        case X_VT_CFM_TO_CPU:
            resp.md_level |= SVID_CFM_TO_CPU << (i * 2);
            break;
        case X_VT_CFM_DROP:
            resp.md_level |= SVID_CFM_DROP << (i * 2);
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * vid_translation_ingress_resp_conv = VID_TRANSLATION_INGRESS_RESP;
    CONVERT_ENDIAN(vid_translation_ingress_resp, &resp);
    
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
    
    return ret;
}

int xel_vid_translation_set_egress(uint8_t xid,
                                   struct xel_vid_trans_egress_req_data* rq_data,
                                   struct xel_vid_trans_egress_resp_data* rs_data)
{
    uint32_t address;
    struct vid_translation_egress_resp resp;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    uint8_t i;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structures. */
    memset(&resp, 0, sizeof(resp));
    
    address = VID_TRANSLATION_EGRESS_ADDR + rq_data->port_id * 4096 + rq_data->relay_svid;
    if(address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    resp.svid = rs_data->local_svid;
    if (rs_data->port_state) {
        if (rs_data->port_state->is_tagged)
            resp.is_in_tagged_set = 1;

        if (rs_data->port_state->is_member)
            resp.is_in_member_set = 1;

        switch(rs_data->port_state->port_state) {
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
    } else
        resp.port_state = PORTSTATE_DISCARDING;
    
    if ((rs_data->flags & X_VT_USE_COUNTER) != 0)
    {
        resp.counter_address = rs_data->packet_counter_addr;
        resp.use_counter = 1;
    }

    /* 8 md levels in the variable. */
    for (i = 0; i < 8; i++)
    {
        switch ((rs_data->md_levels >> (i * 2)) & 0x3)
        {
        case X_VT_CFM_FORWARD:
            resp.md_level |= SVID_CFM_FORWARD << (i * 2);
            break;
        case X_VT_CFM_PROCESS_FP:
            resp.md_level |= SVID_CFM_PROCESS_FP << (i * 2);
            break;
        case X_VT_CFM_TO_CPU:
            resp.md_level |= SVID_CFM_TO_CPU << (i * 2);
            break;
        case X_VT_CFM_DROP:
            resp.md_level |= SVID_CFM_DROP << (i * 2);
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * vid_translation_egress_resp_conv = VID_TRANSLATION_EGRESS_RESP;
    CONVERT_ENDIAN(vid_translation_egress_resp, &resp);
    
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
    if (ret > 0)
        ret = 0;
    
 out:
    
    return ret;
}

int xel_cvid_filtering_init(uint8_t xid)
{
    struct cvid_filtering_resp          cvid_filter_resp;
    struct XCM_Header                   xcm;
    msgprof_t                           profile;
    
    msgflow_t flow    = drv_get_flow(xid);
    int ret           = 0;
    int i             = 0;
    uint32_t address  = 0;

#ifdef RDK
    uint16_t count = CVID_FILTERING_SIZE;
#else
    uint16_t count = 100;
#endif

    /* Initialization of the CVID filtering table */
    memset(&cvid_filter_resp, 0, sizeof(cvid_filter_resp));

    for (i = 0; i < count; i++) /* 4 entries per address */
    {
        address = i + CVID_FILTERING_ADDR;

        if (address >= (CVID_FILTERING_ADDR + CVID_FILTERING_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            goto out;
        }

        const char* cvid_filtering_resp_conv = CVID_FILTERING_RESP;
        CONVERT_ENDIAN(cvid_filtering_resp, &cvid_filter_resp);

        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS0;
        xcm.Addr = htonl(address);
        xcm.ReqCode = LASRAM0_Write64;
        xcm.RW = XCM_WRITE;
        xcm.UID = drv_get_uid(xid, xcm.SUID, address);
        profile = drv_get_profile(xid, DRV_PROF_0);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(cvid_filter_resp), &cvid_filter_resp);
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

int xel_vid_translation_init(uint8_t xid,
                             uint16_t port_id)
{
    struct vid_translation_ingress_resp ing_resp;
    struct vid_translation_egress_resp  eg_resp;
    struct cvid_filtering_resp          cvid_filter_resp;
    struct XCM_Header                   xcm;
    msgprof_t                           profile;
    
    msgflow_t flow    = drv_get_flow(xid);
    int ret           = 0;
    int i             = 0;
    uint32_t address  = 0;
    
#ifdef RDK
    uint16_t count = 4096;
#else
    uint16_t count = 100;
#endif

    memset(&ing_resp, 0, sizeof(ing_resp));
    for (i = 0; i < count; i++) {
        ing_resp.svid = i;
        ing_resp.port_state = PORTSTATE_DISCARDING;

        address = (i + 4096 * port_id) * 2 + VID_TRANSLATION_INGRESS_ADDR;
        if(address >= (VID_TRANSLATION_INGRESS_ADDR + VID_TRANSLATION_INGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }

        const char * vid_translation_ingress_resp_conv = VID_TRANSLATION_INGRESS_RESP;
        CONVERT_ENDIAN(vid_translation_ingress_resp, &ing_resp);
    
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
        eg_resp.svid = i;
        eg_resp.port_state = PORTSTATE_DISCARDING;

        address = i + 4096 * port_id + VID_TRANSLATION_EGRESS_ADDR;
        if(address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }

        const char * vid_translation_egress_resp_conv = VID_TRANSLATION_EGRESS_RESP;
        CONVERT_ENDIAN(vid_translation_egress_resp, &eg_resp);
    
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

int xel_vid_translation_clear(uint8_t xid)
{
    int ret = 0;
#ifdef USE_ECM_PROGRAM
    struct init64_ecm_header_type vid_init_ecm_header;
    const char * init64_ecm_header_type_conv = "hb2ww2";
    uint8_t pkggen[3];
    
    vid_init_ecm_header.ecm.seq = TABLE_INIT_ECM_SEQ;
    vid_init_ecm_header.ecm.type = IN_VID_INIT_ECM_TYPE;
    vid_init_ecm_header.base_address = VID_TRANSLATION_INGRESS_ADDR;
    vid_init_ecm_header.data.data_0 = 0;
    vid_init_ecm_header.data.data_1 = 0;

    CONVERT_ENDIAN(init64_ecm_header_type, &vid_init_ecm_header);
    ret = pkg_start_packet_gen(xid, VID_TRANSLATION_INGRESS_SIZE, sizeof(struct init64_ecm_header_type),
                               (uint8_t*)&vid_init_ecm_header, &pkggen[0]);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    
    vid_init_ecm_header.ecm.seq = TABLE_INIT_ECM_SEQ;
    vid_init_ecm_header.ecm.type = EG_VID_INIT_ECM_TYPE;
    vid_init_ecm_header.base_address = VID_TRANSLATION_EGRESS_ADDR;
    vid_init_ecm_header.data.data_0 = 0;
    vid_init_ecm_header.data.data_1 = 0;

    CONVERT_ENDIAN(init64_ecm_header_type, &vid_init_ecm_header);
    ret = pkg_start_packet_gen(xid, VID_TRANSLATION_EGRESS_SIZE, sizeof(struct init64_ecm_header_type),
                               (uint8_t*)&vid_init_ecm_header, &pkggen[1]);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    vid_init_ecm_header.ecm.seq = TABLE_INIT_ECM_SEQ;
    vid_init_ecm_header.ecm.type = IN_VID_INIT_ECM_TYPE;
    vid_init_ecm_header.base_address = CVID_FILTERING_ADDR;
    vid_init_ecm_header.data.data_0 = 0;
    vid_init_ecm_header.data.data_1 = 0;

    CONVERT_ENDIAN(init64_ecm_header_type, &vid_init_ecm_header);
    ret = pkg_start_packet_gen(xid, CVID_FILTERING_SIZE, sizeof(struct init64_ecm_header_type),
                               (uint8_t*)&vid_init_ecm_header, &pkggen[2]);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    ret = pkg_wait_for_completion(xid, pkggen[0], 0);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    ret = pkg_wait_for_completion(xid, pkggen[1], 0);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    ret = pkg_wait_for_completion(xid, pkggen[2], 0);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
#endif
    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Set ingress entry.
 */
int
XEL_VIDTranslationSetIngress(uint8_t iXid, uint16_t rqPortID,
                             uint16_t rqLocalSVID, uint16_t rsRelaySVID,
                             uint32_t rsVSID, uint16_t rsLearnDestId,
                             struct X_PortState* rsPortState, uint16_t rsFlags,
                             uint16_t rsSuppressionMeterAddr,
                             uint16_t rsPacketCounterAddr, uint16_t rsMDLevels)
{
    struct xel_vid_trans_ingress_req_data rq_data;
    struct xel_vid_trans_ingress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.local_svid = rqLocalSVID;

    rs_data.relay_svid = rsRelaySVID;
    rs_data.vsid = rsVSID;
    rs_data.learn_dest_id = rsLearnDestId;
    rs_data.port_state = (struct xel_port_state*)rsPortState;
    rs_data.flags = rsFlags;
    rs_data.suppression_meter_addr = rsSuppressionMeterAddr;
    rs_data.packet_counter_addr = rsPacketCounterAddr;
    rs_data.md_levels = rsMDLevels;

    return(xel_vid_translation_set_ingress(iXid, &rq_data, &rs_data));
}

/*
 * Set egress entry.
 */
int
XEL_VIDTranslationSetEgress(uint8_t iXid, uint16_t rqPortID,
                            uint16_t rqRelaySVID, uint16_t rsLocalSVID,
                            uint16_t rsFlags, uint16_t rsPacketCounterAddr,
                            struct X_PortState* rsPortState,
                            uint16_t rsMDLevels)
{
    struct xel_vid_trans_egress_req_data rq_data;
    struct xel_vid_trans_egress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.relay_svid = rqRelaySVID;

    rs_data.local_svid = rsLocalSVID;
    rs_data.flags = rsFlags;
    rs_data.packet_counter_addr = rsPacketCounterAddr;
    rs_data.port_state = (struct xel_port_state*)rsPortState;
    rs_data.md_levels = rsMDLevels;

    return(xel_vid_translation_set_egress(iXid, &rq_data, &rs_data));
}

int
XEL_VIDTranslationInit(uint8_t iXid, uint16_t rqPortID)
{
    return(xel_vid_translation_init(iXid, rqPortID));
}

/*
 * Clear tables.
 */
int
XEL_VIDTranslationClear(uint8_t iXid)
{
    return(xel_vid_translation_clear(iXid));
}

