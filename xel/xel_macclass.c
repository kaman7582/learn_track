/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_macclass.c,v $
 * $Revision: 1.45 $
 * 
 * \file  xel_macclass.c
 * \brief Traffic classification management API
 * 
 * Description:
 * API for managing traffic classification table.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_mac_class.h"
#include "mem_nse.h"
#ifdef XEL_TM
#include "mac_classification_tm.h"
#include "classification_tm.h"
#else
#include "mac_classification.h"
#include "classification.h"
#endif
#include "memory.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "fpa_memory_map.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

static int write(uint8_t xid,
                 uint32_t index,
                 struct mac_classify_index_req* mask,
                 struct classify_resp* resp,
                 struct mac_classify_index_req* req)
{
    int ret = 0;
    uint32_t address;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    
    address = MAC_CLASSIFY_ADDR + index;
    if (address >= (MAC_CLASSIFY_ADDR + MAC_CLASSIFY_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(struct classify_resp), resp);
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

    ret = mem_nse_write_search_word_and_mask_320(xid, index,
                                                 MAC_CLASSIFY_INDEX_ADDR,
                                                 MAC_CLASSIFY_INDEX_SIZE,
                                                 (uint8_t*)req, sizeof(struct mac_classify_index_req),
                                                 (uint8_t*)mask, sizeof(struct mac_classify_index_req));
    
 out:
    
    return ret;
}

int xel_ether_set_classify_rule(uint8_t xid,
                                uint32_t index,
                                struct xel_ether_classify_req_data* rq_data,
                                struct xel_ether_classify_req_data* rq_mask,
                                struct xel_ether_classify_resp_data* rs_data)
{
    struct mac_classify_index_req req;
    struct mac_classify_index_req mask;
    struct classify_resp resp;
    int ret = 0;

    if ((!rq_data) || (!rq_mask) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    if ((rs_data->flags & X_CF_USE_METER) != 0)
    {
        if (rs_data->meter == 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
    }

    if (rq_mask->damac == 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (rq_mask->samac == 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (rq_data->damac == 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (rq_data->samac == 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Clear data structures. */
    memset(&req, 0, sizeof(struct mac_classify_index_req));
    memset(&mask, 0, sizeof(struct mac_classify_index_req));
    memset(&resp, 0, sizeof(struct classify_resp));

    /* Request data */

    /* Table id */
    mask.table_id = NSE_CLASS_TABLE_ID_MASK;
    req.table_id = MAC_CLASS_NSE_TABLE_ID;

    /* Wildcard port or not */
    if((rs_data->flags & X_CF_WILDCARD_PORT) == 0)
    {
        mask.rx_port.is_trunk = 1;
        /* Trunk or port */
        if ((rs_data->flags & X_CF_IS_TRUNK) != 0)
        {
            mask.rx_port.trunk_no = rq_mask->rx_port;
            req.rx_port.trunk_no = rq_data->rx_port;
            req.rx_port.is_trunk = 1;
        }
        else
        {
            mask.rx_port.port = rq_mask->rx_port;
            req.rx_port.port = rq_data->rx_port;
        }
    }

    /* VSID */
    mask.vsid = rq_mask->vsid & 0xffff;
    mask.vsid_msb = (rq_mask->vsid >> 16) & 0x3;
    req.vsid = rq_data->vsid & 0xffff;
    req.vsid_msb = (rq_data->vsid >> 16) & 0x3;  

    /* DAMAC */
    memcpy(&mask.damac_lsb, &rq_mask->damac->a[2], sizeof(struct xel_ethernet_addr)-2);
    memcpy(&req.damac_lsb, &rq_data->damac->a[2], sizeof(struct xel_ethernet_addr)-2); 
    memcpy(&req.damac_msb, rq_data->damac, 2); 
    memcpy(&mask.damac_lsb, rq_mask->damac, 2);
   
    /* SAMAC */
    memcpy(&mask.samac_msb, rq_mask->samac, sizeof(struct xel_ethernet_addr)-2);
    memcpy(&req.samac_msb, rq_data->samac, sizeof(struct xel_ethernet_addr)-2); 
    mask.samac_lsb = (uint16_t)((rq_mask->samac->a[4]<< 8) | rq_mask->samac->a[5]);
    req.samac_lsb = (uint16_t)((rq_data->samac->a[4]<< 8) | rq_data->samac->a[5]);

    /* Type of request data */
    mask.rx_port_type = 0xff;
    req.rx_port_type = rq_data->entry_type;  

    /* Ethernet type */
    mask.eth_type = rq_mask->eth_type;
    req.eth_type  = rq_data->eth_type;

    /* Enable IP protocol class if requested. */
    if ((rs_data->flags & X_CF_REQUIRE_IP) != 0)
    {
        mask.ip_proto = rq_mask->ip_proto;
        req.ip_proto = rq_data->ip_proto;
            
        mask.dscp = rq_mask->dscp;
        req.dscp = rq_data->dscp;

        mask.ip_is_valid = 1;
        req.ip_is_valid = 1;
    }
    
    /* Type dependent fields */
    switch (rq_data->entry_type)
    {
    case X_RAW_PW:
    {
        struct xel_raw_pw_param* mask_param = (struct xel_raw_pw_param*)rq_mask->entry_param;
        struct xel_raw_pw_param* req_param = (struct xel_raw_pw_param*)rq_data->entry_param;
        /* VC label. Shift label to put it into same position as in packet memory. */
        mask.type.raw_pw.vc_label = mask_param->vc_label << 12;
        req.type.raw_pw.vc_label = req_param->vc_label << 12;
        /* Experimental bits */
        mask.type.raw_pw.exp = mask_param->exp;
        req.type.raw_pw.exp = req_param->exp;
        break;
    }
    case X_TAGGED_PW:
    {
        struct xel_tagged_pw_param* mask_param = (struct xel_tagged_pw_param*)rq_mask->entry_param;
        struct xel_tagged_pw_param* req_param = (struct xel_tagged_pw_param*)rq_data->entry_param;
        /* VC label. Shift label to put it into same position as in packet memory. */
        mask.type.tagged_pw.vc_label = mask_param->vc_label << 12;
        req.type.tagged_pw.vc_label = req_param->vc_label << 12;
        /* Experimental bits */
        mask.type.tagged_pw.exp = mask_param->exp;
        req.type.tagged_pw.exp = req_param->exp;
        /* SVID and prio + DE */
        mask.type.tagged_pw.vid |= mask_param->vid & VLAN_VID_MASK;
        mask.type.tagged_pw.vid |= (mask_param->prio << 13) & VLAN_PRIO_MASK;
        mask.type.tagged_pw.vid |= (mask_param->de << 12) & VLAN_DE_MASK;
        req.type.tagged_pw.vid |= req_param->vid & VLAN_VID_MASK;
        req.type.tagged_pw.vid |= (req_param->prio << 13) & VLAN_PRIO_MASK;
        req.type.tagged_pw.vid |= (req_param->de << 12) & VLAN_DE_MASK;
        break;
    }
    case X_SVC_OR_CVC:
    {
        struct xel_svc_cvc_param* mask_param = (struct xel_svc_cvc_param*)rq_mask->entry_param;
        struct xel_svc_cvc_param* req_param = (struct xel_svc_cvc_param*)rq_data->entry_param;
        /* Frame type */
        mask.type.svc_or_cvc.frame_type = mask_param->frame_type;
        req.type.svc_or_cvc.frame_type = req_param->frame_type;
        /* SVID and prio + DE */
        mask.type.svc_or_cvc.vid |= mask_param->vid & VLAN_VID_MASK;
        mask.type.svc_or_cvc.vid |= (mask_param->prio << 13) & VLAN_PRIO_MASK;
        mask.type.svc_or_cvc.vid |= (mask_param->de << 12) & VLAN_DE_MASK;
        req.type.svc_or_cvc.vid |= req_param->vid & VLAN_VID_MASK;
        req.type.svc_or_cvc.vid |= (req_param->prio << 13) & VLAN_PRIO_MASK;
        req.type.svc_or_cvc.vid |= (req_param->de << 12) & VLAN_DE_MASK;

        break;
    }
    case X_SVC_DOUBLE_TAGGED:
    {
        struct xel_svc_double_tagged_param* mask_param = (struct xel_svc_double_tagged_param*)rq_mask->entry_param;
        struct xel_svc_double_tagged_param* req_param = (struct xel_svc_double_tagged_param*)rq_data->entry_param;
        /* SVID and prio + DE for outer tag */
        mask.type.svc_double_tagged.svid |= mask_param->svid & VLAN_VID_MASK;
        mask.type.svc_double_tagged.svid |= (mask_param->s_prio << 13) & VLAN_PRIO_MASK;
        mask.type.svc_double_tagged.svid |= (mask_param->de << 12) & VLAN_DE_MASK;
        req.type.svc_double_tagged.svid |= req_param->svid & VLAN_VID_MASK;
        req.type.svc_double_tagged.svid |= (req_param->s_prio << 13) & VLAN_PRIO_MASK;
        req.type.svc_double_tagged.svid |= (req_param->de << 12) & VLAN_DE_MASK;
        /* CVID and prio for inner tag */
        mask.type.svc_double_tagged.cvid |= mask_param->cvid & VLAN_VID_MASK;
        mask.type.svc_double_tagged.cvid |= (mask_param->c_prio << 13) & VLAN_PRIO_MASK;
        req.type.svc_double_tagged.cvid |= req_param->cvid & VLAN_VID_MASK;
        req.type.svc_double_tagged.cvid |= (req_param->c_prio << 13) & VLAN_PRIO_MASK;

        break;
    }
    case X_PBB_ADD:
    {
        struct xel_pbb_add_param* mask_param = (struct xel_pbb_add_param*)rq_mask->entry_param;
        struct xel_pbb_add_param* req_param = (struct xel_pbb_add_param*)rq_data->entry_param;
        mask.type.pbb_add.svid |= mask_param->svid & VLAN_VID_MASK;
        req.type.pbb_add.svid |= req_param->svid & VLAN_VID_MASK;
        break;
    }
    case X_PBB_DROP:
    {
        struct xel_pbb_drop_param* mask_param = (struct xel_pbb_drop_param*)rq_mask->entry_param;
        struct xel_pbb_drop_param* req_param = (struct xel_pbb_drop_param*)rq_data->entry_param;
        if (mask_param->damac == 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        memcpy(&mask.pbb_drop.cmac_dst, mask_param->damac, 6);
        if (req_param->damac == 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        memcpy(&req.pbb_drop.cmac_dst, req_param->damac, 6);
        mask.type.pbb_drop.isid = mask_param->isid;
        req.type.pbb_drop.isid = req_param->isid;
        mask.type.pbb_drop.bvid = mask_param->bvid;
        req.type.pbb_drop.bvid = req_param->bvid;
        break;
    }
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
        break;
    }

    /* Response data */
    
    if (rs_data->traffic_class != NULL)
    {
        if ((rs_data->flags & X_CF_OVERRIDE_TM_COS) != 0)
        {
            resp.flags.override_tm_cos = 1;
        }

        /* CoS */
        resp.flags.tm_cos = rs_data->traffic_class->tm_cos;

        /* Drop precedence */
        resp.flags.tm_drop_prec = rs_data->traffic_class->tm_drop_precedence;
        
        if (rs_data->meter == NULL)
        {
            /* Green marking PHB */
            resp.ryg_phb.green_phb = rs_data->traffic_class->marking_phb;
        }
    }

    if (rs_data->meter != NULL)
    {
        /* Use meter */
        if ((rs_data->flags & X_CF_USE_METER) != 0)
        {
            resp.flags.use_meter = 1;
	    
	    /* Use pre color from PCP decoding table. */
	    if ((rs_data->flags & X_CF_PRE_COLOR_DE) != 0)
	    {
                resp.flags.use_pcp_info = 1;
	    }
            /* Meter address */
            resp.meter_index = rs_data->meter->meter_index;

            /* Precoloring */
            switch(rs_data->meter->pre_color)
            {
            case X_COLOR_BLIND:
                resp.flags.meter_flags = TWO_RATE_REDUCING_COLOR_BLIND;
                break;
            case X_PRE_COLOR_GREEN:
                resp.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_GREEN;
                break;
            case X_PRE_COLOR_YELLOW:
                resp.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_YELLOW;
                break;
            case X_PRE_COLOR_RED:
                resp.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_RED;
                break;
            default:
                XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
                return -EINVAL;
                break;
            }

            /* Drop red packets */
            if ((rs_data->meter->meter_flags & X_DROP_RED) != 0)
            {
                resp.flags.drop_on_red = 1;
            }
            
            /* Drop yellow packets */
            if ((rs_data->meter->meter_flags & X_DROP_YELLOW) != 0)
            {
                resp.flags.drop_on_yellow = 1;
            }

            /* Green marking PHB */
            resp.ryg_phb.green_phb = rs_data->meter->green_marking_phb;

            /* Yellow marking PHB */
            resp.ryg_phb.yellow_phb = rs_data->meter->yellow_marking_phb;

            /* Red marking PHB */
            resp.ryg_phb.red_phb = rs_data->meter->red_marking_phb;
        }
    }

    switch (rs_data->rule)
    {
    case X_ACCEPT:
        if ((rs_data->flags & X_CF_USE_METER) != 0)
        {
            /* Jump target depend on meter type */
            switch (rs_data->meter->meter_type)
            {
            case X_METER_2698:
                resp.jump = SEQ_METER_2698_PREPARE;
                break;
            case X_METER_COUPLED:
                resp.jump = SEQ_COUPLED_METER_PREPARE;
                break;
            case X_METER_DECOUPLED:
                resp.jump = SEQ_DECOUPLED_METER_PREPARE;
                break;
            default:
                XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
                return -EINVAL;
                break;
            }
        }
        else
        {
            /* Jump target, no metering */
            resp.jump = SEQ_ACCEPT_NO_METER;
        }
        break;
    case X_DENY:
        resp.jump = SEQ_DENY;
        break;
    case X_SEND_TO_CPU:
        /* Reason */
        resp.reason = rs_data->reason;
        if ((rs_data->flags & X_CF_USE_METER) != 0)
        {
            /* Jump target depend on meter type */
            switch (rs_data->meter->meter_type)
            {
            case X_METER_2698:
                resp.jump = SEQ_TO_CPU_METER_2698;
                break;
            case X_METER_COUPLED:
                resp.jump = SEQ_TO_CPU_METER_COUPLED;
                break;
            case X_METER_DECOUPLED:
                resp.jump = SEQ_TO_CPU_METER_DECOUPLED;
                break;
            default:
                XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
                return -EINVAL;
                break;
            }
        }
        else
        {
            /* Jump target, no metering */
            resp.jump = SEQ_TO_CPU_NO_METERING;
        }
        break;
    case X_DUPLICATE_TO_CPU:
        resp.jump = SEQ_DUPLICATE_TO_CPU;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
        break;
    }

    switch (rq_data->entry_type)
    {
    case X_RAW_PW:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_RAW_PW_TYPE_REQ;
        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    case X_TAGGED_PW:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_TAGGED_PW_TYPE_REQ;
        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    case X_SVC_OR_CVC:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_SVC_OR_CVC_TYPE_REQ;

        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    case X_SVC_DOUBLE_TAGGED:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_SVC_DOUBLE_TAGGED_TYPE_REQ;

        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    case X_PBB_ADD:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_PBB_ADD_TYPE_REQ;
        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    case X_PBB_DROP:
    {
        const char * mac_classify_index_req_conv = MAC_CLASSIFY_INDEX_PBB_DROP_TYPE_REQ;
        CONVERT_ENDIAN(mac_classify_index_req, &req);
        CONVERT_ENDIAN(mac_classify_index_req, &mask);
        break;
    }
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
        break;
    }

    const char * classify_resp_conv = CLASSIFY_RESP;

    CONVERT_ENDIAN(classify_resp, &resp);
    
    /* Write data */
    ret = write(xid, index, &mask, &resp, &req);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    return ret;
}

int xel_ether_set_classify_no_match(uint8_t xid,
                                    uint32_t index)
{
    struct mac_classify_index_req req;
    struct mac_classify_index_req mask;
    struct classify_resp resp;
    int ret = 0;
    
    /* Clear data structures. */
    memset(&req, 0, sizeof(struct mac_classify_index_req));
    memset(&mask, 0, sizeof(struct mac_classify_index_req));
    memset(&resp, 0, sizeof(struct classify_resp));

    /* Table id */
    mask.table_id = NSE_CLASS_TABLE_ID_MASK;
    req.table_id = MAC_CLASS_NSE_TABLE_ID;

    /* Jump target */
    resp.jump = SEQ_VLAN_NO_MATCH;

    /* Endian conversion not needed. */
    
    /* Write data */
    ret = write(xid, index, &mask, &resp, &req);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    return ret;
}

int xel_ether_clear_classify(uint8_t xid,
                             uint32_t index)
{
    /* Clear entry */
    return(mem_nse_clear_320(xid, index, MAC_CLASSIFY_INDEX_ADDR, MAC_CLASSIFY_INDEX_SIZE));
}

int xel_ether_init_classify(uint8_t xid)
{
    int ret = 0;

#ifdef RDK
    uint32_t i;

    for (i = 0; i < ((MAC_CLASSIFY_INDEX_SIZE / 4) - 1); i++)
    {
        ret = xel_ether_clear_classify(xid, i);
        if(ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            return ret;
        }
    }
#endif

    ret = xel_ether_set_classify_no_match(xid, MAC_CLASSIFY_INDEX_SIZE / 4 - 1);

    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Add an ethernet classification entry in the table.
 */
int XEL_EtherClassifyRuleSet(uint8_t                   iXid, 
                             uint32_t                  iIndex,
                             uint8_t                   rqEntryType,
                             struct X_EtherClassifyData* rqData,
                             struct X_EtherClassifyData* rqMask,
                             void*                     rqExData,
                             void*                     rqExMask,
                             enum X_Rule               rsRule,
                             uint16_t                  rsFlags,
                             struct X_TrafficClass*    rsTrafficClass,
                             struct X_Meter*           rsMeter,
                             uint8_t                   rsReason)
{
    struct xel_ether_classify_req_data rq_data;
    struct xel_ether_classify_req_data rq_mask;
    struct xel_ether_classify_resp_data rs_data;
    struct xel_pbb_drop_param d_params;
    struct xel_pbb_drop_param m_params;
    
    rq_data.entry_type = rqEntryType;
    rq_data.rx_port = rqData->RxPort;
    rq_data.damac = &rqData->DAMAC;
    rq_data.samac = &rqData->SAMAC;
    rq_data.vsid = rqData->VSID;
    rq_data.eth_type = rqData->EthType;
    rq_data.ip_proto = rqData->IPProto;
    rq_data.dscp = rqData->DSCP;
    rq_data.encap_type = rqData->EncapType;
    if (rqEntryType == X_PBB_DROP)
    {
        d_params.damac = &((struct X_PBBDropParam*)rqExData)->DAMAC;
        d_params.isid = ((struct X_PBBDropParam*)rqExData)->ISID;
        d_params.bvid = ((struct X_PBBDropParam*)rqExData)->BVID;
        rq_data.entry_param = (void*)&d_params;
    }
    else
    {
        rq_data.entry_param = rqExData;
    }
    
    rq_mask.entry_type = rqEntryType;
    rq_mask.rx_port = rqMask->RxPort;
    rq_mask.damac = &rqMask->DAMAC;
    rq_mask.samac = &rqMask->SAMAC;
    rq_mask.vsid = rqMask->VSID;
    rq_mask.eth_type = rqMask->EthType;
    rq_mask.ip_proto = rqMask->IPProto;
    rq_mask.dscp = rqMask->DSCP;
    rq_mask.encap_type = rqMask->EncapType;
    if (rqEntryType == X_PBB_DROP)
    {
        m_params.damac = &((struct X_PBBDropParam*)rqExMask)->DAMAC;
        m_params.isid = ((struct X_PBBDropParam*)rqExMask)->ISID;
        m_params.bvid = ((struct X_PBBDropParam*)rqExMask)->BVID;
        rq_mask.entry_param = (void*)&m_params;
    }
    else
    {
        rq_mask.entry_param = rqExMask;
    }

    rs_data.rule = rsRule;
    rs_data.flags = rsFlags;
    rs_data.traffic_class = (struct xel_traffic_class*)rsTrafficClass;
    rs_data.meter = (struct xel_meter*)rsMeter;
    rs_data.reason = rsReason;

    return(xel_ether_set_classify_rule(iXid, iIndex, &rq_data, &rq_mask, &rs_data));
}

/*
 * Add a no match entry.
 */
int XEL_EtherClassifySetNoMatch(uint8_t iXid, uint32_t iIndex)
{
    return(xel_ether_set_classify_no_match(iXid, iIndex));
}

/*
 * Clear an ethernet classification entry.
 */
int XEL_EtherClassifyClear(uint8_t iXid, uint32_t iIndex)
{
    return(xel_ether_clear_classify(iXid, iIndex));
}

/*
 * Initialize the ethernet classification table.
 */
int XEL_EtherClassifyInit(uint8_t iXid)
{
    return(xel_ether_init_classify(iXid));
}
