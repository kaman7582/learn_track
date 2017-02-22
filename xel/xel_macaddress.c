/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_macaddress.c,v $
 * $Revision: 1.73 $
 * 
 * \file  xel_macaddress.c
 * \brief Ethernet bridge management API
 * 
 * Description:
 * API for managing ethernet bridge tables.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_macaddress.h"
#ifdef USE_ECM_PROGRAM
#include "xel_macaddress_learn.h"
#endif
#include "mem_nse.h"
#include "mem_tcam.h"
#include "msgatom.h"
#include "xlog.h"
#include "memory.h"
#include "mac_forward.h"
#ifdef MAC_IN_RAM
#include "mac_forward_dram.h"
#include "pbb_address.h"
#endif
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "fpa_memory_map.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "crc4.h"

uint8_t xel_calc_preamble_crc4(uint16_t input)
{
    struct crc4_s crc_result;

    struct preamble_crc_input_s* ip = (struct preamble_crc_input_s*)&input;

    crc_result.zeroes = 0;
    crc_result.crc_0  = (ip->d11)^(ip->d10)^(ip->d9)^(ip->d8)^(ip->d6)^(ip->d4)^(ip->d3)^(ip->d0);
    crc_result.crc_1  = !((ip->d8)^(ip->d7)^(ip->d6)^(ip->d5)^(ip->d3)^(ip->d1)^(ip->d0));
    crc_result.crc_2  = (ip->d9)^(ip->d8)^(ip->d7)^(ip->d6)^(ip->d4)^(ip->d2)^(ip->d1);
    crc_result.crc_3  = !((ip->d10)^(ip->d9)^(ip->d8)^(ip->d7)^(ip->d5)^(ip->d3)^(ip->d2));

    return *(uint8_t*)&crc_result;
}

int xel_mac_calc_crc(char* data,
                     uint8_t len,
                     uint32_t start,
                     uint8_t reverse,
                     const uint32_t poly)
{
    int i, j;
    uint8_t byte;
    uint16_t word;
    uint8_t buffer[256];
    uint8_t *p_buffer = NULL;
    uint16_t *p_reversed = NULL;
    uint32_t crc = start;

    if (!data)
    {
        return -EINVAL;
    }

    memset((void *)&buffer, 0, len);
    
    /* Reverse the bit order per word (16 bits) */
    if (reverse){
        /* For each 16-bit word */
        for(i = (len/2)-1; i >= 0; i--){
            word = *(((uint16_t*)data) + i);
            /* Go through each bit */
            for(j = 0; j < 16; j++) {
                byte = (word >> j) & 1;
                p_reversed = (uint16_t *)&buffer + i;
                *(p_reversed) |= ((uint16_t)byte << (15 - j));
            }
        }
    }else {
        memcpy((void *)&buffer, (void *)data, len);
    }
    
    p_buffer = (uint8_t *)&buffer;
    for (i = (len-1); i >= 0; i--) {
        byte = *p_buffer; 
        crc ^= (uint32_t)(byte << (32 - 8));
        for(j = 8; j > 0; j--) {
            if (crc & (uint32_t)(1 << 31)){
                crc = (crc << 1) ^ poly;
            }else
                crc <<= 1;
        }
        p_buffer++;
    }
    
    return crc;
}

/*
 * Writes an entry.
 */
static int ethernet_write(uint8_t                       xid,
                          uint32_t                      index,
                          struct mac_forward_index_req* req,
                          struct mac_forward_index_req* mask,
                          struct mac_forward_resp*      resp)
{
    int ret = 0;
    uint32_t address;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    const char * mac_forward_index_req_conv = MAC_FORWARD_INDEX_REQ;
    
    address = MAC_FORWARD_ADDR + index;
    
    if (address >= (MAC_FORWARD_ADDR + MAC_FORWARD_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Response must be converted before calling. Different unions in response. */
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM0_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(struct mac_forward_resp), resp);
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

    CONVERT_ENDIAN(mac_forward_index_req, req);
    CONVERT_ENDIAN(mac_forward_index_req, mask);

    ret = mem_nse_write_search_word_and_mask_80(xid, index, MAC_FORWARD_INDEX_ADDR, MAC_FORWARD_INDEX_SIZE,
                                                (uint8_t*)req, sizeof(struct mac_forward_index_req),
                                                (uint8_t*)mask, sizeof(struct mac_forward_index_req));
    
 out:
    
    return ret;
}

/*
 * Set request data.
 */
static void set_req_data(struct mac_forward_index_req* req,
                         struct mac_forward_index_req* mask,
                         uint32_t                      vsid,
                         struct xel_ethernet_addr*     damac)
{
    /* Table id */
    mask->table_id = NSE_FWD_TABLE_ID_MASK;
    req->table_id = MAC_FWD_NSE_TABLE_ID;
    
    /* VSID */
    mask->vsid = 0xffff;
    req->vsid = vsid & 0xffff;

    /* Flags. */
    mask->vsid_msb = 3;
    req->vsid_msb = (vsid >> 16) & 0x3;

    /* DAMAC */
    if (damac != NULL)
    {
        memset(&(mask->damac), 0xff, sizeof(struct xel_ethernet_addr));
        memcpy(&(req->damac), damac, sizeof(struct xel_ethernet_addr));
    }
}

int xel_mac_set_unicast(uint8_t xid,
                        struct xel_mac_fwd_req_data* rq_data,
                        struct xel_mac_fwd_ucast_resp_data* rs_data)
{
#ifndef USE_ECM_PROGRAM
    struct mac_forward_index_req req;
    struct mac_forward_index_req mask;
    struct mac_forward_resp resp;
    struct mac_addr_ex_resp resp_ex;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));
    
    /* Set request data */
    set_req_data(&req, &mask, rq_data->vsid, rq_data->damac);

    /* Type of entry. */
    resp.address_type.unicast.type = MAC_UNICAST_STATIC;

    /* Flags */
    if ((rs_data->mac_flags & X_MF_NO_RELEARN) != 0)
    {
        resp.address_type.unicast.relearn_not_allowed = 1;
    }
    if ((rs_data->mac_flags & X_MF_TO_HUB) != 0)
    {
        resp.address_type.unicast.to_hub = 1;
    }
    if ((rs_data->mac_flags & X_MF_E_LSP) != 0)
    {
        resp.address_type.unicast.e_lsp = 1;
    }

    /* Dest id, lower 12 bits */
    resp.address_type.unicast.dest_id = rs_data->dest_id;

    /* TCAM address. */
    resp.address_type.unicast.tcam_address = rq_data->index & 0xffff;
    resp.address_type.unicast.address_msb = (rq_data->index >> 16) & 0x1;
    
    /* Load balance options */
    if ((rs_data->mac_flags & X_MF_IS_TRUNK) != 0)
    {
        resp.address_type.unicast.to_trunk = 1;
        resp.address_type.unicast.trunk = rs_data->out_trunk_no;
        switch (rs_data->load_balance)
        {
        case X_LB_SADAMAC:
            resp.address_type.unicast.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.unicast.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.unicast.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.unicast.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.unicast.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.unicast.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.unicast.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    /* If TM is used calculate port from dest_id. */
    resp.address_type.unicast.tx_port = rs_data->dest_id / 400;

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    ret = ethernet_write(xid, rq_data->index, &req, &mask, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Extension table */
    resp_ex.type.lbl.label_ref = rs_data->label_ref & 0xffff;
    resp_ex.type.lbl.label_ref_msb = (rs_data->label_ref >> 16) & 0x1;
    /* Highest 4 bits of dest_id */
    resp_ex.type.lbl.dest_id_hi = rs_data->dest_id >> 12;
    
    const char * mac_addr_ex_resp_conv = MAC_ADDR_EX_RESP_LBL_TYPE;
    CONVERT_ENDIAN(mac_addr_ex_resp, &resp_ex);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(MAC_ADDR_EX_ADDR + rq_data->index);
    xcm.ReqCode = LASRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, MAC_ADDR_EX_ADDR + rq_data->index);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp_ex), &resp_ex);
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
#else
    return(xel_mac_set_unicast_ecm(xid, rq_data, rs_data));
#endif
}

int xel_mac_set_multicast(uint8_t xid,
                          struct xel_mac_fwd_req_data* rq_data,
                          struct xel_mac_fwd_mcast_resp_data* rs_data)
{
    struct mac_forward_index_req    req;
    struct mac_forward_index_req    mask;
    struct mac_forward_resp   resp;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));
    
    /* Set request data */
    set_req_data(&req, &mask, rq_data->vsid, rq_data->damac);

    /* Type of entry. */
    resp.address_type.multicast.type = MAC_MULTICAST_ADDR;

    /* Multicast id */
    resp.address_type.multicast.mcast_id = rs_data->mcast_id;

    /* Load balance options */
    if ((rs_data->mac_flags & X_MF_HAS_TRUNKS) != 0)
    {
        resp.address_type.multicast.has_trunks = 1;
        switch (rs_data->load_balance)
        {
        case X_LB_SADAMAC:
            resp.address_type.multicast.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.multicast.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.multicast.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.multicast.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.multicast.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.multicast.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.multicast.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_MULTICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, rq_data->index, &req, &mask, &resp);
}

int xel_mac_set_flood(uint8_t xid,
                      uint32_t index,
                      uint32_t vsid,
                      struct xel_mac_fwd_flood_resp_data* rs_data)
{
    struct mac_forward_index_req    req;
    struct mac_forward_index_req    mask;
    struct mac_forward_resp   resp;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    /* Set request data */
    set_req_data(&req, &mask, vsid, NULL);

    /* Catch all */
    memset(&(mask.damac), 0, sizeof(struct xel_ethernet_addr));

    /* Type of entry. */
    resp.address_type.flood.type = MAC_FLOOD;

    /* Multicast id */
    resp.address_type.flood.mcast_id = rs_data->mcast_id;

    /* Load balance options */
    if ((rs_data->mac_flags & X_MF_HAS_TRUNKS) != 0)
    {
        resp.address_type.flood.has_trunks = 1;
        switch (rs_data->load_balance)
        {
        case X_LB_SADAMAC:
            resp.address_type.flood.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.flood.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.flood.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.flood.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.flood.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.flood.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.flood.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    /* Flags */
    if ((rs_data->mac_flags & X_MF_DROP_DAMAC_MCAST_ADDRESS) != 0)
        resp.address_type.flood.drop_damac_mcast = 1;
    if ((rs_data->mac_flags & X_MF_DROP_DAMAC_BCAST_ADDRESS) != 0)
        resp.address_type.flood.drop_damac_bcast = 1;
    if ((rs_data->mac_flags & X_MF_USE_FLOOD_COUNTER) != 0)
    {
        resp.address_type.flood.use_flood_counter = 1;
        resp.address_type.flood.flood_counter = rs_data->flood_counter;
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_FLOOD_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, index, &req, &mask, &resp);
}

int xel_mac_set_flood_point_to_point(uint8_t xid,
                                     uint32_t index,
                                     uint32_t vsid,
                                     struct xel_mac_fwd_flood_ptop_resp_data* rs_data)
{
    struct mac_forward_index_req    req;
    struct mac_forward_index_req    mask;
    struct mac_forward_resp   resp;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    /* Set request data */
    set_req_data(&req, &mask, vsid, NULL);

    /* Type of entry. */
    resp.address_type.flood_p2p.type = MAC_FLOOD_POINT_TO_POINT;

    /* Point 1 */

    /* Destination */
    resp.address_type.flood_p2p.point_1.dest_id = rs_data->dest_id_p1;

    /* Trunk */
    if ((rs_data->mac_flags_p1 & X_MF_IS_TRUNK) != 0)
    {
        resp.address_type.flood_p2p.point_1.trunk_no = rs_data->out_trunk_no_p1;
        resp.address_type.flood_p2p.point_1.is_trunk = 1;
        switch (rs_data->load_balance_p1)
        {
        case X_LB_SADAMAC:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.flood_p2p.point_1.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    /* Point 2 */

    /* Destination */
    resp.address_type.flood_p2p.point_2.dest_id = rs_data->dest_id_p2;

    /* Trunk */
    if ((rs_data->mac_flags_p2 & X_MF_IS_TRUNK) != 0)
    {
        resp.address_type.flood_p2p.point_2.trunk_no = rs_data->out_trunk_no_p2;
        resp.address_type.flood_p2p.point_2.is_trunk = 1;
        switch (rs_data->load_balance_p2)
        {
        case X_LB_SADAMAC:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.flood_p2p.point_2.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_FLOOD_P2P_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, index, &req, &mask, &resp);
}

int xel_mac_set_flood_point_to_point_pw(uint8_t xid,
                                        uint32_t index,
                                        uint32_t vsid,
                                        struct xel_mac_fwd_flood_ptop_pw_resp_data* rs_data)
{
    struct mac_forward_index_req     req;
    struct mac_forward_index_req     mask;
    struct mac_forward_resp    resp;
    struct mac_addr_ex_resp      resp_ex;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));
    memset(&resp_ex, 0, sizeof(struct mac_addr_ex_resp));

    /* Set request data */
    set_req_data(&req, &mask, vsid, NULL);
    
    /* Type of entry. */
    resp.address_type.flood_p2p_pw.type = MAC_FLOOD_POINT_TO_POINT_PW;

    /* Point 1 */

    /* TCAM address. */
    resp.address_type.flood_p2p_pw.tcam_address = index & 0xffff;
    resp.address_type.flood_p2p_pw.tcam_address_msb = (index >> 16) & 0x1;
    
    /* Label reference. */
    resp.address_type.flood_p2p_pw.point.label_ref = rs_data->label_ref_p1 & 0xffff;
    resp.address_type.flood_p2p_pw.label_ref_msb = (rs_data->label_ref_p1 >> 16 ) & 0x1;

    /* E-LSP */
    if ((rs_data->mac_flags_p1 & X_MF_E_LSP) != 0)
    {
        resp.address_type.flood_p2p_pw.e_lsp = 1;
    }

    /* To PW */
    if ((rs_data->mac_flags_p1 & X_MF_TO_PW) != 0)
    {
        resp.address_type.flood_p2p_pw.to_pw = 1;
    }
        
    /* Destination */
    resp.address_type.flood_p2p_pw.point.dest_id = rs_data->dest_id_p1;
        
    /* Trunk */
    if ((rs_data->mac_flags_p1 & X_MF_IS_TRUNK) != 0)
    {
        resp.address_type.flood_p2p_pw.trunk_no = rs_data->out_trunk_no_p1;
        resp.address_type.flood_p2p_pw.is_trunk = 1;
        switch (rs_data->load_balance_p1)
        {
        case X_LB_SADAMAC:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp.address_type.flood_p2p_pw.point.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_FLOOD_P2P_PW_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);
        
    /* Write data */
    ret = ethernet_write(xid, index, &req, &mask, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Point 2 */
    
    /* Label reference. */
    resp_ex.type.p_to_ppw_ex.label_ref = rs_data->label_ref_p2 & 0xffff;
    resp_ex.type.p_to_ppw_ex.label_ref_msb = (rs_data->label_ref_p2 >> 16) & 0x1;

    /* E-LSP */
    if ((rs_data->mac_flags_p2 & X_MF_E_LSP) != 0)
    {
        resp_ex.type.p_to_ppw_ex.e_lsp = 1;
    }

    /* To PW */
    if ((rs_data->mac_flags_p2 & X_MF_TO_PW) != 0)
    {
        resp_ex.type.p_to_ppw_ex.to_pw = 1;
    }
        
    /* Destination */
    resp_ex.type.p_to_ppw_ex.dest_id = rs_data->dest_id_p2;
        
    /* Trunk */
    if ((rs_data->mac_flags_p2 & X_MF_IS_TRUNK) != 0)
    {
        resp_ex.type.p_to_ppw_ex.trunk_no = rs_data->out_trunk_no_p2;
        resp_ex.type.p_to_ppw_ex.is_trunk = 1;
        switch (rs_data->load_balance_p2)
        {
        case X_LB_SADAMAC:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_DAMAC;
            break;
        case X_LB_SAIP:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_SAIP;
            break;
        case X_LB_DAIP:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_DAIP;
            break;
        case X_LB_SADAIP:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_SADAIP;
            break;
        case X_LB_VID:
            resp_ex.type.p_to_ppw_ex.link_hash_type = LA_SVID;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
    }

    const char * mac_addr_ex_resp_conv = MAC_ADDR_EX_RESP_P_TO_PPW_EX_TYPE;
    CONVERT_ENDIAN(mac_addr_ex_resp, &resp_ex);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(MAC_ADDR_EX_ADDR + index);
    xcm.ReqCode = LASRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, MAC_ADDR_EX_ADDR + index);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp_ex), &resp_ex);
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

int xel_mac_set_flood_bmac(uint8_t xid,
                           uint32_t index,
                           uint32_t vsid,
                           struct xel_ethernet_addr* bmac)
{
    struct mac_forward_index_req     req;
    struct mac_forward_index_req     mask;
    struct mac_forward_resp          resp;
    struct mac_addr_ex_resp          resp_ex;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if (!bmac)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));
    memset(&resp_ex, 0, sizeof(struct mac_addr_ex_resp));

    /* Set request data */
    set_req_data(&req, &mask, vsid, NULL);

    /* Type of entry. */
    resp.address_type.unicast.type = MAC_UNICAST_PBB;

    /* TCAM index. */
    resp.address_type.unicast.tcam_address = index & 0xffff;
    resp.address_type.unicast.address_msb = (index >> 16) & 0x1;

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write MAC table. */
    ret = ethernet_write(xid, index, &req, &mask, &resp);

    memcpy(&resp_ex.type.pbb.damac, bmac, sizeof(resp_ex.type.pbb.damac));

    const char * mac_addr_ex_resp_conv = MAC_ADDR_EX_RESP_PBB_TYPE;
    CONVERT_ENDIAN(mac_addr_ex_resp, &resp_ex);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(MAC_ADDR_EX_ADDR + index);
    xcm.ReqCode = LASRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, MAC_ADDR_EX_ADDR + index);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp_ex), &resp_ex);
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

int xel_mac_set_reserved_to_cpu(uint8_t xid,
                                struct xel_mac_fwd_req_data* rq_data,
                                struct xel_mac_fwd_to_cpu_resp_data* rs_data)
{
    struct mac_forward_index_req   req;
    struct mac_forward_index_req   mask;
    struct mac_forward_resp  resp;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    if ((rs_data->mac_flags & X_MF_USE_METER) != 0)
    {
        if (!(rs_data->meter))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    /* Set request data */
    set_req_data(&req, &mask, rq_data->vsid, rq_data->damac);

    /* Type of entry. */
    resp.address_type.reserved_address_to_cpu.type = MAC_RESERVED_ADDRESS_TO_CPU;

    /* Reason */
    resp.address_type.reserved_address_to_cpu.reason = rs_data->reason;

    if (rs_data->traffic_class != NULL)
    {
        /* CoS */
        resp.address_type.reserved_address_to_cpu.tm_cos = rs_data->traffic_class->tm_cos;

        /* Drop precedence */
        resp.address_type.reserved_address_to_cpu.flags.tm_drop_prec =
            rs_data->traffic_class->tm_drop_precedence;
    }
    
    if (rs_data->meter != NULL)
    {
        /* Meter address */
        resp.address_type.reserved_address_to_cpu.two_rate_meter_index = rs_data->meter->meter_index;
    
        /* Color */
        switch(rs_data->meter->pre_color)
        {
        case X_COLOR_BLIND:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_COLOR_BLIND;
            break;
        case X_PRE_COLOR_GREEN:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_GREEN;
            break;
        case X_PRE_COLOR_YELLOW:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_YELLOW;
            break;
        case X_PRE_COLOR_RED:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_RED;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }

        /* Meter type */
        switch (rs_data->meter->meter_type)
        {
        case X_METER_2698:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_2698;
            break;
        case X_METER_COUPLED:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_COUPLED;
            break;
        case X_METER_DECOUPLED:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_DECOUPLED;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }

            
        /* Drop on red */
        if ((rs_data->meter->meter_flags & X_DROP_RED) != 0)
        {
            resp.address_type.reserved_address_to_cpu.flags.drop_on_red = 1;
        }
            
        /* Drop on yellow */
        if ((rs_data->meter->meter_flags & X_DROP_YELLOW) != 0)
        {
            resp.address_type.reserved_address_to_cpu.flags.drop_on_yellow = 1;
        }
    }
        
    /* Use meter */
    if ((rs_data->mac_flags & X_MF_USE_METER) != 0)
    {
        resp.address_type.reserved_address_to_cpu.flags.use_meter = 1;
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_RESERVED_ADDRESS_TO_CPU_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, rq_data->index, &req, &mask, &resp);
}

int xel_mac_set_reserved_to_cpu_mask_damac(uint8_t xid,
                                           uint32_t index,
                                           struct xel_ethernet_addr* damac,
                                           struct xel_mac_fwd_to_cpu_resp_data* rs_data)
{
    struct mac_forward_index_req   req;
    struct mac_forward_index_req   mask;
    struct mac_forward_resp  resp;

    if ((!damac) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if ((rs_data->mac_flags & X_MF_USE_METER) != 0)
    {
        if (!(rs_data->meter))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    /* Set request data */
    set_req_data(&req, &mask, 0, damac);

    /* Clear the mask in VSID field (i.e. don't care) */
    mask.vsid = 0;
    mask.vsid_msb = 0;

    /* Type of entry. */
    resp.address_type.reserved_address_to_cpu.type = MAC_RESERVED_ADDRESS_TO_CPU;

    /* Reason */
    resp.address_type.reserved_address_to_cpu.reason = rs_data->reason;

    if (rs_data->traffic_class != NULL)
    {
        /* CoS */
        resp.address_type.reserved_address_to_cpu.tm_cos = rs_data->traffic_class->tm_cos;

        /* Drop precedence */
        resp.address_type.reserved_address_to_cpu.flags.tm_drop_prec =
            rs_data->traffic_class->tm_drop_precedence;
    }

    if (rs_data->meter != NULL)
    {
        /* Meter address */
        resp.address_type.reserved_address_to_cpu.two_rate_meter_index = rs_data->meter->meter_index;
    
        /* Color */
        switch(rs_data->meter->pre_color)
        {
        case X_COLOR_BLIND:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_COLOR_BLIND;
            break;
        case X_PRE_COLOR_GREEN:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_GREEN;
            break;
        case X_PRE_COLOR_YELLOW:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_YELLOW;
            break;
        case X_PRE_COLOR_RED:
            resp.address_type.reserved_address_to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_RED;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }

        /* Meter type */
        switch (rs_data->meter->meter_type)
        {
        case X_METER_2698:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_2698;
            break;
        case X_METER_COUPLED:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_COUPLED;
            break;
        case X_METER_DECOUPLED:
            resp.address_type.reserved_address_to_cpu.flags.meter_type = METER_TYPE_DECOUPLED;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }

        /* Drop on red */
        if ((rs_data->meter->meter_flags & X_DROP_RED) != 0)
        {
            resp.address_type.reserved_address_to_cpu.flags.drop_on_red = 1;
        }

        /* Drop on yellow */
        if ((rs_data->meter->meter_flags & X_DROP_YELLOW) != 0)
        {
            resp.address_type.reserved_address_to_cpu.flags.drop_on_yellow = 1;
        }
    }
    
    /* Use meter */
    if ((rs_data->mac_flags & X_MF_USE_METER) != 0)
    {
        resp.address_type.reserved_address_to_cpu.flags.use_meter = 1;
    }

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_RESERVED_ADDRESS_TO_CPU_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return(ethernet_write(xid, index, &req, &mask, &resp));
}

int xel_mac_set_reserved_to_discard(uint8_t xid,
                                    struct xel_mac_fwd_req_data* rq_data)
{
    struct mac_forward_index_req   req;
    struct mac_forward_index_req   mask;
    struct mac_forward_resp  resp;

    if ((!rq_data) || (!(rq_data->damac)))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    /* Set request data */
    set_req_data(&req, &mask, rq_data->vsid, rq_data->damac);

    /* Type of entry. */
    resp.address_type.unicast.type = MAC_DISCARD;

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, rq_data->index, &req, &mask, &resp);
}

int xel_mac_set_catch_all(uint8_t xid,
                          uint32_t index)
{
    struct mac_forward_index_req   req;
    struct mac_forward_index_req   mask;
    struct mac_forward_resp  resp;
    int ret = 0;

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    mask.is_invalid = 1;

    /* Table id */
    mask.table_id = NSE_FWD_TABLE_ID_MASK;
    req.table_id = MAC_FWD_NSE_TABLE_ID;

    /* Type of entry. */
    resp.address_type.unicast.type = MAC_DISCARD;

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    ret = ethernet_write(xid, index, &req, &mask, &resp);
    
    return ret;
}

int xel_mac_clear_unicast(uint8_t xid,
                          struct xel_mac_fwd_req_data* rq_data)
{
#ifndef USE_ECM_PROGRAM
    return(xel_mac_clear_entry(xid, rq_data->index));
#else
    return(xel_mac_clear_unicast_ecm(xid, rq_data));
#endif
}

int xel_mac_clear_entry(uint8_t xid,
                        uint32_t index)
{
    int ret = 0;

    ret = mem_nse_clear_80(xid, index, MAC_FORWARD_INDEX_ADDR, MAC_FORWARD_INDEX_SIZE);
    
    return ret;
}

int xel_mac_set_free(uint8_t xid,
                     uint32_t index)
{
    struct mac_forward_index_req   req;
    struct mac_forward_index_req   mask;
    struct mac_forward_resp  resp;

    memset(&req, 0, sizeof(struct mac_forward_index_req));
    memset(&mask, 0, sizeof(struct mac_forward_index_req));
    memset(&resp, 0, sizeof(struct mac_forward_resp));

    mask.is_invalid = 1;
    req.is_invalid = 1;

    /* Table id */
    mask.table_id = NSE_FWD_TABLE_ID_MASK;
    req.table_id = MAC_FWD_NSE_TABLE_ID;

    /* Type of entry. */
    resp.address_type.unicast.type = MAC_INVALID;

    /* TCAM address, used by ageing and learning. */
    resp.address_type.unicast.tcam_address = index & 0xffff;
    resp.address_type.unicast.address_msb = (index >> 16) & 0x1;

    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &resp);

    /* Write data */
    return ethernet_write(xid, index, &req, &mask, &resp);
}

int xel_mac_init_bmac(uint8_t xid)
{
    int ret = 0;
#ifdef MAC_IN_RAM
    uint32_t index;
    uint32_t tcam_addr;
    uint32_t sram_addr;
    struct pbb_address_req req;
    struct pbb_address_req mask;
    struct pbb_address_resp resp;

    /* Clear data structures */
    memset(&req, 0, sizeof(struct pbb_address_req));
    memset(&mask, 0, sizeof(struct pbb_address_req));
    memset(&resp, 0, sizeof(struct pbb_address_resp));

    /* Mask is set for MAC address */
    memset(&mask.damac, 0xff, sizeof(mask.damac));

    const char * pbb_address_req_conv  = PBB_ADDRESS_REQ;
    const char * pbb_address_resp_conv = PBB_ADDRESS_RESP;

    CONVERT_ENDIAN(pbb_address_resp, &resp);
    CONVERT_ENDIAN(pbb_address_req, &req);
    CONVERT_ENDIAN(pbb_address_req, &mask);

    /* Write data. Response is set to index of entry. */
    for (index = 0; index < PBB_ADDRESS_REQ_SIZE; index += 2)
    {
        resp.index = index;
        tcam_addr = index + PBB_ADDRESS_REQ_ADDR;
        sram_addr = (index * 2) + PBB_ADDRESS_RES_ADDR;
        
        if ((tcam_addr >= (PBB_ADDRESS_REQ_ADDR + PBB_ADDRESS_REQ_SIZE)) ||
            (sram_addr >= (PBB_ADDRESS_RES_ADDR + PBB_ADDRESS_RES_SIZE)))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }

        ret = mem_tcam_write_entry_80_128(xid, TCAM_0, tcam_addr,
                                          (uint8_t*)&req, sizeof(struct pbb_address_req),
                                          (uint8_t*)&mask, sizeof(struct pbb_address_req),
                                          sram_addr,
                                          (uint8_t*)&resp, sizeof(struct pbb_address_resp));
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            return ret;
        }
    }

    /* Write catch all. Response is index of last entry. */
    memset(&mask, 0, sizeof(struct pbb_address_req));

    tcam_addr = PBB_ADDRESS_REQ_ADDR + PBB_ADDRESS_REQ_SIZE - 2;
    sram_addr = PBB_ADDRESS_RES_ADDR + PBB_ADDRESS_RES_SIZE - 4;

    CONVERT_ENDIAN(pbb_address_req, &mask);
    
    ret = mem_tcam_write_entry_80_128(xid, TCAM_0, tcam_addr,
                                      (uint8_t*)&req, sizeof(struct pbb_address_req),
                                      (uint8_t*)&mask, sizeof(struct pbb_address_req),
                                      sram_addr,
                                      (uint8_t*)&resp, sizeof(struct pbb_address_resp));
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
    }        
#endif
    return ret;
}

int xel_mac_init(uint8_t xid,
                 uint32_t dynamic_size)
{
#ifndef USE_ECM_PROGRAM
    int ret = 0;
    int i   = 0;

    /* For simulator only initialise parts of the table (to reduce simulation time)*/
    ret = xel_mac_init_bmac(xid);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Add Catch all entry last in table */
    ret = xel_mac_set_catch_all(xid, MAC_FORWARD_INDEX_SIZE - 1);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    return ret;
#else
    return(xel_mac_init_ecm(xid, dynamic_size));
#endif
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Calculate the CRC-32 Hash Key for DRAM based MAC forwarding table
 */
uint32_t
XEL_MACCalcCRC(char *data, uint8_t len, uint32_t start, uint8_t reverse, const uint32_t poly)
{
    return(xel_mac_calc_crc(data, len, start, reverse, poly));
}

/*
 * Add a free entry, used by learning to get free entrys.
 */
int XEL_MACSetFree(uint8_t iXid, uint32_t iIndex)
{
    return(xel_mac_set_free(iXid, iIndex));
}

/*
 * Add ethernet unicast forwarding entry.
 */
int XEL_MACSetUnicast(uint8_t                iXid, 
                      uint32_t               rqVSID,
                      struct X_EthernetAddr* rqDAMAC,
                      uint16_t               rsMACFlags,
                      uint16_t               rsDestId,
                      uint8_t                rsOutTrunkNo,
                      enum MF_LoadBalance    rsLoadBalance,
                      uint32_t               rsLabelRef,
                      struct X_EthernetAddr* rsBMAC)
{
    struct xel_mac_fwd_req_data rq_data;
    struct xel_mac_fwd_ucast_resp_data rs_data;

    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.index = 0;

    rs_data.mac_flags = rsMACFlags;
    rs_data.dest_id = rsDestId;
    rs_data.out_trunk_no = rsOutTrunkNo;
    rs_data.load_balance = rsLoadBalance;
    rs_data.label_ref = rsLabelRef;
    rs_data.bmac = rsBMAC;

    return(xel_mac_set_unicast(iXid, &rq_data, &rs_data));
}

/*
 * Add ethernet multicast forwarding entry.
 */
int XEL_MACSetMulticast(uint8_t                iXid,
                        uint32_t               iIndex,
                        uint32_t               rqVSID,
                        struct X_EthernetAddr* rqDAMAC,
                        uint16_t               rsMcastId,
                        enum MF_LoadBalance    rsLoadBalance,
                        uint16_t               rsMACFlags)
{
    struct xel_mac_fwd_req_data rq_data;
    struct xel_mac_fwd_mcast_resp_data rs_data;

    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.index = iIndex;

    rs_data.mcast_id = rsMcastId;
    rs_data.load_balance = rsLoadBalance;
    rs_data.mac_flags = rsMACFlags;

    return(xel_mac_set_multicast(iXid, &rq_data, &rs_data));
}

/*
 * Add ethernet flood entry.
 */
int XEL_MACSetFlood(uint8_t              iXid,
                    uint32_t             iIndex,
                    uint32_t             rqVSID,
                    uint16_t             rsMcastId,
                    enum MF_LoadBalance  rsLoadBalance,
                    uint16_t             rsMACFlags,
                    uint16_t             rsFloodCounter)
{
    struct xel_mac_fwd_flood_resp_data rs_data;

    rs_data.mcast_id = rsMcastId;
    rs_data.load_balance = rsLoadBalance;
    rs_data.mac_flags = rsMACFlags;
    rs_data.flood_counter = rsFloodCounter;

    return(xel_mac_set_flood(iXid, iIndex, rqVSID, &rs_data));
}

/*
 * Add ethernet flood point to point forwarding entry.
 */
int XEL_MACSetFloodPointToPoint(uint8_t              iXid,
                                uint32_t             iIndex,
                                uint32_t             rqVSID,
                                uint16_t             rsMACFlags1,
                                uint16_t             rsDestId1,
                                uint8_t              rsOutTrunkNo1,
                                enum MF_LoadBalance  rsLoadBalance1,
                                uint16_t             rsMACFlags2,
                                uint16_t             rsDestId2,
                                uint8_t              rsOutTrunkNo2,
                                enum MF_LoadBalance  rsLoadBalance2)
{
    struct xel_mac_fwd_flood_ptop_resp_data rs_data;

    rs_data.mac_flags_p1 = rsMACFlags1;
    rs_data.dest_id_p1 = rsDestId1;
    rs_data.out_trunk_no_p1 = rsOutTrunkNo1;
    rs_data.load_balance_p1 = rsLoadBalance1;
    rs_data.mac_flags_p2 = rsMACFlags2;
    rs_data.dest_id_p2 = rsDestId2;
    rs_data.out_trunk_no_p2 = rsOutTrunkNo2;
    rs_data.load_balance_p2 = rsLoadBalance2;

    return(xel_mac_set_flood_point_to_point(iXid, iIndex, rqVSID, &rs_data));
}

/*
 * Add ethernet flood point to point forwarding entry.
 */
int XEL_MACSetFloodPointToPointPW(uint8_t              iXid,
                                  uint32_t             iIndex,
                                  uint32_t             rqVSID,
                                  uint16_t             rsMACFlags1,
                                  uint16_t             rsDestId1,
                                  uint8_t              rsOutTrunkNo1,
                                  enum MF_LoadBalance  rsLoadBalance1,
                                  uint32_t             rsLabelRef1,
                                  uint16_t             rsMACFlags2,
                                  uint16_t             rsDestId2,
                                  uint8_t              rsOutTrunkNo2,
                                  enum MF_LoadBalance  rsLoadBalance2,
                                  uint32_t             rsLabelRef2)
{
    struct xel_mac_fwd_flood_ptop_pw_resp_data rs_data;

    rs_data.mac_flags_p1 = rsMACFlags1;
    rs_data.dest_id_p1 = rsDestId1;
    rs_data.out_trunk_no_p1 = rsOutTrunkNo1;
    rs_data.load_balance_p1 = rsLoadBalance1;
    rs_data.label_ref_p1 = rsLabelRef1;
    rs_data.mac_flags_p2 = rsMACFlags2;
    rs_data.dest_id_p2 = rsDestId2;
    rs_data.out_trunk_no_p2 = rsOutTrunkNo2;
    rs_data.load_balance_p2 = rsLoadBalance2;
    rs_data.label_ref_p2 = rsLabelRef2;

    return(xel_mac_set_flood_point_to_point_pw(iXid, iIndex, rqVSID, &rs_data));
}

/*
 * Add BMAC to BMAC table.
 *
 * NOTE: Preliminary, may change.
 */
int
XEL_MACSetFloodBMAC(uint8_t iXid, uint32_t iIndex, uint32_t rqVSID,
                    struct X_EthernetAddr* rsBMAC)
{
    return(xel_mac_set_flood_bmac(iXid, iIndex, rqVSID, rsBMAC));
}

/*
 * Add ethernet reserved to CPU forwarding entry.
 */
int XEL_MACSetReservedToCPU(uint8_t                iXid, 
                            uint32_t               iIndex,
                            uint32_t               rqVSID,
                            struct X_EthernetAddr* rqDAMAC,
                            uint8_t                rsReason,
                            uint16_t               rsMACFlags,
                            struct X_TrafficClass* rsTrafficClass,
                            struct X_Meter*        rsMeter)
{
    struct xel_mac_fwd_req_data rq_data;
    struct xel_mac_fwd_to_cpu_resp_data rs_data;

    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.index = iIndex;

    rs_data.reason = rsReason;
    rs_data.mac_flags = rsMACFlags;
    rs_data.traffic_class = (struct xel_traffic_class*)rsTrafficClass;
    rs_data.meter = (struct xel_meter*)rsMeter;

    return(xel_mac_set_reserved_to_cpu(iXid, &rq_data, &rs_data));
}

/*
 * Add ethernet reserved to CPU forwarding entry.
 * SVID and VSID is don't care.
 */
int XEL_MACSetReservedToCPUMaskDAMAC(uint8_t                iXid, 
                                     uint32_t               iIndex,
                                     struct X_EthernetAddr* rqDAMAC,
                                     uint8_t                rsReason,
                                     uint16_t               rsMACFlags,
                                     struct X_TrafficClass* rsTrafficClass,
                                     struct X_Meter*        rsMeter)
{
    struct xel_mac_fwd_to_cpu_resp_data rs_data;

    rs_data.reason = rsReason;
    rs_data.mac_flags = rsMACFlags;
    rs_data.traffic_class = (struct xel_traffic_class*)rsTrafficClass;
    rs_data.meter = (struct xel_meter*)rsMeter;

    return(xel_mac_set_reserved_to_cpu_mask_damac(iXid, iIndex, rqDAMAC, &rs_data));
}

/*
 * Add ethernet reserved to discard forwarding entry.
 */
int XEL_MACSetReservedToDiscard(uint8_t                iXid, 
                                uint32_t               iIndex,
                                uint32_t               rqVSID,
                                struct X_EthernetAddr* rqDAMAC)
{
    struct xel_mac_fwd_req_data rq_data;

    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.index = iIndex;

    return(xel_mac_set_reserved_to_discard(iXid, &rq_data));
}

/*
 * Add a catch all entry,
 */
int XEL_MACSetCatchAll(uint8_t iXid, uint32_t iIndex)
{
    return(xel_mac_set_catch_all(iXid, iIndex));
}

/*
 * Remove an unicast entry from the table.
 */
int XEL_MACClearUnicastEntry(uint8_t                iXid,
                             uint32_t               rqVSID,
                             struct X_EthernetAddr* rqDAMAC)
{
    struct xel_mac_fwd_req_data rq_data;

    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.index = 0;

    return(xel_mac_clear_unicast(iXid, &rq_data));
}

/*
 * Remove an entry from the table.
 */
int XEL_MACClear(uint8_t iXid, uint32_t iIndex)
{
    return(xel_mac_clear_entry(iXid, iIndex));
}

/*
 * Initialize the table.
 */
int XEL_MACInitBMAC(uint8_t iXid)
{
    return(xel_mac_init_bmac(iXid));
}

/*
 * Initialize the table.
 */
int XEL_MACInit(uint8_t iXid, uint32_t iDynamicSize)
{
    return(xel_mac_init(iXid, iDynamicSize));
}
