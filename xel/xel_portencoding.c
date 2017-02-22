/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_portencoding.c,v $
 * $Revision: 1.55 $
 * 
 * \file  xel_portencoding.c
 * \brief Port encoding management API
 * 
 * Description:
 * API for managing port encoding table.
 *--------------------------------------------------------------------------*/

#include <assert.h>
#include <netinet/in.h>
#include <errno.h>

#include "xel_portencoding.h"
#include "xel_portdecoding.h"
#include "drv_driver.h"
#include "mem_nse.h"
#ifndef LOOP_MODE
#include "port_encoding.h"
#else
#include "port_encoding_loop.h"
#endif
#include "memory.h"
#include "fpa_memory_map.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

static uint16_t sub_port(uint16_t port_id, uint16_t port_flags)
{
    uint16_t sub_port = 0;
    
    if ((port_flags & X_PF_TRI) != 0)
    {
        sub_port = port_id;
    }
    else if ((port_flags & X_PF_XAUI) != 0)
    {
        sub_port = port_id * 4;
    }
    else
    {
        assert(0);
    }
    if (sub_port >= 48)
    {
        return -EINVAL;
    }
        
    return sub_port;
}

static int write_ram(uint8_t xid, uint32_t address, struct port_encoding_resp* resp)
{
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    int ret;

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE4;
    xcm.Addr = htonl(address);
    xcm.ReqCode = SRAM4_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(struct port_encoding_resp), resp);
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

/*
 * Writes a port enc entry.
 */    
static int write_encoding(uint8_t  xid,
                          uint16_t index,
                          uint16_t phy_port,
                          uint16_t port_flags,
                          struct port_encoding_resp* resp)
{
    struct port_encoding_index_req req;
    struct port_encoding_index_req mask;
    uint32_t tcam_index;
    uint32_t sram_addr;
    int ret;

    memset(&req, 0, sizeof(struct port_encoding_index_req));
    memset(&mask, 0, sizeof(struct port_encoding_index_req));

    req.port = sub_port(phy_port, port_flags);
    req.table_id = PORT_ENC_NSE_TABLE_ID;

    /* Set mask. */
    mask.port = 0xff;
    mask.table_id = NSE_TABLE_ID_MASK;

    tcam_index = PORT_ENCODING_INDEX_SIZE - 48 - 1 + index;
    sram_addr = PORT_ENCODING_ADDR + PORT_ENCODING_SIZE - 48 - 1 + index;
    if (sram_addr >= (PORT_ENCODING_ADDR + PORT_ENCODING_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    ret = write_ram(xid, sram_addr, resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    const char * port_encoding_index_req_conv = PORT_ENCODING_INDEX_PORT_ENCODING_UNICAST_TYPE_REQ;
    CONVERT_ENDIAN(port_encoding_index_req, &req);
    CONVERT_ENDIAN(port_encoding_index_req, &mask);

    ret = mem_nse_write_search_word_and_mask_80(
        xid, 
        tcam_index,
        PORT_ENCODING_INDEX_ADDR,
        PORT_ENCODING_INDEX_SIZE,
        (uint8_t*)&req, 
        sizeof(struct port_encoding_index_req),
        (uint8_t*)&mask, 
        sizeof(struct port_encoding_index_req));

    return ret;
}

/*
 * Writes a L3 port enc entry.
 */
static int write_encoding_layer3(
    uint8_t                    xid,
    uint16_t                   index,
    uint16_t                   phy_port,
    uint16_t                   port_flags,
    struct port_encoding_resp* resp,
    struct xel_log_multi*      log_multi)
{
    struct port_encoding_index_req req;
    struct port_encoding_index_req mask;
    uint32_t tcam_index;
    uint32_t sram_addr;
    int ret;

    memset(&req, 0, sizeof(struct port_encoding_index_req));
    memset(&mask, 0, sizeof(struct port_encoding_index_req));

    /* Set packet interface for Tri Speed destination ports */
    req.port     = sub_port(phy_port, port_flags);
    req.table_id = PORT_ENC_NSE_TABLE_ID;

    /* Set mask. */
    mask.port     = 0xff;
    mask.table_id = NSE_TABLE_ID_MASK;

    if ((port_flags & X_PF_L3_MULTICAST) != 0) 
    {
        if (!log_multi)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }

        /* Multicast entries are placed before unicast entries */
        tcam_index = index + 2;
        sram_addr = PORT_ENCODING_ADDR + index + 2;
#ifndef LOOP_MODE
        req.u.multicast.tm_to_np_multicast.tm_to_np_type  = TM_NP_MULTICAST;
        req.u.multicast.tm_to_np_multicast.mcast_cnt      = log_multi->mcast_copy_cnt;
        req.u.multicast.tm_to_np_multicast.multicast_id   = log_multi->mcast_id;

        mask.u.multicast.tm_to_np_multicast.tm_to_np_type = 0x3;
        mask.u.multicast.tm_to_np_multicast.mcast_cnt     = TM_NP_MULTICAST_COPY_MASK;
        mask.u.multicast.tm_to_np_multicast.multicast_id  = TM_NP_MULTICAST_ID_MASK;
#endif
    } 
    else 
    {
        if (log_multi)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }

        tcam_index = PORT_ENCODING_INDEX_SIZE - 48 - 1 + index;
        sram_addr = PORT_ENCODING_ADDR + PORT_ENCODING_SIZE - 48 - 1 + index;
#ifndef LOOP_MODE
        req.u.unicast.tm_to_np_unicast.tm_to_np_type     = TM_NP_UNICAST;
        mask.u.unicast.tm_to_np_unicast.tm_to_np_type    = 0x3;
#endif
        req.u.unicast.type  = 0;
        mask.u.unicast.type = NP_L3_MASK; 
    }

    if (sram_addr >= (PORT_ENCODING_ADDR + PORT_ENCODING_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    if (resp->jump == L3_MCAST_ENCODER)
    {
        const char * port_encoding_resp_conv = PORT_ENCODING_RESP_L3_MCAST_TYPE;
        CONVERT_ENDIAN(port_encoding_resp, resp);

        const char * port_encoding_index_req_conv = PORT_ENCODING_INDEX_PORT_ENCODING_MULTICAST_TYPE_REQ;
        CONVERT_ENDIAN(port_encoding_index_req, &req);
        CONVERT_ENDIAN(port_encoding_index_req, &mask);
    }
    else
    {
        const char * port_encoding_resp_conv = PORT_ENCODING_RESP_L3_UCAST_TYPE;
        CONVERT_ENDIAN(port_encoding_resp, resp);

        const char * port_encoding_index_req_conv = PORT_ENCODING_INDEX_PORT_ENCODING_UNICAST_TYPE_REQ;
        CONVERT_ENDIAN(port_encoding_index_req, &req);
        CONVERT_ENDIAN(port_encoding_index_req, &mask);
    }

    ret = write_ram(xid, sram_addr, resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    ret = mem_nse_write_search_word_and_mask_80(
        xid, 
        tcam_index,
        PORT_ENCODING_INDEX_ADDR,
        PORT_ENCODING_INDEX_SIZE,
        (uint8_t*)&req, 
        sizeof(struct port_encoding_index_req),
        (uint8_t*)&mask, 
        sizeof(struct port_encoding_index_req));

    return ret;
}

/*
 * Writes a L3 over C-VLAN enc entry.
 */
static int write_encoding_layer3_cvc(uint8_t  xid,
                                     uint16_t phy_port,
                                     uint16_t port_flags,
                                     struct port_encoding_resp* resp)
{
    struct port_encoding_index_req req;
    struct port_encoding_index_req mask;
    uint32_t tcam_index;
    uint32_t sram_addr;
    int ret;

    memset(&req, 0, sizeof(struct port_encoding_index_req));
    memset(&mask, 0, sizeof(struct port_encoding_index_req));

    /* Set packet interface for Tri Speed destination ports */
    req.port = sub_port(phy_port, port_flags);
    req.table_id = PORT_ENC_NSE_TABLE_ID;
    /* Set mask. Include table id. */
    mask.port = 0xff;
    mask.table_id = NSE_TABLE_ID_MASK;

    tcam_index = PORT_ENCODING_INDEX_SIZE - 96 - 1 + phy_port;
    sram_addr = PORT_ENCODING_ADDR + PORT_ENCODING_SIZE - 96 - 1 + phy_port;
#ifndef LOOP_MODE
    req.u.unicast.tm_to_np_unicast.tm_to_np_type  = TM_NP_UNICAST;
    mask.u.unicast.tm_to_np_unicast.tm_to_np_type = 0x3;
#endif
    req.u.unicast.type             = 0;       /* Only for L3 packets */
    mask.u.unicast.type            = NP_L3_MASK;

    if (sram_addr >= (PORT_ENCODING_ADDR + PORT_ENCODING_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_L3_UCAST_TYPE;    
    CONVERT_ENDIAN(port_encoding_resp, resp);

    ret = write_ram(xid, sram_addr, resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    const char * port_encoding_index_req_conv = PORT_ENCODING_INDEX_PORT_ENCODING_UNICAST_TYPE_REQ;
    CONVERT_ENDIAN(port_encoding_index_req, &req);
    CONVERT_ENDIAN(port_encoding_index_req, &mask);

    ret = mem_nse_write_search_word_and_mask_80(
        xid, 
        tcam_index,
        PORT_ENCODING_INDEX_ADDR,
        PORT_ENCODING_INDEX_SIZE,
        (uint8_t*)&req, 
        sizeof(struct port_encoding_index_req),
        (uint8_t*)&mask, 
        sizeof(struct port_encoding_index_req));

    return ret;
}

static int clear_encoding_layer3_cvc(uint8_t  xid,
                                     uint16_t phy_port)
{
    uint32_t index;
    int ret;

    index = PORT_ENCODING_INDEX_SIZE - 96 - 1 + phy_port;

    ret = mem_nse_clear_80(xid, index, PORT_ENCODING_INDEX_ADDR, PORT_ENCODING_INDEX_SIZE);

    return ret;
}

int xel_port_set_bridge_egress(uint8_t xid,
                               uint16_t port_id,
                               struct xel_port_bridge_egress_resp_data* rs_data)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&resp, 0, sizeof(struct port_encoding_resp));

    index = sub_port(port_id, rs_data->port_flags);

    resp.port.bridge.l2_tx_port.port_number = index;
    if (rs_data->port_flags & X_PF_IS_TRUNK) {
        resp.port.bridge.l2_tx_port.is_trunk = 1;
        resp.port.bridge.l2_tx_port.trunk_or_line_card = rs_data->trunk_id;
    }
    else { /* No trunk, set Line Card Id*/
        resp.port.bridge.l2_tx_port.trunk_or_line_card = rs_data->line_card_id;
    }

    /* Common fields for SVC and CVC */
    if (rs_data->port_flags & X_PF_DIST_TRUNK) {
        resp.port.bridge.distributed_trunk = 1;
    }

    /* SVC/CVC/IVC specific */
    switch(rs_data->component)
    {
    case X_S_COMP:
        /* SVC */
        resp.port.bridge.stag_etype = ((struct xel_svc_param*)rs_data->port_params)->stag_etype;
        resp.port.bridge.pcp_ref = ((struct xel_svc_param*)rs_data->port_params)->pcp_encoding_ref;
        if (rs_data->port_flags & X_PF_USE_DE)
        {
            resp.port.bridge.use_de_bit = 1;
        }
        resp.jump = SVLAN_ENCODER;
        break;
    case X_C_COMP:
        /* CVC */
        resp.jump = CVLAN_ENCODER;
        break;
    case X_I_COMP:
        /* IVC */
        resp.port.bridge.stag_etype = ((struct xel_ivc_param*)rs_data->port_params)->stag_etype;
        resp.port.bridge.pcp_ref = ((struct xel_ivc_param*)rs_data->port_params)->pcp_encoding_ref;
        resp.port.bridge.start_sid = ((struct xel_ivc_param*)rs_data->port_params)->start_sid & 0xff;
        resp.port.bridge.start_sid_field = (((struct xel_ivc_param*)rs_data->port_params)->start_sid >> 8);
        resp.jump = IVLAN_ENCODER;
        break;
    }

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_PORT_ENCODING_BRIDGE_TYPE;    
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    /* Create request data and mask and install port encoding entry */
    ret = write_encoding(xid, index, port_id, rs_data->port_flags, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    return ret;
}

int xel_port_set_layer3_egress(uint8_t xid,
                               uint16_t port_id,
                               struct xel_port_layer3_egress_resp_data* rs_data)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if ((rs_data->port_flags & X_PF_L3_MULTICAST) != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    index = sub_port(port_id, rs_data->port_flags);

    memset(&resp, 0, sizeof(resp));

    /* Encoding. */
    if (rs_data->port_flags & X_PF_IS_TRUNK)
    {
        resp.port.l3_ucast.l2_tx_port.trunk_or_line_card = rs_data->trunk_id;
        resp.port.l3_ucast.l2_tx_port.is_trunk = 1;
    }
    else
    {
        resp.port.l3_ucast.l2_tx_port.port_number = index;
        resp.port.l3_ucast.l2_tx_port.trunk_or_line_card = rs_data->line_card_id;
    }
    resp.port.l3_ucast.l3_port = rs_data->l3_port_id;

    resp.jump = L3_UCAST_ENCODER;
    /* Create request data and mask and install port encoding entry */
    ret = write_encoding_layer3(xid, index, port_id, rs_data->port_flags, &resp, 0);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Clear L3 over L2 rule, if any */
    ret = clear_encoding_layer3_cvc(xid, index);

    return ret;
}

int xel_port_set_layer3_cvc_egress(uint8_t xid,
                                   uint16_t port_id,
                                   struct xel_port_layer3_egress_resp_data* rs_data)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if ((rs_data->port_flags & X_PF_L3_MULTICAST) != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    index = sub_port(port_id, rs_data->port_flags);

    memset(&resp, 0, sizeof(resp));

    /* Encoding. */
    if (rs_data->port_flags & X_PF_IS_TRUNK)
    {
        resp.port.l3_ucast.l2_tx_port.trunk_or_line_card = rs_data->trunk_id;
        resp.port.l3_ucast.l2_tx_port.is_trunk = 1;
    }
    else
    {
        resp.port.l3_ucast.l2_tx_port.port_number = index;
        resp.port.l3_ucast.l2_tx_port.trunk_or_line_card = rs_data->line_card_id;
    }
    resp.port.l3_ucast.l3_port = rs_data->l3_port_id;
    resp.jump = L3_UCAST_ENCODER;

    /* Create request data and mask and install port encoding entry */
    ret = write_encoding_layer3_cvc(xid, index, rs_data->port_flags, &resp);
    return ret;
}

int xel_port_set_drop_egress(uint8_t xid,
                             uint16_t port_id,
                             uint16_t port_flags)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    memset(&resp, 0, sizeof(struct port_encoding_resp));

    index = sub_port(port_id, port_flags);

    resp.port.drop_port.tx_port = (uint8_t)index;
    resp.jump = PORT_ENCODER_DROP;

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_DROP_PORT_TYPE;
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    ret = write_encoding(xid, index, port_id, port_flags, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Clear L3 over L2 rule, if any */
    ret = clear_encoding_layer3_cvc(xid, index);

    return ret;
}

int xel_port_set_drop_layer3_cvc_egress(uint8_t xid,
                                        uint16_t port_id,
                                        uint16_t port_flags)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    if ((port_flags & X_PF_L3_MULTICAST) != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    index = sub_port(port_id, port_flags);

    memset(&resp, 0, sizeof(resp));

    resp.port.drop_port.tx_port = (uint8_t)index;
    resp.jump = PORT_ENCODER_DROP;

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_DROP_PORT_TYPE;
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    /* Create request data and mask and install port encoding entry */
    ret = write_encoding_layer3_cvc(xid, index, port_flags, &resp);
    return ret;
}


int xel_port_set_log_multi_egress(uint8_t xid,
                                  uint16_t port_id,
                                  uint16_t index,
                                  struct xel_port_log_multi_egress_resp_data* rs_data)
{
    struct port_encoding_resp resp;
    uint16_t idx;
    int ret;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (!(((rs_data->port_flags & X_PF_L3_MULTICAST) != 0) && rs_data->log_multi))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&resp, 0, sizeof(resp));

    idx = sub_port(port_id, rs_data->port_flags);

    if (rs_data->port_flags & X_PF_IS_TRUNK)
    {
        resp.port.l3_mcast.l2_tx_port.trunk_or_line_card = rs_data->trunk_id;
        resp.port.l3_mcast.l2_tx_port.is_trunk = 1;
    }
    else
    {
        resp.port.l3_mcast.l2_tx_port.port_number = idx;
        resp.port.l3_mcast.l2_tx_port.trunk_or_line_card = rs_data->line_card_id;
    }
    resp.port.l3_mcast.l3_tx_port = rs_data->l3_port_id;

    /* Store next layer ref. */
    resp.port.l3_mcast.next_layer_ref = rs_data->log_multi->next_layer_ref & 0xffff;
    resp.port.l3_mcast.next_layer_ref_msb = (rs_data->log_multi->next_layer_ref >> 16) & 0x1;

    if (rs_data->log_multi->flags & X_LMF_E_LSP)
    {
        resp.port.l3_mcast.e_lsp = 1;
    }
    if (rs_data->log_multi->flags & X_LMF_NEXT_LAYER_MPLS)
    {
        resp.port.l3_mcast.next_layer_mpls = 1;
    }
    resp.port.l3_mcast.ttl_scope = rs_data->log_multi->ttl_scope;
    resp.jump = L3_MCAST_ENCODER;

    /* Create request data and mask and install port encoding entry */
    ret = write_encoding_layer3(xid, index, port_id, rs_data->port_flags, &resp, rs_data->log_multi);
    return ret;
}

int xel_port_clear_log_multi(uint8_t xid,
                             uint16_t index)
{
    int ret;

    ret = mem_nse_clear_80(xid, index + 2, PORT_ENCODING_INDEX_ADDR, PORT_ENCODING_INDEX_SIZE);
    return ret;
}

int xel_port_set_to_cpu_egress(uint8_t xid,
                               uint16_t port_id,
                               uint16_t port_flags)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    memset(&resp, 0, sizeof(struct port_encoding_resp));

    index = sub_port(port_id, port_flags);

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_PORT_ENCODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    resp.jump = PORT_ENCODER_TO_CPU;
    ret = write_encoding(xid, index, port_id, port_flags, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    return ret;
}

int xel_port_set_loop_egress(uint8_t xid,
                             uint16_t port_id,
                             uint16_t port_flags)
{
    struct port_encoding_resp resp;
    uint16_t index;
    int ret;

    memset(&resp, 0, sizeof(struct port_encoding_resp));

    index = sub_port(port_id, port_flags);

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_PORT_ENCODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    resp.jump = PORT_ENCODER_LOOP;
    ret = write_encoding(xid, index, port_id, port_flags, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Clear L3 over L2 rule, if any */
    ret = clear_encoding_layer3_cvc(xid, index);

    return ret;
}

int xel_port_set_catch_all_egress(uint8_t xid)
{
    struct port_encoding_index_req req;
    struct port_encoding_index_req mask;
    struct port_encoding_resp resp;
    int ret;
    uint32_t tcam_index;
    uint32_t sram_addr;

    /* Clear data structures. */
    memset(&req,  0, sizeof(struct port_encoding_index_req));
    memset(&resp, 0, sizeof(struct port_encoding_resp));
    memset(&mask, 0, sizeof(struct port_encoding_index_req));

    req.u.unicast.type = NP_SLOW_PATH;
    mask.u.unicast.type  = 0x0f;
#ifndef LOOP_MODE
    req.u.unicast.tm_to_np_unicast.tm_to_np_type = 0x0;
    mask.u.unicast.tm_to_np_unicast.tm_to_np_type = 0x1;
#endif
    mask.table_id = NSE_TABLE_ID_MASK;
    req.table_id = PORT_ENC_NSE_TABLE_ID;

    tcam_index = 0;
    sram_addr = PORT_ENCODING_ADDR;

    resp.jump = PORT_ENCODER_LOOP;

    const char * port_encoding_resp_conv = PORT_ENCODING_RESP_PORT_ENCODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_encoding_resp, &resp);

    ret = write_ram(xid, sram_addr, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    const char * port_encoding_index_req_conv = PORT_ENCODING_INDEX_PORT_ENCODING_UNICAST_TYPE_REQ;
    CONVERT_ENDIAN(port_encoding_index_req, &req);
    CONVERT_ENDIAN(port_encoding_index_req, &mask);

    ret = mem_nse_write_search_word_and_mask_80(
        xid, 
        tcam_index,
        PORT_ENCODING_INDEX_ADDR,
        PORT_ENCODING_INDEX_SIZE,
        (uint8_t*)&req, 
        sizeof(struct port_encoding_index_req),
        (uint8_t*)&mask, 
        sizeof(struct port_encoding_index_req));

    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Port encoding catch all */

    /* Clear data structures. */
    memset(&req,  0, sizeof(struct port_encoding_index_req));
    memset(&resp, 0, sizeof(struct port_encoding_resp));
    memset(&mask, 0, sizeof(struct port_encoding_index_req));

    mask.table_id = NSE_TABLE_ID_MASK;
    req.table_id = PORT_ENC_NSE_TABLE_ID;
    
    tcam_index = PORT_ENCODING_INDEX_SIZE - 1;
    sram_addr = PORT_ENCODING_ADDR + PORT_ENCODING_SIZE - 1;

    resp.jump = PORT_ENCODER_DROP;
    
    CONVERT_ENDIAN(port_encoding_resp, &resp);
    ret = write_ram(xid, sram_addr, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    CONVERT_ENDIAN(port_encoding_index_req, &req);
    CONVERT_ENDIAN(port_encoding_index_req, &mask);
    ret = mem_nse_write_search_word_and_mask_80(xid,
                                                tcam_index,
                                                PORT_ENCODING_INDEX_ADDR,
                                                PORT_ENCODING_INDEX_SIZE,
                                                (uint8_t*)&req, sizeof(struct port_encoding_index_req),
                                                (uint8_t*)&mask, sizeof(struct port_encoding_index_req));
    return ret;
}

int xel_port_init_egress(uint8_t xid)
{
    int ret = 0;

#ifdef NSE_REN
#ifdef RDK
    uint32_t idx;

    for (idx = 0; idx < PORT_ENCODING_INDEX_SIZE; idx++)
    {
        ret = mem_nse_clear_80(xid, idx, PORT_ENCODING_INDEX_ADDR, PORT_ENCODING_INDEX_SIZE);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            return ret;
        }
    }
#endif
#endif
    
    ret = xel_port_set_catch_all_egress(xid);

    return ret;
}

/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Sets a L3 over C-VLAN port.
 */
int XEL_PortSetLayer3CVC(uint8_t            iXid, 
                         uint16_t           rqPortID,
                         uint8_t            rsLineCardID,
                         uint16_t           rsPortFlags,
                         uint16_t           rsTrunkId,
                         uint16_t           rsL3PortId)
{
    struct xel_port_layer3_egress_resp_data rs_data;

    rs_data.line_card_id = rsLineCardID;
    rs_data.port_flags = rsPortFlags;
    rs_data.trunk_id = rsTrunkId;
    rs_data.l3_port_id = rsL3PortId;

    return(xel_port_set_layer3_cvc_egress(iXid, rqPortID, &rs_data));
}

int XEL_PortDropLayer3CVC(uint8_t            iXid,
                          uint16_t           rqPortID,
                          uint16_t           rsPortFlags)
{
    return(xel_port_set_drop_layer3_cvc_egress(iXid, rqPortID, rsPortFlags));
}

/*
 * Set a multicast port enc entry.
 */
int XEL_PortSetLogMulti(uint8_t            iXid, 
                        uint16_t           rqPortID,
                        uint16_t           iIndex,
                        uint8_t            rsLineCardID,
                        uint16_t           rsPortFlags,
                        uint16_t           rsTrunkId,
                        uint8_t            rsL3PortId,
                        struct X_LogMulti* rsLogMulti)
{
    struct xel_port_log_multi_egress_resp_data rs_data;

    rs_data.line_card_id = rsLineCardID;
    rs_data.port_flags = rsPortFlags;
    rs_data.trunk_id = rsTrunkId;
    rs_data.l3_port_id = rsL3PortId;
    rs_data.log_multi = (struct xel_log_multi*)rsLogMulti;

    return(xel_port_set_log_multi_egress(iXid, rqPortID, iIndex, &rs_data));
}

/*
 * Disable Log Multi entry.
 */
int XEL_PortClearLogMulti(uint8_t iXid, uint16_t iIndex)
{
    return(xel_port_clear_log_multi(iXid, iIndex));
}

