/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_portdecoding.c,v $
 * $Revision: 1.47 $
 * 
 * \file  xel_portdecoding.c
 * \brief Port decoding management API
 * 
 * Description:
 * API for managing port decoding table.
 *--------------------------------------------------------------------------*/

#include <assert.h>
#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_portdecoding.h"
#include "xel_portencoding.h"
#include "mem_tcam.h"
#include "port_decoding.h"
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

    return sub_port;
}

/*
 * Fills in bridge port decoding resp.
 */
static void bridge_port_resp(uint16_t         index,
                             struct port_decoding_resp* dec_resp,
                             uint8_t          line_card_id,
                             uint16_t         vid,
                             uint16_t         port_flags,
                             uint16_t         trunk_id,
                             enum xel_load_balance hash,
                             enum X_Frames    filter)
{
    if (port_flags & X_PF_IS_TRUNK)
    {
        dec_resp->rx_port.trunk_lc = trunk_id;
        dec_resp->rx_port.is_trunk = 1;
        /* Link hash type. */
        switch(hash)
        {
        case X_LB_SADAMAC:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_SADAMAC;
            break;
        case X_LB_SAMAC:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_SAMAC;
            break;
        case X_LB_DAMAC:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_DAMAC;
            break;
        case X_LB_SAIP:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_SAIP;
            break;
        case X_LB_DAIP:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_DAIP;
            break;
        case X_LB_SADAIP:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_SADAIP;
            break;
        case X_LB_VID:
            dec_resp->port.bridge.pdec_link_hash.link_hash = LA_SVID;
            break;
        default:
            assert(0);
        }
    }
    else
    { /* No trunk, set Line card. */
        dec_resp->rx_port.trunk_lc = line_card_id;
        dec_resp->rx_port.port_number = index;
    }
    
    dec_resp->port.bridge.vid  = vid;

    dec_resp->port.bridge.acceptable_frames = filter;
    
    if (port_flags & X_PF_ENABLE_INGR_FILTER)
    {
        dec_resp->port.bridge.ingress_filter = 1;
    }
    if (port_flags & X_PF_DIST_TRUNK)
    {
        dec_resp->dist_trunk = 1;
    }
    if (port_flags & X_PF_NO_RELEARN)
    {
        dec_resp->port.bridge.no_relearn = 1;
    }
}

/*
 * Fills in SVC port dec resp.
 */
static void bridge_svc_port_resp(struct port_decoding_resp* dec_resp,
                                 uint16_t port_flags,
                                 struct xel_svc_param* svc_params)
{
    /* Ethernet Type */
    dec_resp->port.bridge.stag_etype = svc_params->stag_etype;

    /* Set use DE form frame flag. */
    if (port_flags & X_PF_USE_DE)
    {
        dec_resp->port.bridge.use_de = 1;
    } 

    /* CFM MAC address ? */
    if (port_flags & X_PF_CFM_PACKET)
    {
        dec_resp->port.bridge.cfm_mac = 1;
    }
    
    /* Default prio */
    dec_resp->port.bridge.prio = svc_params->prio;
}

/*
 * Fills in CVC port dec response.
 */
static void bridge_cvc_port_resp(struct port_decoding_resp* dec_resp,
                                 uint16_t port_flags,
                                 struct xel_cvc_param* cvc_params)
{
    /* Ethernet Type */
    dec_resp->port.bridge.stag_etype = ETHER_TYPE_VLAN;
    
    /* Default prio */
    dec_resp->port.bridge.prio = cvc_params->prio;

}

/*
 * Fills in IVC port dec response.
 */
static void bridge_ivc_port_resp(struct port_decoding_resp* dec_resp,
                                 struct xel_ivc_param* ivc_params,
                                 uint16_t port_index)
{
    /* Ethernet Type */
    dec_resp->port.bridge.stag_etype = ivc_params->stag_etype;

    /* Default prio */
    dec_resp->port.bridge.prio = ivc_params->prio;
}

/*
 * Writes a port dec entry.
 */
static int write_decoding(uint8_t  xid,
                          uint16_t index,
                          uint16_t phy_port,
                          uint16_t port_flags,
                          struct xel_vlan_classify* classify,
                          struct port_decoding_resp* resp)
{
    struct port_decoding_req req;
    struct port_decoding_req mask;
    uint32_t tcam_addr;
    uint32_t sram_addr;
    int ret;

    memset(&req, 0, sizeof(struct port_decoding_req));
    memset(&mask, 0, sizeof(struct port_decoding_req));

    /* Set packet interface for Tri Speed ports */
    req.port = sub_port(phy_port, port_flags);

    /* Set mask. */
    mask.port = 0x3f;
    
    if (classify) {
        /* Include protocol and MAC based class key and mask. */
        memcpy(&req.damac, &classify->damac, sizeof(struct xel_ethernet_addr));
        memcpy(&mask.damac, &classify->damac_mask, sizeof(struct xel_ethernet_addr));
        memcpy(&req.samac, &classify->samac, sizeof(struct xel_ethernet_addr));
        memcpy(&mask.samac, &classify->samac_mask, sizeof(struct xel_ethernet_addr));
    }
    
    if (classify) {
        tcam_addr = PORT_DECODING_REQ_ADDR + 4 * classify->index;
        sram_addr = PORT_DECODING_RES_ADDR + 4 * classify->index;
    }
    else {
        tcam_addr = PORT_DECODING_REQ_ADDR + PORT_DECODING_REQ_SIZE - 48*4 - 2*4 + 4 * index;
        sram_addr = PORT_DECODING_RES_ADDR + PORT_DECODING_RES_SIZE - 48*4 - 2*4 + 4 * index;
    }
    if (tcam_addr >= (PORT_DECODING_REQ_ADDR + PORT_DECODING_REQ_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (sram_addr >= (PORT_DECODING_RES_ADDR + PORT_DECODING_RES_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    const char * port_decoding_req_conv = PORT_DECODING_REQ;

    CONVERT_ENDIAN(port_decoding_req, &req);
    CONVERT_ENDIAN(port_decoding_req, &mask);

    ret = mem_tcam_write_entry_160_128(xid, TCAM_1, tcam_addr,
                                       (uint8_t*)&req, sizeof(struct port_decoding_req),
                                       (uint8_t*)&mask, sizeof(struct port_decoding_req),
                                       sram_addr,
                                       (uint8_t*)resp, sizeof(struct port_decoding_resp));

    return ret;
}

/*
 * Writes a port dec extension entry.
 */
static int write_decoding_ex(uint8_t            xid,
                             uint16_t           port_id,
                             enum xel_vlan_comp component,
                             void*              port_params)
{
    struct port_decoding_extended_resp resp;
    struct xel_svc_param* svc_params;
    struct xel_cvc_param* cvc_params;
    struct xel_ivc_param* ivc_params;
    uint32_t addr;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    switch(component)
    {
        case X_S_COMP:
        {
            svc_params = (struct xel_svc_param*)port_params;
            resp.rt.svc.pcp_decoding_table = svc_params->pcp_decoding_table;
            resp.rt.svc.prio_regen_ref = svc_params->svc_prio_decoding_ref;
        
            const char* port_decoding_extended_resp_conv =
                PORT_DECODING_EXTENDED_RESP_SVC_TYPE;
        
            CONVERT_ENDIAN(port_decoding_extended_resp, &resp);
        
            break;
        }
        
        case X_C_COMP:
        {
            cvc_params = (struct xel_cvc_param*)port_params;
            resp.rt.cvc.prio_regen_table = cvc_params->cvc_ing_prio_regen_table;
        
            const char * port_decoding_extended_resp_conv =
                PORT_DECODING_EXTENDED_RESP_CVC_TYPE;
            
            CONVERT_ENDIAN(port_decoding_extended_resp, &resp);
        
            break;
        }
        
        case X_I_COMP:
        {
            ivc_params = (struct xel_ivc_param*)port_params;
            resp.rt.ivc.prio_regen_table = ivc_params->ivc_ing_prio_regen_table;
            resp.rt.ivc.b_samac_ref = ivc_params->b_samac_ref;
        
            const char * port_decoding_extended_resp_conv =
                PORT_DECODING_EXTENDED_RESP_IVC_TYPE;
        
            CONVERT_ENDIAN(port_decoding_extended_resp, &resp);
            break;
        }
    }

    addr = PORT_DECODING_EXTENDED_ADDR + port_id;

    if (addr >= (PORT_DECODING_EXTENDED_ADDR + PORT_DECODING_EXTENDED_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE1;
    xcm.Addr = htonl(addr);
    xcm.ReqCode = SRAM1_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, addr);
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

int xel_port_set_bridge_ingress(uint8_t xid,
                                struct xel_port_ingress_req_data* rq_data,
                                struct xel_port_bridge_ingress_resp_data* rs_data)
{
    struct port_decoding_resp resp;
    uint16_t index;
    int ret;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&resp, 0, sizeof(struct port_decoding_resp));

    index = sub_port(rq_data->port_id, rs_data->port_flags);

    /*
     * Port Decoding Table
     */

    /* Response data */
    /* Common fields for SVC, CVC and IVC */
    bridge_port_resp(index, &resp, rs_data->line_card_id, rs_data->vid, rs_data->port_flags,
                     rs_data->trunk_id, rs_data->link_hash, rs_data->filter);

    /* SVC/CVC/IVC specific */
    switch(rs_data->component)
    {
    case X_S_COMP:
        bridge_svc_port_resp(&resp, rs_data->port_flags, (struct xel_svc_param*)rs_data->port_params);
        resp.jump = SVLAN_DECODER;
        break;
    case X_C_COMP:
        bridge_cvc_port_resp(&resp, rs_data->port_flags, (struct xel_cvc_param*)rs_data->port_params);
        resp.jump = CVLAN_DECODER;
        break;
    case X_I_COMP:
        bridge_ivc_port_resp(&resp, (struct xel_ivc_param*)rs_data->port_params, index);
        resp.jump = IVLAN_DECODER;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        break;
    }

    if ((rs_data->port_flags & X_PF_CLASSIFY_TO_VLAN) != 0) 
    {
        if (!(rq_data->classify))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
    }

    const char * port_decoding_resp_conv = PORT_DECODING_RESP_PORT_DECODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);
    ret = write_decoding(xid, index, rq_data->port_id, rs_data->port_flags, rq_data->classify, &resp);
    if (ret < 0) 
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
    }

    /*
     * Port Decoding Extension Table
     */
    ret = write_decoding_ex(xid, rq_data->port_id, rs_data->component, rs_data->port_params);

    return ret;
}

int xel_port_set_bridge_class_ingress(uint8_t xid,
                                      struct xel_port_ingress_req_data* rq_data,
                                      struct xel_port_bridge_ingress_resp_data* rs_data)
{
    uint16_t index;
    struct port_decoding_resp resp;
    int ret;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&resp, 0, sizeof(struct port_decoding_resp));

    if (!(rq_data->classify))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
        
    index = rq_data->classify->index;

    /* Response data */
    /* Common fields for SVC, CVC and IVC */
    bridge_port_resp(index, &resp, rs_data->line_card_id, rs_data->vid, rs_data->port_flags,
                     rs_data->trunk_id, rs_data->link_hash, rs_data->filter);

    /* SVC/CVC/IVC specific */
    switch(rs_data->component)
    {
    case X_S_COMP:
:        bridge_svc_port_resp(&resp, rs_data->port_flags, (struct xel_svc_param*)rs_data->port_params);
        resp.jump = SVLAN_DECODER;
        break;
    case X_C_COMP
        bridge_cvc_port_resp(&resp, rs_data->port_flags, (struct xel_cvc_param*)rs_data->port_params);
        resp.jump = CVLAN_DECODER;
        break;
    case X_I_COMP:
        bridge_ivc_port_resp(&resp, (struct xel_ivc_param*)rs_data->port_params, index);
        resp.jump = IVLAN_DECODER;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        break;
    }

    const char * port_decoding_resp_conv = PORT_DECODING_RESP_PORT_DECODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);
    ret = write_decoding(xid, index, rq_data->port_id, rs_data->port_flags, rq_data->classify, &resp);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
    }

    ret = write_decoding_ex(xid, rq_data->port_id, rs_data->component, rs_data->port_params);
    return ret;
}

int xel_port_set_layer3_ingress(uint8_t xid,
                                uint16_t port_id,
                                struct xel_port_layer3_ingress_resp_data* rs_data)
{
    struct port_decoding_resp resp;
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

    memset(&resp, 0, sizeof(struct port_decoding_resp));
    index = sub_port(port_id, rs_data->port_flags);

    if (rs_data->port_flags & X_PF_IS_TRUNK)
    {
        resp.rx_port.is_trunk = 1;
        resp.rx_port.trunk_lc = rs_data->trunk_id;
    }
    else
    {
        resp.rx_port.port_number = index;
        resp.rx_port.trunk_lc = rs_data->line_card_id;
    }
    resp.jump = L3_DECODER;
    
    const char * port_decoding_resp_conv = PORT_DECODING_RESP_PORT_DECODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);
    ret = write_decoding(xid, index, port_id, rs_data->port_flags, 0, &resp);

    return ret;
}

int xel_port_set_to_cpu_ingress(uint8_t xid,
                                struct xel_port_ingress_req_data* rq_data,
                                struct xel_port_cpu_ingress_resp_data* rs_data)
{
    struct port_decoding_resp resp;
    uint16_t index;
    int ret;

    if ((!rq_data) || (!rs_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset(&resp, 0, sizeof(struct port_decoding_resp));

    index = sub_port(rq_data->port_id, rs_data->port_flags);

    if ((rs_data->port_flags & X_PF_USE_METER) != 0)
    {
        assert(rs_data->meter);
        resp.port.to_cpu.flags.use_meter = 1;
        resp.port.to_cpu.meter_index = rs_data->meter->meter_index;
        switch(rs_data->meter->pre_color)
        {
        case X_COLOR_BLIND:
            resp.port.to_cpu.flags.meter_flags = TWO_RATE_REDUCING_COLOR_BLIND;
            break;
        case X_PRE_COLOR_GREEN:
            resp.port.to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_GREEN;
            break;
        case X_PRE_COLOR_YELLOW:
            resp.port.to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_YELLOW;
            break;
        case X_PRE_COLOR_RED:
            resp.port.to_cpu.flags.meter_flags = TWO_RATE_REDUCING_PRE_COLOR_RED;
            break;
        default:
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            break;
        }
        if (rs_data->meter->meter_type == X_METER_2698)
        {
            resp.port.to_cpu.flags.meter_type = METER_TYPE_2698;
        }
        else if (rs_data->meter->meter_type == X_METER_COUPLED)
        {
            resp.port.to_cpu.flags.meter_type = METER_TYPE_COUPLED;
        }
        else if (rs_data->meter->meter_type == X_METER_DECOUPLED)
        {
            resp.port.to_cpu.flags.meter_type = METER_TYPE_DECOUPLED;
        }
        else
        {
            assert(0);
        }
        if ((rs_data->meter->meter_flags & X_DROP_RED) != 0)
        {
            resp.port.to_cpu.flags.drop_on_red = 1;
        }
        if ((rs_data->meter->meter_flags & X_DROP_YELLOW) != 0)
        {
            resp.port.to_cpu.flags.drop_on_yellow = 1;
        }
    }
    if (rs_data->traffic_class != NULL)
    {
        resp.port.to_cpu.flags.tm_drop_prec = rs_data->traffic_class->tm_drop_precedence;
        resp.port.to_cpu.flags.tm_cos = rs_data->traffic_class->tm_cos;
    }
    resp.rx_port.port_number = index;
    resp.port.to_cpu.reason = rs_data->reason;
    resp.jump = PORT_DECODER_TO_CPU;

    const char * port_decoding_resp_conv = PORT_DECODING_RESP_TO_CPU_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);
    ret = write_decoding(xid, index, rq_data->port_id, rs_data->port_flags, rq_data->classify, &resp);

    return ret;
}

int xel_port_set_drop_ingress(uint8_t xid,
                              struct xel_port_ingress_req_data* rq_data,
                              uint16_t port_flags)
{
    struct port_decoding_resp resp;
    uint16_t index;
    int ret;

    if (!rq_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&resp, 0, sizeof(struct port_decoding_resp));

    index = sub_port(rq_data->port_id, port_flags);

    resp.jump = PORT_DECODER_DROP;
    const char * port_decoding_resp_conv = PORT_DECODING_RESP_PORT_DECODING_BRIDGE_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);
    if ((port_flags & X_PF_CLASSIFY_TO_VLAN) != 0)
    {
        if (!(rq_data->classify))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        ret = write_decoding(xid, index, rq_data->port_id, port_flags, rq_data->classify, &resp);
    }
    else
    {
        ret = write_decoding(xid, index, rq_data->port_id, port_flags, 0, &resp);
    }

    return ret;
}

int xel_port_set_loop_ingress(uint8_t xid,
                              uint16_t port_id,
                              struct xel_port_loop_ingress_resp_data* rs_data)
{
    struct port_decoding_resp resp;
    uint16_t index;
    int ret;

    if (!rs_data)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    memset(&resp, 0, sizeof(struct port_decoding_resp));

    index = sub_port(port_id, rs_data->port_flags);

    resp.port.loop_port.dest_id = rs_data->destination;

    if (rs_data->traffic_class != NULL)
    {
        resp.port.loop_port.tm_drop_precedence = rs_data->traffic_class->tm_drop_precedence;
        resp.port.loop_port.tm_cos = rs_data->traffic_class->tm_cos;
    }

    resp.jump = PORT_DECODER_LOOP;

    /* Create request data and mask and install port entries */
    const char * port_decoding_resp_conv = PORT_DECODING_RESP_LOOP_TYPE;
    CONVERT_ENDIAN(port_decoding_resp, &resp);

    ret = write_decoding(xid, index, port_id, rs_data->port_flags, 0, &resp);

    return ret;
}

int xel_port_clear_bridge_class_ingress(uint8_t xid,
                                        uint16_t index)
{
    uint32_t addr;
    int ret;

    addr = PORT_DECODING_REQ_ADDR + 4 * index;
    if (addr >= (PORT_DECODING_REQ_ADDR + PORT_DECODING_REQ_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    ret = mem_tcam_clear_entry_160(xid, TCAM_1, addr);

    return ret;
}

int xel_port_set_catch_all_ingress(uint8_t xid)
{
    struct port_decoding_req req;
    struct port_decoding_req mask;
    struct port_decoding_resp resp;
    int ret;
    uint32_t tcam_addr;
    uint32_t sram_addr;

    /* Port decoding, unused port catch all. */

    memset(&req, 0, sizeof(struct port_decoding_req));
    memset(&mask, 0, sizeof(struct port_decoding_req));
    
    /* Set mask. */
    mask.port = 0;
    resp.jump = PORT_DECODER_DROP;

    tcam_addr = PORT_DECODING_REQ_ADDR + PORT_DECODING_REQ_SIZE - (1 * 4);
    sram_addr = PORT_DECODING_RES_ADDR + PORT_DECODING_RES_SIZE - (1 * 4);

    if (tcam_addr >= (PORT_DECODING_REQ_ADDR + PORT_DECODING_REQ_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (sram_addr >= (PORT_DECODING_RES_ADDR + PORT_DECODING_RES_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    const char * port_decoding_req_conv = PORT_DECODING_REQ;
    const char * port_decoding_resp_conv = PORT_DECODING_RESP_PORT_DECODING_BRIDGE_TYPE;

    CONVERT_ENDIAN(port_decoding_resp, &resp);
    CONVERT_ENDIAN(port_decoding_req, &req);
    CONVERT_ENDIAN(port_decoding_req, &mask);

    ret = mem_tcam_write_entry_160_128(xid, TCAM_1, tcam_addr,
                                       (uint8_t*)&req, sizeof(struct port_decoding_req),
                                       (uint8_t*)&mask, sizeof(struct port_decoding_req),
                                       sram_addr,
                                       (uint8_t*)&resp, sizeof(struct port_decoding_resp));

    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 * Configures a bridge port.
 */
int XEL_PortSetBridge(uint8_t          iXid, 
                      uint16_t         rqPortID,
                      struct X_VLANClassify* rqClassify,
                      uint8_t          rsLineCardID,
                      enum X_VLANComp  rsComponent,

                      uint16_t         rsVID,
    
                      uint16_t         rsPortFlags,
                      uint16_t         rsTrunkId,
                      enum X_Frames    rsFilter,
                      
                      void*            rsPortParams)
{
    struct xel_port_ingress_req_data rq_data;
    struct xel_port_bridge_ingress_resp_data rs_data_ing;
    struct xel_port_bridge_egress_resp_data rs_data_eg;
    int ret = 0;
    
    rq_data.port_id = rqPortID;
    rq_data.classify = (struct xel_vlan_classify*)rqClassify;

    rs_data_ing.line_card_id = rsLineCardID;
    rs_data_ing.component = rsComponent;
    rs_data_ing.vid = rsVID;
    rs_data_ing.port_flags = rsPortFlags;
    rs_data_ing.trunk_id = rsTrunkId;
    rs_data_ing.link_hash = (rsPortFlags >> 9) & 0x07;
    rs_data_ing.filter = rsFilter;
    rs_data_ing.port_params = rsPortParams;

    ret = xel_port_set_bridge_ingress(iXid, &rq_data, &rs_data_ing);
    if (ret < 0)
        return ret;

    rs_data_eg.line_card_id = rsLineCardID;
    rs_data_eg.component = rsComponent;
    rs_data_eg.vid = rsVID;
    rs_data_eg.port_flags = rsPortFlags;
    rs_data_eg.trunk_id = rsTrunkId;
    rs_data_eg.filter = rsFilter;
    rs_data_eg.port_params = rsPortParams;
 
    return(xel_port_set_bridge_egress(iXid, rqPortID, &rs_data_eg));
}

/*
 * Set ingress bridge port with classification. Index is in
 * rqClassify.
 */
int 
XEL_PortSetBridgeClass(uint8_t iXid, uint16_t rqPortID,
                       struct X_VLANClassify* rqClassify, uint8_t rsLineCardID,
                       enum X_VLANComp rsComponent, uint16_t rsVID,
                       uint16_t rsPortFlags, uint16_t rsTrunkId,
                       enum X_Frames rsFilter, void* rsPortParams)
{
    struct xel_port_ingress_req_data rq_data;
    struct xel_port_bridge_ingress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.classify = (struct xel_vlan_classify*)rqClassify;

    rs_data.line_card_id = rsLineCardID;
    rs_data.component = rsComponent;
    rs_data.vid = rsVID;
    rs_data.port_flags = rsPortFlags;
    rs_data.trunk_id = rsTrunkId;
    rs_data.filter = rsFilter;
    rs_data.port_params = rsPortParams;

    return(xel_port_set_bridge_class_ingress(iXid, &rq_data, &rs_data));    
}

/*
 * Sets a L3 port.
 */
int XEL_PortSetLayer3(uint8_t            iXid, 
                      uint16_t           rqPortID,
                      uint8_t            rsLineCardID,
                      uint16_t           rsPortFlags,
                      uint16_t           rsTrunkId,
                      uint16_t           rsL3PortId)
{
    struct xel_port_layer3_ingress_resp_data rs_data;
    int ret = 0;

    rs_data.line_card_id = rsLineCardID;
    rs_data.port_flags = rsPortFlags;
    rs_data.trunk_id = rsTrunkId;
    rs_data.l3_port_id = rsL3PortId;

    ret = xel_port_set_layer3_ingress(iXid, rqPortID, &rs_data);
    if (ret)
        return ret;

    return(xel_port_set_layer3_egress(iXid, rqPortID, (struct xel_port_layer3_egress_resp_data*)&rs_data));
}

/*
 *
 */
int XEL_PortSetToCPU(uint8_t                 iXid,
                     uint16_t                rqPortID,
                     struct X_VLANClassify*  rqClassify,
                     struct X_TrafficClass*  rsTrafficClass,
                     struct X_Meter*         rsMeter,
                     uint16_t                rsPortFlags,
                     uint8_t                 rsReason)
{
    struct xel_port_ingress_req_data rq_data;
    struct xel_port_cpu_ingress_resp_data rs_data;

    rq_data.port_id = rqPortID;
    rq_data.classify = (struct xel_vlan_classify*)rqClassify;

    rs_data.traffic_class = (struct xel_traffic_class*)rsTrafficClass;
    rs_data.meter = (struct xel_meter*)rsMeter;
    rs_data.port_flags = rsPortFlags;
    rs_data.reason = rsReason;

    return(xel_port_set_to_cpu_ingress(iXid, &rq_data, &rs_data));
}

/*
 *
 */
int XEL_PortSetLoop(uint8_t                iXid,
                    uint16_t               rqPortID,
                    uint16_t               rsPortFlags,
                    uint16_t               rsDestination,
                    struct X_TrafficClass* rsTrafficClass)
{
    struct xel_port_loop_ingress_resp_data rs_data;
    int ret = 0;
    
    rs_data.port_flags = rsPortFlags;
    rs_data.destination = rsDestination;
    rs_data.traffic_class = (struct xel_traffic_class*)rsTrafficClass;

    ret = xel_port_set_loop_ingress(iXid, rqPortID, &rs_data);
    if (ret)
        return ret;
    
    return(xel_port_set_loop_egress(iXid, rqPortID, rsPortFlags));
}

/* 
 * Set port to silently drop all packets.
 */
int XEL_PortSetDrop(uint8_t                 iXid,
                    uint16_t                rqPortID,
                    struct X_VLANClassify*  rqClassify,
                    uint16_t                rsPortFlags)
{
    struct xel_port_ingress_req_data rq_data;
    int ret;

    rq_data.port_id = rqPortID;
    rq_data.classify = (struct xel_vlan_classify*)rqClassify;

    ret = xel_port_set_drop_ingress(iXid, &rq_data, rsPortFlags);
    if (ret)
        return ret;
    return(xel_port_set_drop_egress(iXid, rqPortID, rsPortFlags));
}

/*
 * Disable Bridge class entry.
 */
int XEL_PortClearBridgeClass(uint8_t iXid, uint16_t iIndex)
{
    return(xel_port_clear_bridge_class_ingress(iXid, iIndex));
}

/*
 *
 */
int XEL_PortSetCatchAll(uint8_t iXid)
{
    int ret = 0;
    
    ret = xel_port_set_catch_all_ingress(iXid);
    if (ret)
        return ret;

    return(xel_port_set_catch_all_egress(iXid));
}

