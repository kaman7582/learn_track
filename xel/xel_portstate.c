/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_portstate.c,v $
 * $Revision: 1.34 $
 * 
 * \file  xel_portstate.c
 * \brief Port state management API
 * 
 * Description:
 * API for managing port state table.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <byteswap.h>

#include "drv_driver.h"
#include "xel_portstate.h"
#include "memory.h"
#include "engine_operations.h"
#include "fpa_ecmheader.h"
#ifdef USE_ECM_PROGRAM
#include "pkg.h"
#endif
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

/*
 * Internal function
 */
static int port_state_set(uint8_t xid,
                          struct xel_port_state_req_data* rq_data,
                          struct xel_port_state* port_state,
                          msgflow_t flow)
{
    uint32_t address  = 0;
    uint8_t  state    = PORTSTATE_DISCARDING;
    int      ret      = 0;
    uint16_t val      = 0;
    msgprof_t  profile;

    struct XCM_Header xcm;

    if ((!rq_data) || (!port_state))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Update ingress. */
    switch(port_state->port_state) {
    case X_FORWARDING:
        state = PORTSTATE_FORWARDING;
        break;
    case X_DISCARDING:
        state = PORTSTATE_DISCARDING;
        break;
    case X_LEARNING:
        state = PORTSTATE_LEARNING;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
    }

    if (port_state->is_member != 0)
        state |= PORTSTATE_VLAN_IS_MEMBER;   
 
    if (port_state->is_tagged)
        state |= PORTSTATE_VLAN_IS_TAGGED;

    address = VID_TRANSLATION_INGRESS_ADDR + (rq_data->port_id * 4096 + (rq_data->vid & 0x0fff)) * 2;

    if (address >= (VID_TRANSLATION_INGRESS_ADDR + VID_TRANSLATION_INGRESS_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    val = BSWAP16(state | (6 << 8));

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM0_SetNibble;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(val), &val);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    /* Update egress. */
    if (rq_data->component == X_S_COMP) {

        address = VID_TRANSLATION_EGRESS_ADDR + rq_data->port_id * 4096 + rq_data->svid;

        if (address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        val = BSWAP16(state | (15 << 8));

    }
    else
    {
        address = VID_TRANSLATION_EGRESS_ADDR + rq_data->port_id * 4096 + rq_data->svid;
        if (address >= (VID_TRANSLATION_EGRESS_ADDR + VID_TRANSLATION_EGRESS_SIZE))
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
            return -EINVAL;
        }
        
        val = BSWAP16(state | (6 << 8));
    }
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS2;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM2_SetNibble;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(val), &val);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }

    return ret;
}

int xel_port_state_set(uint8_t xid,
                       struct xel_port_state_req_data* rq_data,
                       struct xel_port_state* port_state)
{
    msgflow_t flow = drv_get_flow(xid);
    int ret    = 0;

    ret = port_state_set(xid, rq_data, port_state, flow);
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


#ifdef USE_ECM_PROGRAM
int xel_port_state_set_port(uint8_t xid,
                            struct xel_port_state_port_req_data* rq_data,
                            struct xel_port_state* port_state)
{
    int ret;
    struct set_portstate_ecm_header set_port_state_ecm;
    uint32_t inject_counter;
    uint8_t pkggen[2];

    if ((!rq_data) || (!port_state))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Ingress. Each ECM updates two entries. Entries are 128 bit. */
    set_port_state_ecm.ecm.seq = SET_PORT_STATE_SEQ;
    
    switch(port_state->port_state) {
    case X_FORWARDING:
        set_port_state_ecm.port_state = PORTSTATE_FORWARDING;
        break;
    case X_DISCARDING:
        set_port_state_ecm.port_state = PORTSTATE_DISCARDING;
        break;
    case X_LEARNING:
        set_port_state_ecm.port_state = PORTSTATE_LEARNING;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        break;
    }
#ifdef RDK
    inject_counter = 4096 / 2;
#else
    inject_counter = 400;
#endif
    set_port_state_ecm.table_address = VID_TRANSLATION_INGRESS_ADDR + 4096 * 2 * rq_data->port_id;

    if (rq_data->component == X_S_COMP)
        set_port_state_ecm.ecm.type = SET_PORT_STATE_SVLAN_INGR_TYPE;
    else {
        if (rq_data->component != X_C_COMP)
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        set_port_state_ecm.ecm.type = SET_PORT_STATE_CVLAN_INGR_TYPE;
    }

    const char * set_portstate_ecm_header_conv = "hb2wb";
    CONVERT_ENDIAN(set_portstate_ecm_header, &set_port_state_ecm);    
    ret = pkg_start_packet_gen(xid, inject_counter, sizeof(struct set_portstate_ecm_header),
                               (uint8_t*)&set_port_state_ecm, &pkggen[0]);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return ret;
    }
    
    /* Egress. Each ECM updates two entries. Entries are 64 bit. */
    set_port_state_ecm.ecm.seq = SET_PORT_STATE_SEQ;
    
    switch(port_state->port_state) {
    case X_FORWARDING:
        set_port_state_ecm.port_state = PORTSTATE_FORWARDING;
        break;
    case X_DISCARDING:
        set_port_state_ecm.port_state = PORTSTATE_DISCARDING;
        break;
    case X_LEARNING:
        set_port_state_ecm.port_state = PORTSTATE_LEARNING;
        break;
    default:
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        break;
    }
#ifdef RDK
    inject_counter = 4096 / 2;
#else
    inject_counter = 400;
#endif
    set_port_state_ecm.table_address = VID_TRANSLATION_EGRESS_ADDR + 4096 * 1 * rq_data->port_id;

    if (rq_data->component == X_S_COMP)
        set_port_state_ecm.ecm.type = SET_PORT_STATE_SVLAN_EGR_TYPE;
    else {
        if (rq_data->component != X_C_COMP)
            XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        set_port_state_ecm.ecm.type = SET_PORT_STATE_CVLAN_EGR_TYPE;
    }
    
    CONVERT_ENDIAN(set_portstate_ecm_header, &set_port_state_ecm);    
    ret = pkg_start_packet_gen(xid, inject_counter, sizeof(struct set_portstate_ecm_header),
                               (uint8_t*)&set_port_state_ecm, &pkggen[1]);
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
    
    return ret;
}
#else

int xel_port_state_set_port(uint8_t xid,
                            struct xel_port_state_port_req_data* rq_data,
                            struct xel_port_state* port_state)
{
    int      ret      = 0;
    uint16_t vid      = 0;
    msgflow_t flow    = drv_get_flow(xid);
    struct xel_port_state_req_data ps_rq_data;

    if (rq_data == NULL)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (port_state == NULL)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    ps_rq_data.component = rq_data->component;
    ps_rq_data.port_id   = rq_data->port_id;

    for (vid = 0; vid < 4096; vid++)
    {
        ps_rq_data.vid = ps_rq_data.svid = vid;

        ret = port_state_set(xid, &ps_rq_data, port_state, flow);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
#ifndef RDK
        usleep(5000);
#endif
    }

    ret = msgflow_flush(flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        

    while ((ret = msgflow_transit_count(flow)) > 0)
    {
        usleep(100000);
    }
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

/*
 * Set port state for single VID and and port.
 */
int 
XEL_PortStateSet(uint8_t iXid, enum X_VLANComp rsComponent, uint16_t rqPortID,
                 uint16_t rqVID, uint16_t rqSVID, struct X_PortState* rsPortState)
{
    struct xel_port_state_req_data rq_data;

    rq_data.component = rsComponent;
    rq_data.port_id = rqPortID;
    rq_data.vid = rqVID;
    rq_data.svid = rqSVID;

    return(xel_port_state_set(iXid, &rq_data, (struct xel_port_state*)rsPortState));
}

/*
 * Set port state for all VIDs of a port.
 */
int 
XEL_PortStateSetPort(uint8_t iXid, enum X_VLANComp rsComponent,
                     uint16_t rqPortID, enum X_PortStateVal rsPortState)
{
    struct xel_port_state_port_req_data rq_data;
    struct xel_port_state port_state;

    rq_data.component = rsComponent;
    rq_data.port_id = rqPortID;

    port_state.port_state = rsPortState;

    return(xel_port_state_set_port(iXid, &rq_data, &port_state));
}

