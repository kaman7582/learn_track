/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_macread.c,v $
 * $Revision: 1.28 $
 * 
 * \file xel_macread.c
 * \brief Ethernet bridge management API
 * 
 * Description:
 * API for managing ethernet bridge tables.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_macread.h"
#include "xel_macaddress.h"
#include "mem_nse.h"
#include "msgatom.h"
#include "xlog.h"
#include "memory.h"
#include "mac_forward.h"
#ifdef MAC_IN_RAM
#include "mac_forward_dram.h"
#endif
#include "engine_operations.h"
#include "fpa_memory_map.h"
#include "fpa_endian_conv_strings.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"

/*
 * Find entry in TCAM.
 */
int xel_mac_find(uint8_t xid,
                 struct xel_mac_find_req_data* rq_data,
                 struct xel_mac_find_read_data* re_data)
{
    int ret = 0;
    uint8_t resp_size;
    struct mac_forward_index_req tcam_req;
    uint8_t tcam_index_resp[sizeof(tcam_req)];
    struct mac_forward_resp tcam_resp;
    
#ifdef MAC_IN_RAM
    struct hash_req_part dram_hash;
    struct mac_dram_resp dram_resp;
#endif
    uint32_t address;
    struct XCM_Header xcm;
    msgflow_t flow = NULL;
    msgprof_t profile;
    uint16_t length;

    if ((!rq_data) || (!re_data))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    if (!(rq_data->damac))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    ret = msgflow_cm_open(drv_get_msgctl_hndl(xid), NULL, 3, &flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    re_data->memory_type = X_MF_NOT_FOUND;
    re_data->address = 0;

#ifdef MAC_IN_RAM
    memset(&dram_hash, 0, sizeof(struct hash_req_part));
    memset(&dram_resp, 0, sizeof(struct mac_dram_resp));

    /* Read first address */
    dram_hash.vsid = htons(rq_data->vsid & 0xffff);
    dram_hash.vsid_msb = htons((rq_data->vsid >> 16) & 0x3);
    memcpy(&dram_hash.damac, rq_data->damac, sizeof(struct xel_ethernet_addr));
        
    address = xel_mac_calc_crc((uint8_t *)&dram_hash,
                               sizeof(struct hash_req_part), 
                               0xffffffff, 1, 0x04c11db7);
    address &= (MAC_DRAM_ADDRESS_MASK << 16) | 0xffff;
    address |= MAC_DRAM_BANK_A_U16 << 16;

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAD0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LADRAM0_Read120;
    xcm.RW = XCM_READ;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(dram_resp), &dram_resp);
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
    
    ret = msgflow_receive(flow, &dram_resp, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    /* Check result */
    const char * mac_dram_resp_conv = MAC_DRAM_RESP_LABEL_REF; /* Same conv string for all resp types */
    CONVERT_ENDIAN(mac_dram_resp, &dram_resp);

    if ((dram_resp.cmp_vsid == (rq_data->vsid & 0xffff)) &&
        (dram_resp.cmp_vsid_msb == ((rq_data->vsid >> 16) & 0x3)) &&
        (dram_resp.cmp_mac.a0 == rq_data->damac->a[0]) &&
        (dram_resp.cmp_mac.a1 == rq_data->damac->a[1]) &&
        (dram_resp.cmp_mac.a2 == rq_data->damac->a[2]) &&
        (dram_resp.cmp_mac.a3 == rq_data->damac->a[3]) &&
        (dram_resp.cmp_mac.a4 == rq_data->damac->a[4]) &&
        (dram_resp.cmp_mac.a5 == rq_data->damac->a[5]))
    {
        re_data->memory_type = X_MF_FOUND_IN_DRAM;
        re_data->address = address;
        goto out;
    }
    
    /* Read second address */
    address = xel_mac_calc_crc((uint8_t *)&dram_hash,
                               sizeof(struct hash_req_part), 
                               0x00000000, 0, 0x04c11db7);
    address &= (MAC_DRAM_ADDRESS_MASK << 16) | 0xffff;
    address |= MAC_DRAM_BANK_B_U16 << 16;

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAD0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LADRAM0_Read120;
    xcm.RW = XCM_READ;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(dram_resp), &dram_resp);
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
    
    ret = msgflow_receive(flow, &dram_resp, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    /* Check result */
    CONVERT_ENDIAN(mac_dram_resp, &dram_resp);

    if ((dram_resp.cmp_vsid == (rq_data->vsid & 0xffff)) &&
        (dram_resp.cmp_vsid_msb == ((rq_data->vsid >> 16) & 0x3)) &&
        (dram_resp.cmp_mac.a0 == rq_data->damac->a[0]) &&
        (dram_resp.cmp_mac.a1 == rq_data->damac->a[1]) &&
        (dram_resp.cmp_mac.a2 == rq_data->damac->a[2]) &&
        (dram_resp.cmp_mac.a3 == rq_data->damac->a[3]) &&
        (dram_resp.cmp_mac.a4 == rq_data->damac->a[4]) &&
        (dram_resp.cmp_mac.a5 == rq_data->damac->a[5]))
    {
        re_data->memory_type = X_MF_FOUND_IN_DRAM;
        re_data->address = address;
        goto out;
    }
#endif /* ifdef MAC_IN_RAM */

    /* Lookup in TCAM. */
    memset(&tcam_req, 0, sizeof(struct mac_forward_index_req));
    memcpy(&tcam_req.damac, rq_data->damac, sizeof(tcam_req.damac));
    tcam_req.vsid = rq_data->vsid & 0xffff;
    tcam_req.vsid_msb = (rq_data->vsid >> 16) & 0x3;
    /* Table id */
    tcam_req.table_id = MAC_FWD_NSE_TABLE_ID;

    const char * mac_forward_index_req_conv = MAC_FORWARD_INDEX_REQ;
    CONVERT_ENDIAN(mac_forward_index_req, &tcam_req);

    ret = mem_nse_lookup_80(
        xid, 
        MAC_FORWARD_INDEX_GMR, 
        (uint8_t*)&tcam_req,
        sizeof(struct mac_forward_index_req),
        tcam_index_resp, 
        &resp_size);

    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    //const char * mac_forward_index_resp_conv = MAC_FORWARD_INDEX_RESP;
    //CONVERT_ENDIAN(mac_forward_index_resp, tcam_index_resp);

#ifndef NSE_REN
    struct nse_resp temp;

    temp.index_hi = tcam_index_resp[1];
    temp.index_lo = (tcam_index_resp[2] << 8) | tcam_index_resp[3];
    
    address = (temp.index_hi << 16) | temp.index_lo;
    address = address - MAC_FORWARD_INDEX_ADDR + MAC_FORWARD_ADDR;
#else
    struct nse_resp temp;

    temp.index_hi = tcam_index_resp[1] & 0x3;
    temp.tcam_id  = tcam_index_resp[1] & 0x4;
    temp.index_lo = (tcam_index_resp[2] << 8) | tcam_index_resp[3];

    address = (temp.index_hi << 16) | temp.index_lo;
    address = address - MAC_FORWARD_INDEX_ADDR/2 + MAC_FORWARD_ADDR;
    address = address + temp.tcam_id * (MAC_FORWARD_INDEX_SIZE/2);

#endif
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS0;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM0_Read64;
    xcm.RW = XCM_READ;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(struct mac_forward_resp), &tcam_resp);
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
    
    ret = msgflow_receive(flow, &tcam_resp, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    if (ret > 0)
        ret = 0;
    
    const char * mac_forward_resp_conv = MAC_FORWARD_RESP_UNICAST_TYPE;
    CONVERT_ENDIAN(mac_forward_resp, &tcam_resp);

    if (tcam_resp.address_type.unicast.type == MAC_UNICAST_ADDR)
    {
        re_data->memory_type = X_MF_FOUND_IN_TCAM;
        re_data->address = (uint32_t)tcam_resp.address_type.unicast.tcam_address;
        goto out;
    }
    
 out:
    if (flow != NULL)
    {
        int rc = 0;
        rc = msgflow_close(flow);
        if (rc < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), rc);
            ret = rc;
        }
    }

    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int XEL_MACFind(uint8_t                iXid,
                uint32_t               rqVSID,
                struct X_EthernetAddr* rqDAMAC,
                uint8_t                rqFromPW,
                uint8_t*               oMemoryType,
                uint32_t*              oAddress)
{
    struct xel_mac_find_req_data rq_data;
    struct xel_mac_find_read_data re_data;
    int ret;
    
    rq_data.vsid = rqVSID;
    rq_data.damac = rqDAMAC;
    rq_data.from_pw = rqFromPW;
    ret = xel_mac_find(iXid, &rq_data, &re_data);
    if (ret)
        return ret;

    *oMemoryType = re_data.memory_type;
    *oAddress = re_data.address;

    return ret;
}
#if 0
/*
 * Reads an entry from TCAM.
 */
int
XEL_MACRead(uint8_t                     iXid,
            uint32_t                    iIndex,
            struct MACAddressReqType*   oReq,
            struct MACAddressRespType*  oResp)
{
    return -ENOSYS;
}

/*
 * Reads an entry from DRAM.
 */
#ifdef MAC_IN_RAM
int XEL_MACDRAMRead(uint8_t                  iXid,
                    uint32_t                 iIndex,
                    struct MACDRAMEntryType* oEntry)
{
    return -ENOSYS;
}
#endif

/*
 *
 */
int 
XEL_MACPrintHeader(void)
{
    return -ENOSYS;
}

/*
 *
 */
int
XEL_MACPrint(uint8_t  iXid,
             uint32_t iStartIndex,
             uint32_t iStopIndex)
{
    return -ENOSYS;
}

#ifdef MAC_IN_RAM
/*
 *
 */
int
XEL_MACDRAMPrint(uint8_t   iXid,
                 uint32_t  iStartIndex,
                 uint32_t  iStopIndex)
{
    return -ENOSYS;
}
#endif
#endif
