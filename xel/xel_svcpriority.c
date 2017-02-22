/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_svcpriority.c,v $
 * $Revision: 1.24 $
 * 
 * \file xel_svcpriority.c
 * \brief PCP encoding management API
 * 
 * Description:
 * API for managing PCP encoding table.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_svcpriority.h"
#include "prio_regen.h"
#include "pcp_encoding.h"
#include "memory.h"
#include "engine_operations.h"
#include "fpa_endian_conv_strings.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "xel_endian.h"

uint32_t xel_svc_create_pcp_decoding_tbl(struct xel_pcp_decoding_table* table)
{
    int i;
    uint32_t tbl;
    
    tbl = 0;
    for (i = 0; i < 8; i++) {
        tbl = tbl << 4;
        if (table->decoded_pcp[i].prio >= 8)
            return -EINVAL;
        if (table->decoded_pcp[i].de >= 2)
            return -EINVAL;
        tbl |= (table->decoded_pcp[i].prio << 1);
        tbl |= (table->decoded_pcp[i].de);
    }
    return tbl;
}

int xel_svc_set_prio_decoding(uint8_t xid,
                              uint16_t svc_prio_decoding_ref,
                              struct xel_svc_prio_decoding_table* table)
{
    uint16_t address;
    struct prio_regen_ingress_resp resp;
    uint8_t i;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    if (!table)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    /* Address = (PriorityRegenerationRef * 16 +  2 * Priority + DE) / 4
     *         = PriorityRegenerationRef * 4 + (2*Prio + DE)/4
     *
     * There are 16 entries, prio values + DE, that shall be decoded to a response of DP, CoS and PHB for
     * each value. The response is 6 * 8 bits = 48 bits.
     * It is place for 4 responses in each address, that is four addresses are used.
     * The placement of the bits are as below. The meaning of the acronyms are:
     *
     * Cl0 = TMDropPrecedence for prio value 0
     * CoS0 = TMCoS for prio value 0
     * PHB0 = Marking PHB for prio value 0
     *
     * <pre>
     *  7 6 5 4 3 2 1 0
     * +-+-+-+-+-+-+-+-+
     * |Cl0|  -  |CoS0 |
     * +-+-+-+-+-+-+-+-+
     * |Cl1|  -  |CoS1 |
     * +-+-+-+-+-+-+-+-+
     * |Cl2|  -  |CoS2 |
     * +-+-+-+-+-+-+-+-+
     * |Cl3|  -  |CoS3 |
     * +-+-+-+-+-+-+-+-+
     * |  PHB0 |  PHB1 |
     * +-+-+-+-+-+-+-+-+
     * |  PHB2 |  PHB3 |
     * +-+-+-+-+-+-+-+-+
     * </pre>
     */

    for (i = 0; i < 4; i++)
    {
        /* Clear data structure. */
        memset(&resp, 0, sizeof(resp));
        
        address = svc_prio_decoding_ref * 4 + i + PRIO_REGEN_INGRESS_ADDR;
        if (address >= (PRIO_REGEN_INGRESS_ADDR + PRIO_REGEN_INGRESS_SIZE))
            return -EINVAL;
        
        *((uint8_t*)&resp.cl_cos_0) = table->decoded_pcp[i * 4].tm_cos |
            (table->decoded_pcp[i * 4].tm_drop_precedence << 6);
        *((uint8_t*)&resp.cl_cos_1) = table->decoded_pcp[(i * 4) + 1].tm_cos |
            (table->decoded_pcp[(i * 4) + 1].tm_drop_precedence << 6);
        *((uint8_t*)&resp.cl_cos_2) = table->decoded_pcp[(i * 4) + 2].tm_cos |
            (table->decoded_pcp[(i * 4) + 2].tm_drop_precedence << 6);
        *((uint8_t*)&resp.cl_cos_3) = table->decoded_pcp[(i * 4) + 3].tm_cos |
            (table->decoded_pcp[(i * 4) + 3].tm_drop_precedence << 6);
       

        resp.phb_0 = table->decoded_pcp[i * 4].marking_phb;
        resp.phb_1 = table->decoded_pcp[(i * 4) + 1].marking_phb;
        resp.phb_2 = table->decoded_pcp[(i * 4) + 2].marking_phb;
        resp.phb_3 = table->decoded_pcp[(i * 4) + 3].marking_phb;

        const char * prio_regen_ingress_resp_conv = PRIO_REGEN_INGRESS_RESP;
        CONVERT_ENDIAN(prio_regen_ingress_resp, &resp);
    
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

    /* Ignore number of messages remaining */
    if (ret > 0)
        ret = 0;
    
 out:

    return ret;
}

int xel_svc_set_pcp_encoding(uint8_t xid,
                             uint16_t pcp_encoding_ref,
                             struct xel_pcp_encoding_table* table)
{
    uint16_t address_1;
    uint16_t address_2;
    struct pcp_encoding_resp resp_1;
    struct pcp_encoding_resp resp_2;
    uint8_t i;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;

    /* Clear data structure. */
    memset(&resp_1, 0, sizeof(resp_1));
    memset(&resp_2, 0, sizeof(resp_2));

    /* The 16 entries of the PCP encoding table stretches two consecutive addresses*/
    /* Address = PcpEncodingTblAddr + (PCPEncodingRef * 16 + MarkingPHB) / 8 */
    address_1 = PCP_ENCODING_ADDR + (pcp_encoding_ref * 2);
    address_2 = address_1 + 1;
    if ((address_1 >= (PCP_ENCODING_ADDR + PCP_ENCODING_SIZE)) ||
        (address_2 >= (PCP_ENCODING_ADDR + PCP_ENCODING_SIZE)))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* 
     * There are 8 groups with 4 bits, DE 1 bit | Prio 3 bits on each address.
     *
     *  5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Prio |D|Prio |D|Prio |D|Prio |D|  A   prio[2] = 0
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     * |Prio |D|Prio |D|Prio |D|Prio |D|  B   prio[2] = 1
     * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *  prio[1:0] =
     *    0       1       2       3
     */
    for (i = 0; i < 4; i++)
    {
        resp_1.pcp_de_a |= (table->encoded_pcp[i].prio     << (13-(i*4)));
        resp_1.pcp_de_a |= (table->encoded_pcp[i].de       << (12-(i*4)));

        resp_1.pcp_de_b |= (table->encoded_pcp[i+4].prio   << (13-(i*4)));
        resp_1.pcp_de_b |= (table->encoded_pcp[i+4].de     << (12-(i*4)));

        resp_2.pcp_de_a |= (table->encoded_pcp[i+8].prio   << (13-(i*4)));
        resp_2.pcp_de_a |= (table->encoded_pcp[i+8].de     << (12-(i*4)));

        resp_2.pcp_de_b |= (table->encoded_pcp[i+8+4].prio << (13-(i*4)));
        resp_2.pcp_de_b |= (table->encoded_pcp[i+8+4].de   << (12-(i*4)));
    }

    const char * pcp_encoding_resp_conv = PCP_ENCODING_RESP;
    CONVERT_ENDIAN(pcp_encoding_resp, &resp_1);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE2;
    xcm.Addr = htonl(address_1);
    xcm.ReqCode = SRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address_1);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp_1), &resp_1);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }
    
    CONVERT_ENDIAN(pcp_encoding_resp, &resp_2);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE2;
    xcm.Addr = htonl(address_2);
    xcm.ReqCode = SRAM2_Write64;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address_2);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(resp_2), &resp_2);
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

uint32_t XEL_PCPDecodingCreate(struct X_PCPDecodingTable* rsTable)
{
    return(xel_svc_create_pcp_decoding_tbl((struct xel_pcp_decoding_table*)rsTable));
}

int XEL_SVCPrioDecodingSet(uint8_t iXid, 
                           uint16_t rqSVCPrioDecodingRef,
                           struct X_SVCPrioDecodingTable* rsTable)
{
    return(xel_svc_set_prio_decoding(iXid, rqSVCPrioDecodingRef, (struct xel_svc_prio_decoding_table*)rsTable));
}

int XEL_PCPEncodingSet(uint8_t iXid, 
                       uint16_t rqPCPEncodingRef,
                       struct X_PCPEncodingTable* rsTable)
{
    return(xel_svc_set_pcp_encoding(iXid, rqPCPEncodingRef, (struct xel_pcp_encoding_table*)rsTable));
}
