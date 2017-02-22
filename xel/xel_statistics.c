/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_statistics.c,v $
 * $Revision: 1.23 $
 * 
 * \file xel_statistics.c
 * \brief Ethernet bridge management API
 * 
 * Description:
 * API for managing ethernet bridge tables.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>
#include <byteswap.h>

#include "drv_driver.h"
#include "xel_statistics.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "xel_endian.h"
#include "memory.h"

#include "dot_counter.h" 
#include "engine_operations.h"

extern const uint16_t counter_address[X_STAT_COUNTER_SIZE][2];
#define INVALID_COUNTER_ADDR 0xdead

#define XCM_COUNTER_SUID             0
#define XCM_READ_COUNTER_REQ_CODE    1
#define XCM_WRITE_COUNTER_REQ_CODE   2

#define STAT_INVAL                   -1

static const int counter_xcm_data[X_STAT_COUNTER_SIZE][3] =
{
    {SUID_SE0,    SRAM0_Read64,  SRAM0_Write64},   /* X_IF_HC_IN_UCAST_PACKET                        */
    {SUID_SE3,    SRAM3_Read64,  SRAM3_Write64},   /* X_IF_HC_IN_OCTETS                              */
    {SUID_SE0,    SRAM0_Read64,  SRAM0_Write64},   /* X_IF_HC_IN_DISCARDS                            */
    {SUID_SE4,    SRAM4_Read64,  SRAM4_Write64},   /* X_IF_HC_OUT_OCTETS                             */
    {SUID_SE2,    SRAM2_Read64,  SRAM2_Write64},   /* X_IF_HC_OUT_UCAST_PACKET                       */
    {SUID_SE2,    SRAM2_Read64,  SRAM2_Write64},   /* X_IF_HC_OUT_MULTICAST_PACKET                   */
    {SUID_SE4,    SRAM4_Read64,  SRAM4_Write64},   /* X_DOT_1Q_TP_VLAN_PORT_HC_IN_DISCARDS           */
    {SUID_SE4,    SRAM4_Read64,  SRAM4_Write64},   /* X_DOT_1Q_TP_VLAN_PORT_HC_OUT_DISCARDS          */
    {SUID_SE1,    SRAM1_Read64,  SRAM1_Write64},   /* X_DOT_1Q_TP_VLAN_PORT_HC_IN_FRAMES             */
    {SUID_SE1,    SRAM1_Read64,  SRAM1_Write64},   /* X_DOT_1D_TP_HC_PORT_OUT_FRAMES                 */
    {SUID_SE0,    SRAM0_Read64,  SRAM0_Write64},   /* X_MPLS_IN_SEGMENT_PERF_HC_COUNT_1              */ 
    {STAT_INVAL,  STAT_INVAL,    STAT_INVAL},
    {SUID_SE2,    SRAM2_Read64,  SRAM2_Write64},   /* X_MPLS_IN_SEGMENT_PERF_HC_COUNT_2              */
    {STAT_INVAL,  STAT_INVAL,    STAT_INVAL},
    {SUID_SE0,    SRAM0_Read64,  SRAM0_Write64},   /* X_MPLS_INTERFACE_PERF_IN_LABEL_LOOKUP_FAILURES */
    {SUID_SE1,    SRAM1_Read64,  SRAM1_Write64},   /* X_MPLS_OUT_SEGMENT_PERF_HC_COUNT_1             */
    {STAT_INVAL,  STAT_INVAL,    STAT_INVAL},
    {SUID_SE1,    SRAM1_Read64,  SRAM1_Write64},   /* X_MPLS_OUT_SEGMENT_PERF_HC_COUNT_2             */
    {STAT_INVAL,  STAT_INVAL,    STAT_INVAL},
    {SUID_SE3,    SRAM3_Read64,  SRAM3_Write64},   /* X_FLOOD_COUNTER_PKT                            */       
    {SUID_SE4,    SRAM4_Read64,  SRAM4_Write64},   /* X_PORT_IN_PACKET_DISCARD_COUNTER               */           
    {SUID_SE4,    SRAM4_Read64,  SRAM4_Write64},   /* X_PORT_OUT_PACKET_DISCARD_COUNTER              */         
    {SUID_SE0,    SRAM0_Read64,  SRAM0_Write64},   /* X_IP_IN_RECEIVES_COUNTER                       */             
    {SUID_SE3,    SRAM3_Read64,  SRAM3_Write64}    /* X_IP_IN_HDR_ERRORS_COUNTER                     */              
};

/*
 * 
 */
int64_t read_counter(uint8_t               xid,                        
                     enum xel_stat_counter counter_id,
                     uint16_t              address)
{
    uint64_t  value           = 0;
    int64_t   ret             = 0;
    msgprof_t profile         = 0;
    msgflow_t flow            = NULL;
    uint16_t  length          = 0;

    struct XCM_Header xcm;

    profile     = drv_get_profile(xid, DRV_PROF_0);

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID    = counter_xcm_data[counter_id][XCM_COUNTER_SUID];
    xcm.ReqCode = counter_xcm_data[counter_id][XCM_READ_COUNTER_REQ_CODE];
    xcm.UID     = drv_get_uid(xid, xcm.SUID, address);
    xcm.RW      = XCM_READ;
    xcm.Addr    = htonl(address);

    ret = msgflow_cm_open(drv_get_msgctl_hndl(xid), NULL, 1, &flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(uint64_t), &value);
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

    ret = msgflow_receive(flow, &value, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        

    value = BSWAP64(value);
    
 out:
    if (flow != NULL)
    {
        int rc = 0;
        rc = msgflow_close(flow);
        if (rc < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), rc);
            value = rc;
        }
    }
    
    return value;
}

/*
 *
 */
int clear_counter(uint8_t               xid, 
                  enum xel_stat_counter counter_id, 
                  uint16_t              address)
{
    int       ret            = 0;
    uint64_t  counter_value  = 0;
    msgprof_t profile        = 0;
    msgflow_t flow           = drv_get_flow(xid);

    struct XCM_Header xcm;

    profile     = drv_get_profile(xid, DRV_PROF_0);

    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID    = counter_xcm_data[counter_id][XCM_COUNTER_SUID];
    xcm.ReqCode = counter_xcm_data[counter_id][XCM_WRITE_COUNTER_REQ_CODE];
    xcm.UID     = drv_get_uid(xid, xcm.SUID, address);
    xcm.RW      = XCM_WRITE;
    xcm.Addr    = htonl(address);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(counter_value), &counter_value);
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

int64_t xel_get_statistics(uint8_t                xid,
                           enum xel_stat_counter  stat,
                           uint32_t               index)
{
    uint16_t address   = 0;
    uint8_t  per_port  = 0;

    if ( stat >= X_STAT_COUNTER_SIZE )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    } 
    
    address = counter_address[stat][0];

    if (address == INVALID_COUNTER_ADDR)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -ENOSYS);
        return -ENOSYS; 
    }

    per_port  = counter_address[stat][1];

    /* Mapping for tri-speed ethernet ports: */
    if (per_port && (index > 48)) return -EINVAL;

    address += index;

    return read_counter(xid, stat, address);
}

/*
 *
 */
int xel_clear_statistics(uint8_t               xid,
                         enum xel_stat_counter stat,
                         uint32_t              index)

{
    uint16_t address    = 0;
    uint8_t  per_port   = 0;
    
    if (stat >= X_STAT_COUNTER_SIZE)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL; 
    }

    address = counter_address[stat][0];

    if (address == INVALID_COUNTER_ADDR)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -ENOSYS);
        return -ENOSYS; 
    }

    per_port = counter_address[stat][1];

    /* Mapping for tri-speed ethernet ports: */
    if ( per_port && (index > 48) ) 
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    address += index;

    return clear_counter(xid, stat, address);
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

/*
 *
 */
int64_t XEL_ReadCounter(uint8_t iXid, uint16_t iAddress)
{
    return -ENOSYS;
}

/*
 *
 */
int XEL_ClearCounter(uint8_t iXid, uint16_t iAddress)
{
    return -ENOSYS;
}

/*
 *
 */
int XEL_StatisticsGet(uint8_t            iXid,
                      enum X_StatCounter iStat,
                      uint32_t           iIndex,
                      uint64_t*          oValue)
{
  int64_t ret = 0;

  if (oValue == 0) return -EINVAL;
 
  ret = xel_get_statistics(iXid, iStat, iIndex);

  if (ret < 0) return ret;

  *oValue = ret;
  return 0;
}

/*
 *
 */
int XEL_StatisticsClear(uint8_t            iXid,
                        enum X_StatCounter iStat,
                        uint32_t           iIndex)
{
  return xel_clear_statistics(iXid, iStat, iIndex);
}

