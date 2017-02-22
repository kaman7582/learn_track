/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_slowpath.c,v $
 * $Revision: 1.21 $
 * 
 * \file  xel_slowpath.c
 * \brief Application specific slow path API
 * 
 * Description:
 * API for slowpath traffic.
 *--------------------------------------------------------------------------*/

#include <stdint.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <byteswap.h>

#include "xel_slowpath.h"
#include "fpa_cpuheader.h"
#include "fpa_tc_config.h"
#include "drv_driver.h"
#include "xlog.h"
#include "xel_endian.h"
#include "msgatom.h"
#include "msgctl.h"
#include "msgflow.h"
#include "msgflow_sp.h"
#include "msgflow_ctrl.h"
#include "msgflow_conf.h"
#include "msgflow_direct.h"

int xel_slow_path_write(uint8_t  xid,
                        uint8_t  queue_sel,
                        uint16_t destination_id,
                        uint8_t* data,
                        uint16_t data_len)
{
    uint8_t   sp_queues[4]     = {FPATC_SPI_0, FPATC_SPI_1, FPATC_SPI_2, FPATC_SPI_3};
    int       ret              = 0;
    uint8_t*  buf              = NULL;
    uint16_t  dest_id          = 0;

    msgprof_t profile;
    uint16_t  queue;
    
    if ((!data) || (queue_sel >= 4))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* TODO: Remove this when test cases has been changed. */
	queue_sel = 0;
    
    queue = sp_queues[queue_sel];

    ret = msgprof_open(&profile);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }
    ret = msgprof_conf_qmap_direct(profile, queue, 1);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    dest_id = BSWAP16(destination_id);
    
    /* Prepend destination_id to data. */
    buf = malloc(data_len + sizeof(dest_id));
    if (buf == NULL)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -ENOMEM);
        return -ENOMEM;
    }

    
    /* Copy data and send */
    memcpy(buf, &dest_id, sizeof(dest_id));
    memcpy(buf + sizeof(dest_id), data, data_len);
    
    ret = msgatom_pkt(drv_get_msgctl_hndl(xid), profile, data_len + sizeof(dest_id), buf);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    ret = msgctl_flush_all(drv_get_msgctl_hndl(xid));
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

 out:
    if (buf != NULL)
        free(buf);
    
    return ret;
}

int xel_slow_path_read(uint8_t xid,
                       uint32_t tmo,
                       struct xel_slow_path_info* info,
                       uint8_t* data,
                       uint16_t* data_len)
{
    int ret = 0;
    uint16_t queue;
    msgflow_t flow = NULL;
    uint16_t length;
    uint8_t* buf = NULL;

    if ((!info) || (!data) || (!data_len))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    queue = FPATC_SPO_p0 - 512;

    buf = (uint8_t*)malloc(*data_len);
    if (buf == NULL)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -ENOMEM);
        return -ENOMEM;
    }

    ret = msgflow_sp_open(drv_get_msgctl_hndl(xid), NULL, &queue, 1, &flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    ret = msgflow_conf_timeout(flow, tmo);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    ret = msgflow_receive(flow, buf, &length);
    /* Message received */
    if (ret == 0)
    {
        struct np_cpu_header* head = (struct np_cpu_header*)buf;
        info->port_id = ntohs(head->port);
        info->reason = head->reason;
        info->svid = ntohs(head->svid);
        *data_len = length - sizeof(struct np_cpu_header);
        memcpy(data, buf + sizeof(struct np_cpu_header), *data_len);
    }
    else if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }
    
 out:
    if (flow != NULL)
    {
        int rc = 0;
        rc = drv_msgflow_close(flow);
        if (rc < 0)
        {
            ret = rc;
            XLOG_ERR(drv_get_xlog_hndl(xid), rc);
        }
    }
    if (buf != NULL)
        free(buf);
    
    return ret;
}


/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int
XEL_SlowPathWrite(uint8_t iXid, uint8_t iPrio,
                 uint16_t iDestinationID,
                 char* iData, uint16_t iDataLen)
{
    return(xel_slow_path_write(iXid, 0, iDestinationID, iData, iDataLen));
}

int
XEL_SlowPathRead(uint8_t iXid, uint8_t iPrio, struct X_SlowPathInfo* oInfo,
                 uint8_t** ioData, uint16_t* ioDataLen)
{
    int ret = 0;
    struct xel_slow_path_info info;
    
    ret = xel_slow_path_read(iXid, 15000, &info, *ioData, ioDataLen);
    if (ret < 0)
        return ret;
    oInfo->PortID = info.port_id;
    oInfo->Flags = 0;
    oInfo->Reason = info.reason;
    oInfo->SVID = info.svid;

    return ret;
}
