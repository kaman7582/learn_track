/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_meter.c,v $
 * $Revision: 1.40 $
 *
 * \file  xel_meter.c
 * \brief Meter API
 *
 * Description:
 * API for managing meters in LA attached SRAM or internal SRAM. Consult
 * "Using internal and external SRAM" for further information.
 *--------------------------------------------------------------------------*/

#include <netinet/in.h>
#include <errno.h>

#include "drv_driver.h"
#include "xel_meter.h"
#include "EAP.h"
#include "lws.h"
#include "class_meter.h"
#include "memory.h"
#include "color_counter.h"
#include "engine_operations.h"
#include "xel_endian.h"
#include "msgflow.h"
#include "msgflow_cm.h"
#include "msgflow_ctrl.h"
#include "fpa_endian_conv_strings.h"

static void meter_compute(struct xel_meter_rate* meter,
                          struct xel_meter_param* meter_param,
                          uint32_t freq)
{
    uint32_t burst;
    uint16_t burst_mant;
    uint8_t burst_exp;
    uint8_t divisor;
    uint64_t rate_mant;
    uint8_t rate_exp;
    uint64_t rate;
    int found;

    /* burst_size = burst_mantissa * (2 ^ burst_exponent) bytes */

    found = 0;
    burst_exp = 0;

    while (!found && (burst_exp < 16))
    {
        burst_mant = 0xffff;
        burst = burst_mant * (1 << burst_exp);

        if (burst >= meter->burst_size)
        {
            while (!found && (burst_mant > 0))
            {
                --burst_mant;

                burst = burst_mant * (1 << burst_exp);

                if (burst < meter->burst_size)
                {
                    found = 1;
                    meter_param->burst_mant = burst_mant + 1;
                    meter_param->burst_exp = burst_exp;
                }
            }
        }
        else
        {
            burst_exp++;
        }
    }

    /* rate = (frequency / divisor) * rate_mantissa * (2 ^ (rate_exponent - 22)) bps */
    found = 0;
    divisor = 2; /* When PRESCALE = 0 */
    rate_exp = 0;
    
    while (!found && (rate_exp < 16))
    {
        rate_mant = 0xffff;
        rate = (((freq / divisor) * rate_mant) / (1 << (22 - rate_exp)));

        if ((rate / 1000) >= meter->information_rate)
        {
            while (!found && (rate_mant > 0))
            {
                --rate_mant;
                rate = (((freq / divisor) * rate_mant) / (1 << (22 - rate_exp)));
                if ((rate / 1000) < meter->information_rate)
                {
                    found = 1;
                    meter_param->rate_mant = rate_mant + 1;
                    meter_param->rate_exp = rate_exp;
                }
            }
        }
        else
        {
            rate_exp++;
        }
    }
}

int xel_meter_clear_stat(uint8_t xid,
                         uint32_t meter_index)
{
    uint64_t counter = 0;
    int ret = 0;
    uint32_t cnt_addr;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    int i;

    cnt_addr = meter_index * 4 + COLOR_COUNTER_ADDR;
    if (cnt_addr >= (COLOR_COUNTER_ADDR + COLOR_COUNTER_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    profile = drv_get_profile(xid, DRV_PROF_0);

    for (i = 0; i < 4; i++)
    {
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS1;
        xcm.ReqCode = LASRAM1_Write64;
        xcm.RW = XCM_WRITE;
        xcm.Addr = htonl(cnt_addr + i);
        xcm.UID = drv_get_uid(xid, xcm.SUID, cnt_addr + i);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(counter), &counter);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
    }

    /* Flush all messages. */
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


int xel_meter_compute_two_rate(uint8_t xid,
                               struct xel_meter_rate* meter_1,
                               struct xel_meter_param* meter_param_1,                               
                               struct xel_meter_rate* meter_2,
                               struct xel_meter_param* meter_param_2)
{
    int res = 0;

    if ( (meter_1 == 0) ||
         (meter_2 == 0) ||
         (meter_1->burst_size == 0) ||
         (meter_2->burst_size == 0) ||
         (meter_1->information_rate == 0) ||
         (meter_2->information_rate == 0) )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Check allowed range. */
    if ((meter_1->information_rate < 1) || (meter_2->information_rate < 1) ||
        (meter_1->information_rate > 0x8800000) || (meter_2->information_rate > 0x8800000) ||
        (meter_1->burst_size < 0x4000) || (meter_2->burst_size < 0x4000) ||
        (meter_1->burst_size > 0x4000000) || (meter_2->burst_size > 0x4000000))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EOVERFLOW);
        return -EOVERFLOW;
    }

    meter_compute(meter_1, meter_param_1, XTC_CF10);
    meter_compute(meter_2, meter_param_2, XTC_CF10);

    return res;
}
    

int xel_meter_set(uint8_t xid,
                  uint32_t meter_index,
                  struct xel_meter_profile* meter_profile_1,
                  struct xel_meter_rate* meter_1,
                  struct xel_meter_profile* meter_profile_2,
                  struct xel_meter_rate* meter_2)
{
    struct xel_meter_param meter_param_1;
    struct xel_meter_param meter_param_2;
    int res;
    uint32_t meter_addr;

    if ( (meter_1 == 0) ||
         (meter_2 == 0) ||
         (meter_profile_1 == 0) ||
         (meter_profile_2 == 0) ||
         (meter_1->burst_size == 0) ||
         (meter_2->burst_size == 0) ||
         (meter_1->information_rate == 0) ||
         (meter_2->information_rate == 0) )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    /* Check allowed range. */
    if ((meter_1->information_rate < 1) || (meter_2->information_rate < 1) ||
        (meter_1->information_rate > 0x8800000) || (meter_2->information_rate > 0x8800000) ||
        (meter_1->burst_size < 0x4000) || (meter_2->burst_size < 0x4000) ||
        (meter_1->burst_size > 0x4000000) || (meter_2->burst_size > 0x4000000))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EOVERFLOW);
        return -EOVERFLOW;
    }

    res = xel_meter_clear_stat(xid, meter_index);
    meter_addr = meter_index * 2;

    if(res) return res;

    meter_compute(meter_1, &meter_param_1, XTC_CF10);

    meter_compute(meter_2, &meter_param_2, XTC_CF10);

    return xel_meter_set_two_rate(xid, meter_addr,
                                  meter_profile_1, &meter_param_1,
                                  meter_profile_2, &meter_param_2);
}

int xel_meter_get_stat(uint8_t xid,
                       uint32_t meter_index,
                       struct xel_meter_stat* meter_stat)
{
    int ret = 0;
    struct color_counter_resp counter;
    uint32_t cnt_addr;
    struct XCM_Header xcm;
    msgflow_t flow = NULL;
    msgprof_t profile;
    int i;
    uint16_t length;

    if (!meter_stat)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    memset((void *)meter_stat, 0, sizeof(struct xel_meter_stat));

    cnt_addr = meter_index * 4 + COLOR_COUNTER_ADDR;
    if (cnt_addr >= (COLOR_COUNTER_ADDR + COLOR_COUNTER_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_cm_open(drv_get_msgctl_hndl(xid), NULL, 4, &flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    for (i = 0; i < 4; i++)
    {
        memset(&xcm, 0, sizeof(struct XCM_Header));
        xcm.SUID = SUID_LAS1;
        xcm.ReqCode = LASRAM1_Read64;
        xcm.RW = XCM_READ;
        xcm.Addr = htonl(cnt_addr + i);
        xcm.UID = drv_get_uid(xid, xcm.SUID, cnt_addr + i);

        ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(counter), &counter);
        if (ret < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
            goto out;
        }
    }

    /* Flush all messages. */
    ret = msgflow_flush(flow);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }        

    /* Deny */
    ret = msgflow_receive(flow, &counter, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    const char* color_counter_resp_conv = COLOR_COUNTER_RESP;
    CONVERT_ENDIAN(color_counter_resp, &counter);

    meter_stat->deny_packets = counter.data_0 >> (32 - 29);
    meter_stat->deny_octets = ((uint64_t)(counter.data_0 & 0x7) << 32) | counter.data_1; 

    /* Green */
    ret = msgflow_receive(flow, &counter, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    CONVERT_ENDIAN(color_counter_resp, &counter);

    meter_stat->green_packets = counter.data_0 >> (32 - 29);
    meter_stat->green_octets = ((uint64_t)(counter.data_0 & 0x7) << 32) | counter.data_1; 

    /* Yellow */
    ret = msgflow_receive(flow, &counter, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    CONVERT_ENDIAN(color_counter_resp, &counter);

    meter_stat->yellow_packets = counter.data_0 >> (32 - 29);
    meter_stat->yellow_octets = ((uint64_t)(counter.data_0 & 0x7) << 32) | counter.data_1; 

    /* Red */
    ret = msgflow_receive(flow, &counter, &length);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    CONVERT_ENDIAN(color_counter_resp, &counter);

    if (ret > 0)
        ret = 0;

    meter_stat->red_packets = counter.data_0 >> (32 - 29);
    meter_stat->red_octets = ((uint64_t)(counter.data_0 & 0x7) << 32) | counter.data_1; 
    
 out:
    if (flow != NULL)
    {
        int rc = 0;
        rc = drv_msgflow_close(flow);
        if (rc < 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), rc);
            ret = rc;
        }
    }
    
    return ret;
}

int xel_meter_set_two_rate(uint8_t xid,
                           uint32_t meter_address,
                           struct xel_meter_profile* meter_profile_1,
                           struct xel_meter_param* meter_param_1,
                           struct xel_meter_profile* meter_profile_2,
                           struct xel_meter_param* meter_param_2)
{
    struct meter_config meter;
    uint32_t address;
    uint32_t cnt_address;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    struct EAP_LAS_Conf_R_CommitRate0 com_rate_prof;
    struct EAP_LAS_Conf_R_CommitBucket0 com_burst_prof;
    struct EAP_LAS_Conf_R_ExcessRate0 exc_rate_prof;
    struct EAP_LAS_Conf_R_ExcessBucket0 exc_burst_prof;

    memset(&com_rate_prof, 0, sizeof(struct EAP_LAS_Conf_R_CommitRate0));
    memset(&com_burst_prof, 0, sizeof(struct EAP_LAS_Conf_R_CommitBucket0));
    memset(&exc_rate_prof, 0, sizeof(struct EAP_LAS_Conf_R_ExcessRate0));
    memset(&exc_burst_prof, 0, sizeof(struct EAP_LAS_Conf_R_ExcessBucket0));
    
    if ( (meter_param_1 == 0) ||
         (meter_param_2 == 0) ||
         (meter_profile_1 == 0) ||
         (meter_profile_2 == 0) )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    /* Counter address = meter index * 4. Meter address = meter index * 2.
       Counter address = meter_address * 2. */
    cnt_address = meter_address * 2;
    if (cnt_address >= (COLOR_COUNTER_ADDR + COLOR_COUNTER_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    address = meter_address + CLASS_METER_ADDR;
    if (address >= (CLASS_METER_ADDR + CLASS_METER_SIZE))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    profile = drv_get_profile(xid, DRV_PROF_0);

    /* Profile config. */
    com_rate_prof.RateMant = meter_param_1->rate_mant;
    com_rate_prof.RateExp = meter_param_1->rate_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].LAS[LAS_1].Conf.R_CommitRate0,
                             meter_profile_1->rate_profile, &com_rate_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    com_burst_prof.BurstMant = meter_param_1->burst_mant;
    com_burst_prof.BurstExp = meter_param_1->burst_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].LAS[LAS_1].Conf.R_CommitBucket0,
                             meter_profile_1->burst_profile, &com_burst_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    exc_rate_prof.RateMant = meter_param_2->rate_mant;
    exc_rate_prof.RateExp = meter_param_2->rate_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].LAS[LAS_1].Conf.R_ExcessRate0,
                             meter_profile_2->rate_profile, &exc_rate_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    exc_burst_prof.BurstMant = meter_param_2->burst_mant;
    exc_burst_prof.BurstExp = meter_param_2->burst_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].LAS[LAS_1].Conf.R_ExcessBucket0,
                             meter_profile_2->burst_profile, &exc_burst_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    /* Meter config. */
    memset(&meter, 0, sizeof(meter));

    meter.exc_burst_ptr = meter_profile_2->burst_profile;
    meter.exc_rate_ptr = meter_profile_2->rate_profile;
    meter.com_burst_ptr = meter_profile_1->burst_profile;
    meter.com_rate_ptr = meter_profile_1->rate_profile;

    /* Set start levels to requested burst size. If burst size is min allowed (0x4000)
       then set start level to 0 (for simulator). */
    if ((meter_param_2->burst_mant == 0x4000) && (meter_param_2->burst_exp == 0))
    {
        meter.excess_level = 0;
    }
    else
    {
        meter.excess_level = meter_param_2->burst_mant * (1 << meter_param_2->burst_exp);
    }
    if ((meter_param_1->burst_mant == 0x4000) && (meter_param_1->burst_exp == 0))
    {
        meter.commit_level = 0;
    }
    else
    {
        meter.commit_level = meter_param_1->burst_mant * (1 << meter_param_1->burst_exp);
    }
    
    const char * meter_config_conv = "wwwhh";

    CONVERT_ENDIAN(meter_config, &meter);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_LAS1;
    xcm.Addr = htonl(address);
    xcm.ReqCode = LASRAM1_Write128;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(meter), &meter);
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

int xel_imeter_set_two_rate(uint8_t xid,
                            uint32_t meter_address,
                            struct xel_meter_profile* meter_profile_1,
                            struct xel_meter_param* meter_param_1,
                            struct xel_meter_profile* meter_profile_2,
                            struct xel_meter_param* meter_param_2)
{
    struct meter_config meter;
    uint32_t address;
    int ret = 0;
    struct XCM_Header xcm;
    msgflow_t flow = drv_get_flow(xid);
    msgprof_t profile;
    struct EAP_SE_Conf_R_CommitRate1 com_rate_prof;
    struct EAP_SE_Conf_R_CommitBucket1 com_burst_prof;
    struct EAP_SE_Conf_R_ExcessRater1 exc_rate_prof;
    struct EAP_SE_Conf_R_ExcessBucket1 exc_burst_prof;

    memset(&com_rate_prof, 0, sizeof(struct EAP_SE_Conf_R_CommitRate1));
    memset(&com_burst_prof, 0, sizeof(struct EAP_SE_Conf_R_CommitBucket1));
    memset(&exc_rate_prof, 0, sizeof(struct EAP_SE_Conf_R_ExcessRater1));
    memset(&exc_burst_prof, 0, sizeof(struct EAP_SE_Conf_R_ExcessBucket1));
    
    if ( (meter_param_1 == 0) ||
         (meter_param_2 == 0) ||
         (meter_profile_1 == 0) ||
         (meter_profile_2 == 0) )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    
    address = meter_address;
    /* Only every second address can be used (128 bit entry). */
    if ((address & 1) == 1)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }

    profile = drv_get_profile(xid, DRV_PROF_0);

    /* Profile config. */
    com_rate_prof.RateMant = meter_param_1->rate_mant;
    com_rate_prof.RateExp = meter_param_1->rate_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].SE[SE_5].Conf.R_CommitRate1,
                             meter_profile_1->rate_profile, &com_rate_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    com_burst_prof.BurstMant = meter_param_1->burst_mant;
    com_burst_prof.BurstExp = meter_param_1->burst_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].SE[SE_5].Conf.R_CommitBucket1,
                             meter_profile_1->burst_profile, &com_burst_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    exc_rate_prof.RateMant = meter_param_2->rate_mant;
    exc_rate_prof.RateExp = meter_param_2->rate_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].SE[SE_5].Conf.R_ExcessRater1,
                             meter_profile_2->rate_profile, &exc_rate_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    exc_burst_prof.BurstMant = meter_param_2->burst_mant;
    exc_burst_prof.BurstExp = meter_param_2->burst_exp;
    ret = msgflow_send_write(flow, profile, EAP[0].SE[SE_5].Conf.R_ExcessBucket1,
                             meter_profile_2->burst_profile, &exc_burst_prof);
    if (ret < 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        goto out;
    }

    /* Meter config. */
    memset(&meter, 0, sizeof(meter));

    meter.exc_burst_ptr = meter_profile_2->burst_profile;
    meter.exc_rate_ptr = meter_profile_2->rate_profile;
    meter.com_burst_ptr = meter_profile_1->burst_profile;
    meter.com_rate_ptr = meter_profile_1->rate_profile;

    /* Set start levels to requested burst size. If burst size is min allowed (0x4000)
       then set start level to 0 (for simulator). */
    if ((meter_param_2->burst_mant == 0x4000) && (meter_param_2->burst_exp == 0))
    {
        meter.excess_level = 0;
    }
    else
    {
        meter.excess_level = meter_param_2->burst_mant * (1 << meter_param_2->burst_exp);
    }
    if ((meter_param_1->burst_mant == 0x4000) && (meter_param_1->burst_exp == 0))
    {
        meter.commit_level = 0;
    }
    else
    {
        meter.commit_level = meter_param_1->burst_mant * (1 << meter_param_1->burst_exp);
    }
    
    const char * meter_config_conv = "wwwhh";

    CONVERT_ENDIAN(meter_config, &meter);
    
    memset(&xcm, 0, sizeof(struct XCM_Header));
    xcm.SUID = SUID_SE5;
    xcm.Addr = htonl(address);
    xcm.ReqCode = SRAM5_Write128;
    xcm.RW = XCM_WRITE;
    xcm.UID = drv_get_uid(xid, xcm.SUID, address);
    profile = drv_get_profile(xid, DRV_PROF_0);

    ret = msgflow_send_xcm(flow, profile, &xcm, sizeof(meter), &meter);
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

int xel_imeter_set(uint8_t xid,
                   uint32_t meter_address,
                   struct xel_meter_profile* meter_profile_1,
                   struct xel_meter_rate* meter_1,
                   struct xel_meter_profile* meter_profile_2,
                   struct xel_meter_rate* meter_2)
{
    struct xel_meter_param meter_param_1;
    struct xel_meter_param meter_param_2;

    if ( (meter_1 == 0) ||
         (meter_2 == 0) ||
         (meter_profile_1 == 0) ||
         (meter_profile_2 == 0) ||
         (meter_1->burst_size == 0) ||
         (meter_2->burst_size == 0) ||
         (meter_1->information_rate == 0) ||
         (meter_2->information_rate == 0) )
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EINVAL);
        return -EINVAL;
    }
    /* Check allowed range. */
    if ((meter_1->information_rate < 1) || (meter_2->information_rate < 1) ||
        (meter_1->information_rate > 0x8800000) || (meter_2->information_rate > 0x8800000) ||
        (meter_1->burst_size < 0x4000) || (meter_2->burst_size < 0x4000) ||
        (meter_1->burst_size > 0x4000000) || (meter_2->burst_size > 0x4000000))
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), -EOVERFLOW);
        return -EOVERFLOW;
    }
    
    meter_compute(meter_1, &meter_param_1, XTC_CF31);

    meter_compute(meter_2, &meter_param_2, XTC_CF31);

    return xel_imeter_set_two_rate(xid, meter_address,
                                   meter_profile_1, &meter_param_1,
                                   meter_profile_2, &meter_param_2);
}

/*----------------------------------------------------------------------------
 * For backward compatibility.
 *--------------------------------------------------------------------------*/

int XEL_MeterStatClear(uint8_t           iXid,
                       uint32_t          iMeterIndex)
{
    return(xel_meter_clear_stat(iXid, iMeterIndex));
}

int XEL_MeterSet(uint8_t          iXid, 
                 uint32_t         iMeterIndex,
                 struct X_MeterRate* iMeter1,
                 struct X_MeterRate* iMeter2)
{
    struct xel_meter_profile prof;

    prof.burst_profile = 0;
    prof.rate_profile = 0;

    if ( ((struct xel_meter_rate*)iMeter1)->burst_size < 0x4000 )
    {
        ((struct xel_meter_rate*)iMeter1)->burst_size = 0x4000;
    }

    if ( ((struct xel_meter_rate*)iMeter1)->information_rate == 0 )
    {
        ((struct xel_meter_rate*)iMeter1)->information_rate = 1;
    }

    if ( ((struct xel_meter_rate*)iMeter2)->burst_size < 0x4000 )
    {
        ((struct xel_meter_rate*)iMeter2)->burst_size = 0x4000;
    }

    if ( ((struct xel_meter_rate*)iMeter2)->information_rate == 0 )
    {
        ((struct xel_meter_rate*)iMeter2)->information_rate = 1;
    }
    
    return(xel_meter_set(iXid, iMeterIndex,
                         &prof, 
                         (struct xel_meter_rate*)iMeter1,
                         &prof,
                         (struct xel_meter_rate*)iMeter2));
}

int XEL_MeterStatGet(uint8_t           iXid,
                     uint32_t          iMeterIndex,
                     struct X_MeterStat* oMeterStat)
{
    return(xel_meter_get_stat(iXid, iMeterIndex, oMeterStat));
}

int XEL_IMeterSet(uint8_t              iXid, 
                  uint16_t             iMeterAddr,
                  uint8_t              iConfigAddr,
                  struct X_IMeterRate* ioMeter1,
                  struct X_IMeterRate* ioMeter2)
{
    struct xel_meter_profile profile;

    profile.burst_profile = iConfigAddr;
    profile.rate_profile = iConfigAddr;

    if ( ((struct xel_meter_rate*)ioMeter1)->burst_size < 0x4000 )
    {
        ((struct xel_meter_rate*)ioMeter1)->burst_size = 0x4000;
    }

    if ( ((struct xel_meter_rate*)ioMeter1)->information_rate == 0 )
    {
        ((struct xel_meter_rate*)ioMeter1)->information_rate = 1;
    }

    if ( ((struct xel_meter_rate*)ioMeter2)->burst_size < 0x4000 )
    {
        ((struct xel_meter_rate*)ioMeter2)->burst_size = 0x4000;
    }

    if ( ((struct xel_meter_rate*)ioMeter2)->information_rate == 0 )
    {
        ((struct xel_meter_rate*)ioMeter2)->information_rate = 1;
    }

    return(xel_imeter_set(iXid, iMeterAddr, &profile, 
                          (struct xel_meter_rate*)ioMeter1,
                          &profile,
                          (struct xel_meter_rate*)ioMeter2));
}

int XEL_IMeterSetRealTime(uint8_t iXid, 
                          uint8_t iAddr,
                          uint16_t iDivisor, 
                          uint8_t  iQuantum)
{
    return -ENOSYS;
}

int XEL_IMeterSetMaxBurst(uint8_t iXid, 
                          uint8_t iAddr,
                          uint32_t iMaxBurstSize)
{
    return -ENOSYS;
}

int XEL_IMeterSetSingle(uint8_t  iXid, 
                        uint16_t iMeterAddr,
                        struct X_IMeterParam *iMeter)
{
    return -ENOSYS;
}

