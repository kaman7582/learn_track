/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: init_app.c,v $
 * $Revision: 1.22 $
 * 
 * @file  init_app.c
 * @brief System initialization.
 * 
 *--------------------------------------------------------------------------*/
#include <stdio.h>

#include "memory.h"
#include "drv_driver.h"
#include "mem_nse.h"
#include "mem_tcam.h"
#include "mem_hash.h"
#ifdef RDK
#include "hxboot.h"
#include "hxdict.h"
#include "crkctl.h"
#include "crki2c.h"
#include "crkmnt.h"
#endif
#include "xel_macaddress.h"
#include "xel_portdecoding.h"
#include "xel_portencoding.h"
#include "xel_classification.h"
#include "xel_vidtranslation.h"
#include "xel_mac_class.h"
#include "xel_cpudest.h"

#include "xel_statistics.h"

/* Synchronize with enum xel_stat_counter in xel_statistics.h! */

#define INVALID_COUNTER_ADDR 0xdead

const uint16_t counter_address_bridging[X_STAT_COUNTER_SIZE][2] = 
{
    {INVALID_COUNTER_ADDR,              1},
    {IF_IN_OCTET_COUNTER_ADDR,          1},
    {INVALID_COUNTER_ADDR,              1},
    {IF_OUT_OCTET_COUNTER_ADDR,         1},
    {INVALID_COUNTER_ADDR,              1},
    {INVALID_COUNTER_ADDR,              1},
    {DOT_COUNTER_IN_DISCARDS_ADDR,      0},
    {DOT_COUNTER_OUT_DISCARDS_ADDR,     1}, 
    {DOT_COUNTER_IN_FRAMES_ADDR,        0},
    {DOT_COUNTER_OUT_FRAMES_ADDR,       0},
    {INVALID_COUNTER_ADDR,              0},
    {INVALID_COUNTER_ADDR,              0}, /* Obsolete X11 counter */
    {INVALID_COUNTER_ADDR,              0},
    {INVALID_COUNTER_ADDR,              0}, /* Obsolete X11 counter */
    {INVALID_COUNTER_ADDR,              1},
    {INVALID_COUNTER_ADDR,              0},
    {INVALID_COUNTER_ADDR,              0}, /* Obsolete X11 counter */
    {INVALID_COUNTER_ADDR,              0}, 
    {INVALID_COUNTER_ADDR,              0}, /* Obsolete X11 counter */
    {FLOOD_COUNTER_ADDR,                0},                   
    {PORT_COUNTER_IN_DISCARDS_ADDR,     1},               
    {PORT_COUNTER_OUT_DISCARDS_ADDR,    1},        
    {INVALID_COUNTER_ADDR,              1},           
    {INVALID_COUNTER_ADDR,              1}                 
};


int init_bridging_counters(uint8_t xid)
{
    uint32_t index = 0;
    int      ret   = 0;

    /* Flood counter */
    for (index = 0; index < FLOOD_COUNTER_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_FLOOD_COUNTER_PKT, index);

        if (ret != 0)
        {
            printf("init of flood counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Incoming frames counter */
    for (index = 0; index < DOT_COUNTER_IN_FRAMES_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_DOT_1Q_TP_VLAN_PORT_HC_IN_FRAMES, index);

        if (ret != 0)
        {
            printf("init of incoming frames counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Outgoing frames counter */
    for (index = 0; index < DOT_COUNTER_OUT_FRAMES_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_DOT_1D_TP_HC_PORT_OUT_FRAMES, index);

        if (ret != 0)
        {
            printf("init of outgoing frames counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Discarded (by filtering) incoming frames counter */
    for (index = 0; index < DOT_COUNTER_IN_DISCARDS_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_DOT_1Q_TP_VLAN_PORT_HC_IN_DISCARDS, index);

        if (ret != 0)
        {
            printf("init of discarded incoming frames counter failed with %d\n", ret);
            return ret;
        }  
    }


    /* Discarded (by filtering) outgoing frames counter */
    for (index = 0; index < DOT_COUNTER_OUT_DISCARDS_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_DOT_1Q_TP_VLAN_PORT_HC_OUT_DISCARDS, index);

        if (ret != 0)
        {
            printf("init of discarded outgoing frames counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Incoming octets counter */
    for (index = 0; index < IF_IN_OCTET_COUNTER_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_IF_HC_IN_OCTETS, index);

        if (ret != 0)
        {
            printf("init of incoming octets counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Outgoing octets counter */
    for (index = 0; index < IF_OUT_OCTET_COUNTER_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_IF_HC_OUT_OCTETS, index);

        if (ret != 0)
        {
            printf("init of outgoing octets counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Ingress drop counter */
    for (index = 0; index < PORT_COUNTER_IN_DISCARDS_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_PORT_IN_PACKET_DISCARD_COUNTER, index);

        if (ret != 0)
        {
            printf("init of ingress drop counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Egress drop counter */
    for (index = 0; index < PORT_COUNTER_OUT_DISCARDS_SIZE; index++) 
    {
        ret = xel_clear_statistics(xid, X_PORT_OUT_PACKET_DISCARD_COUNTER, index);

        if (ret != 0)
        {
            printf("init of egress drop counter failed with %d\n", ret);
            return ret;
        }  
    }

    /* Color and deny counters */
    for (index = 0; index < COLOR_COUNTER_SIZE/4; index++) 
    {
      ret = xel_meter_clear_stat(xid, index);

        if (ret != 0)
    {
            printf("init of color counters failed with %d\n", ret);
            return ret;
    }  
    }
    
    return ret;
}


void* boot_app (void* args)
{
    uint8_t i   = 0;
    int     ret = 0;
    uint8_t xid = ((struct thread_args_type*)args)->xid;
    hxdict_t hxdict = NULL;
    xlog_t xlog_hndl = NULL;
    
#ifdef RDK    
    char* xex_file = ((struct thread_args_type*)args)->xex_file;
    char* param_file = ((struct thread_args_type*)args)->param_file;
       
    char* bootarg[5];
    hxboot_t hxboot;
    crki2c_t crki2c_module[4];
    crksfp_t crksfp[4];
#endif

    ret = drv_open(xid);

    if (ret < 0)
    {
        printf("drv_open failed with %d\n", ret);
        return (void*)ret;        
    }

    xlog_hndl = drv_get_xlog_hndl(xid);
    
#ifdef RDK
    /* Init HW. */
    ret = hxdict_open(xlog_hndl, &hxdict);
    
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }
    
    ret = hxboot_open(xlog_hndl, hxdict, &hxboot);
    
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }

    bootarg[0] = "xxx";
    bootarg[1] = "-x";
    bootarg[2] = xex_file;
    bootarg[3] = "-p";
    bootarg[4] = param_file;

    ret = hxboot_arguments(hxboot, 5, bootarg);
    
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }

    ret = hxboot_init(hxboot);
    
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }
#endif
    
    /* Initialize driver. */
    ret = drv_init(xid, hxdict);
    
    if (ret != 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }

#ifdef RDK
    /* Init SFP */
    for (i = 0; i < 3; i++)
    {
        ret = crkctl_init_io(drv_get_crkctl_hndl(xid), i, SFP_TYPE);
        if (ret < 0)
        {
            XLOG_ERR(xlog_hndl, ret);
            return (void*)ret;
        }
    }
    
    for (i = 0; i < 3; i++)
    {
        ret = crki2c_open(CRKI2C_MODULE0 + (i * 0x0100), drv_get_crkctl_hndl(xid), &crki2c_module[i]);
        if (ret < 0)
        {
            XLOG_ERR(xlog_hndl, ret);
            return (void*)ret;
        }
    }
    
    for (i = 0; i < 3; i++)
    {
        ret = crksfp_open(crki2c_module[i], &crksfp[i]);
        if (ret < 0)
        {
            XLOG_ERR(xlog_hndl, ret);
            return (void*)ret;
        }
        ret = crksfp_init_io(crksfp[i]);
        if (ret < 0)
        {
            XLOG_ERR(xlog_hndl, ret);
            return (void*)ret;
        }
    }

    /* Init HW */
    ret = hxboot_conf(hxboot, drv_get_cfgctl_hndl(xid), drv_get_msgctl_hndl(xid));
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }

    ret = hxboot_send(hxboot, drv_get_msgctl_hndl(xid));
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }
        
    ret = hxboot_close(hxboot);
    if (ret < 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }
#endif
    
    ret = drv_init_post_boot(xid);
    if (ret != 0)
    {
        XLOG_ERR(xlog_hndl, ret);
        return (void*)ret;
    }
    
    ret = drv_init_post_init(xid);
    
    if (ret != 0)
    {
        XLOG_ERR(xlog_hndl, ret);
    }

    return (void*)ret;
}

void* init_app_bridging (void* args)
{
    uint8_t i   = 0;
    int     ret = 0;
    uint8_t xid = ((struct thread_args_type*)args)->xid;

    ret = (int) boot_app(args);

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }
    
    ret = mem_nse_init(xid);
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    ret = mem_tcam_init(xid);
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    ret = mem_hash_init(xid);

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    /*
     * Initialize bridging tables (common to all applications)
     */
    xlog_write(drv_get_xlog_hndl(xid), LOG_NOTICE, "MAC table init");
    
#ifdef RDK
    ret = xel_mac_init(xid, MAC_FORWARD_INDEX_SIZE - 1024);
#else
    ret = xel_mac_init(xid, 256);
#endif

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    ret = xel_port_set_catch_all_ingress(xid);
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    ret = xel_port_init_egress(xid);
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }

    xlog_write(drv_get_xlog_hndl(xid), LOG_NOTICE, "Classify table init");
    ret = xel_ether_init_classify(xid);
    
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }
   
#ifdef RDK
    xlog_write(drv_get_xlog_hndl(xid), LOG_NOTICE, "VID table init");
    
#ifdef USE_ECM_PROGRAM    
    ret = xel_vid_translation_clear(xid);

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }
#else
    for (i = 0; i < 48; i++)
    {
        ret = xel_vid_translation_init(xid, i);

        if (ret != 0)
        {
            XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        }
    }

    xlog_write(drv_get_xlog_hndl(xid), LOG_NOTICE, "Filtering table init");
    ret = xel_cvid_filtering_init(xid);

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
    }
#endif /* USE_ECM_PROGRAM */

    /* The counters are zeroed in simulator */
    ret = init_bridging_counters(xid);

    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
        return (void*)ret;
    }    
#endif /* RDK */   

    ret = xel_set_tm_to_cpu_dest(xid, 0);
    
    if (ret != 0)
    {
        XLOG_ERR(drv_get_xlog_hndl(xid), ret);
    }

    xlog_write(drv_get_xlog_hndl(xid), LOG_NOTICE, "  Init bridging tables done\n");

    return (void*) ret;
}

