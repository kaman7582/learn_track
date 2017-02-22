/*----------------------------------------------------------------------------
 * Copyright (c) 2009-2011 Xelerated AB.
 * This program may be used and/or copied only with the written
 * permission from Xelerated AB, or in accordance with the terms
 * and conditions stipulated in the agreement/contract under which
 * the program has been supplied.
 * All rights reserved.
 *--------------------------------------------------------------------------*/
/**
 * $RCSfile: xel_init.c,v $
 * $Revision: 1.18 $
 * 
 * @file  xel_init.c
 * @brief System initialization.
 * 
 *--------------------------------------------------------------------------*/
#include <stdio.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>

#include "xel_init.h"
#include "drv_driver.h"
#include "mem_nse.h"
#include "mem_tcam.h"
#include "xel_macaddress.h"
#include "xel_portdecoding.h"
#include "xel_classification.h"
#include "xel_mac_class.h"
#include "xel_cpudest.h"

/* */
extern char *build_time;

void* init_app(void* args);

/*
 * Initializes the control plane.
 */
int
xel_init(char* xex_file, char* param_file)
{
    int ret = 0;
    uint8_t num_npus;
    uint8_t i;
    pthread_t threads[NUM_NPUS];
    struct thread_args_type* args[NUM_NPUS];
    pthread_attr_t attr[NUM_NPUS];

    num_npus = NUM_NPUS;
    printf("Control plane: %s\n", build_time);

    /* Initialize application. */
    for (i = 0; i < num_npus; i++)
    {
        args[i] = (struct thread_args_type*) malloc(sizeof(struct thread_args_type));
        args[i]->xid = i;
        args[i]->xex_file = xex_file;
        args[i]->param_file = param_file;

        ret = pthread_attr_init(&attr[i]);
        if (ret)
            return -ret;

        ret = pthread_attr_setdetachstate(&attr[i], PTHREAD_CREATE_JOINABLE);
        if (ret)
            return -ret;

        ret = pthread_create(&threads[i], &attr[i], init_app, (void*)(args[i]));
        if (ret)
            return -ret;
    }
    /* Wait for threads to finish. */
    for (i = 0; i < num_npus; i++)
    {
        void* rc;
        pthread_join(threads[i], &rc);
        if (rc)
        {
            ret = (int)rc;
            printf("%d: System boot [FAILED]\n", i);
        }
        else 
            printf("%d: System boot [OK]\n", i);
        pthread_attr_destroy(&attr[i]);
        free(args[i]);
    }

    return ret;
}
