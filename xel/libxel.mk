#
# Copyright (c) 2009-2011 Xelerated AB.
#
# This program may be used and/or copied only with the written
# permission from Xelerated AB, or in accordance with the terms
# and conditions stipulated in the agreement/contract under
# which the program has been supplied.
#
# All rights reserved.
#
# @file libxel.mk
#
# @brief Target makefile for building the xel library.
#
# $Revision: 1.7 $
#
BRIEF			:= "xel: XEL Control Plane API"
TARGET			:= libxel.a
DEFINE			= $(HX_APP_DEFINE)
INC_PATH		= $(HX_APP_INC_PATH)
INC_PROJ                := hsl msg hxdev
