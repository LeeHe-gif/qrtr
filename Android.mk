LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
	LOCAL_MODULE := libqrtr

	LOCAL_CFLAGS := -Wall -g
	LOCAL_C_INCLUDES := $(LOCAL_PATH)/src
	LOCAL_EXPORT_C_INCLUDE_DIRS := $(LOCAL_PATH)/lib
	LOCAL_SRC_FILES := lib/libqrtr.c
include $(BUILD_SHARED_LIBRARY)
