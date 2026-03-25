TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = DriverWrapper
DriverWrapper_FILES = DriverWrapper.m lv_bypass.c
DriverWrapper_CFLAGS = -fno-objc-arc
DriverWrapper_LDFLAGS = -sectcreate __TEXT __SBTweak ../../payloads/377bed7460f7538f96bbad7bdc2b8294bdc54599/entry1_type0x09.dylib
# $(THEOS_OBJ_DIR)/SpringBoardTweak.dylib
DriverWrapper_INSTALL_PATH = /usr/local/lib

install:: $(THEOS_OBJ_DIR)/DriverWrapper.dylib
	echo INSTALLING

include $(THEOS_MAKE_PATH)/library.mk
