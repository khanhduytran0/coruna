TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

SUBPROJECTS += SpringBoardTweak
include $(THEOS_MAKE_PATH)/aggregate.mk

LIBRARY_NAME = TweakLoader
TweakLoader_FILES = TweakLoader.m lv_bypass.c
TweakLoader_CFLAGS = -fno-objc-arc
TweakLoader_LDFLAGS = -sectcreate __TEXT __SBTweak $(THEOS_OBJ_DIR)/SpringBoardTweak.dylib
TweakLoader_INSTALL_PATH = /usr/local/lib

$(THEOS_OBJ_DIR)/TweakLoader.dylib: \
    $(THEOS_OBJ_DIR)/SpringBoardTweak.dylib

include $(THEOS_MAKE_PATH)/library.mk
