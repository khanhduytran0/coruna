TARGET := iphone:clang:latest:15.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = SpringBoardTweak

SpringBoardTweak_FILES = SpringBoardTweak.m
SpringBoardTweak_CFLAGS = -fobjc-arc
SpringBoardTweak_LDFLAGS = -undefined dynamic_lookup
SpringBoardTweak_INSTALL_PATH = /usr/local/lib

include $(THEOS_MAKE_PATH)/library.mk
