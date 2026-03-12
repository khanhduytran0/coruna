TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = bootstrap

bootstrap_FILES = $(wildcard *.m)
bootstrap_CFLAGS = -fobjc-arc -mcpu=apple-a12
bootstrap_INSTALL_PATH = /usr/local/lib

include $(THEOS_MAKE_PATH)/library.mk
