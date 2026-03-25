TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = entry1_type0x09

entry1_type0x09_FILES = entry1_type0x09.m
entry1_type0x09_CFLAGS = \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -Wno-implicit-function-declaration \
    -Wno-deprecated-non-prototype \
    -Wno-incompatible-library-redeclaration \
    -Wno-implicit-int \
    -fno-builtin \
    -I.
entry1_type0x09_FRAMEWORKS = CoreFoundation IOKit Security
entry1_type0x09_INSTALL_PATH = /usr/local/lib

include $(THEOS_MAKE_PATH)/library.mk
