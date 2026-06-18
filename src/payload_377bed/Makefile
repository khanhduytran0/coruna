TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e
FINALPACKAGE = 1
STRIP = 0
GO_EASY_ON_ME = 1
TARGET_CODESIGN = bash ./sign.sh ldid

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = entry1_type0x09

RECOMP_DEBUG_LOCALS ?= 0
ifeq ($(RECOMP_DEBUG_LOCALS),1)
entry1_type0x09_OPTFLAGS = -O0 -fno-omit-frame-pointer
else
entry1_type0x09_OPTFLAGS = -Og
endif

RECOMP_TRACE_DMAFAIL ?= 0
RECOMP_TRACE_PHYSMAP ?= 0
RECOMP_TRACE_PORTS ?= 0
RECOMP_PHYSMAP_VALIDATE_CACHE ?= 1
RECOMP_TEMP_FAKE_OBJC_CLASS ?= 0
RECOMP_TEMP_FAKE_OBJC_ARC ?= 0

entry1_type0x09_FILES = entry1_type0x09.m
entry1_type0x09_CFLAGS = \
    $(entry1_type0x09_OPTFLAGS) \
    -DRECOMP_TRACE_DMAFAIL=$(RECOMP_TRACE_DMAFAIL) \
    -DRECOMP_TRACE_PHYSMAP=$(RECOMP_TRACE_PHYSMAP) \
    -DRECOMP_TRACE_PORTS=$(RECOMP_TRACE_PORTS) \
    -DRECOMP_PHYSMAP_VALIDATE_CACHE=$(RECOMP_PHYSMAP_VALIDATE_CACHE) \
    -DRECOMP_TEMP_FAKE_OBJC_CLASS=$(RECOMP_TEMP_FAKE_OBJC_CLASS) \
    -fno-inline \
    -fno-strict-aliasing \
    -Wno-int-conversion \
    -Wno-incompatible-pointer-types \
    -Werror=implicit-function-declaration \
    -Werror=deprecated-non-prototype \
    -Wno-incompatible-library-redeclaration \
    -Wno-implicit-int \
    -fno-builtin \
    -fblocks \
    -I.
entry1_type0x09_FRAMEWORKS = CoreFoundation IOKit Security
entry1_type0x09_INSTALL_PATH = /usr/local/lib

ifeq ($(RECOMP_TEMP_FAKE_OBJC_ARC),1)
entry1_type0x09_CFLAGS += -fobjc-arc
endif
#entry1_type0x09_CFLAGS += -ferror-limit=0

TOOL_NAME = entry1_type0x09_test
entry1_type0x09_test_FILES = test.m
entry1_type0x09_test_CODESIGN_FLAGS = -Sentitlements.xml
entry1_type0x09_test_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/library.mk
include $(THEOS_MAKE_PATH)/tool.mk
