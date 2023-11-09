CC = gcc
LD = gcc
PROJ_DIR = $(shell pwd)

# common
COMMON_INC_DIR = common/inc
COMMON_SRC_DIR = common/src
COMMON_INC = $(wildcard $(COMMON_INC_DIR)/*.h)
COMMON_SRC = $(wildcard $(COMMON_SRC_DIR)/*.c)
COMMON_BUILD_DIR = build/common_obj
COMMON_OBJ = $(subst $(COMMON_SRC_DIR),$(COMMON_BUILD_DIR),$(patsubst %.c,%.o,$(COMMON_SRC)))
COMMON_CFLAGS = -I./common/inc
# tunnel
TUNNLE_INC_DIR = tunnel/inc
TUNNLE_SRC_DIR = tunnel/src
TUNNLE_INC = $(wildcard $(TUNNLE_INC_DIR)/*.h)
TUNNLE_SRC = $(wildcard $(TUNNLE_SRC_DIR)/*.c)
TUNNLE_BUILD_DIR = build/tunnel_obj
TUNNLE_OBJ = $(subst $(TUNNLE_SRC_DIR),$(TUNNLE_BUILD_DIR),$(patsubst %.c,%.o,$(TUNNLE_SRC)))
TUNNLE_CFLAGS = -I./tunnel/inc -I./common/inc
TUNNLE_LDFLAGS =
TUNNLE_NAME = tunnel

#tunneld
TUNNLED_SRC_DIR = tunneld/src
TUNNLED_INC_DIR = tunneld/inc
TUNNLED_INC = $(wildcard $(TUNNLED_INC_DIR)/*.h)
TUNNLED_SRC = $(wildcard $(TUNNLED_SRC_DIR)/*.c)
TUNNLED_BUILD_DIR = build/tunneld_obj
TUNNLED_OBJ = $(subst $(TUNNLED_SRC_DIR),$(TUNNLED_BUILD_DIR),$(patsubst %.c,%.o,$(TUNNLED_SRC)))
TUNNLED_CFLAGS = -I./lib/zlog/include -I./tunneld/inc -I./common/inc
TUNNLED_LDFLAGS = -L./lib/zlog/lib -lzlog -pthread -static #-lm -lc #-lpthread #-lrt #-lpthread -lm -lc
TUNNLED_NAME = tunneld

#final build dir
F_BUILD_DIR = ./build

.PHONY:tunnel_prep tunneld_prep

All:tunnel tunneld

debug:
	@echo $(TUNNLE_SRC)
	@echo $(TUNNLE_OBJ)
	@echo $(PROJ_DIR)
	@echo $(TUNNLED_OBJ)
	mkdir -p $(TUNNLED_BUILD_DIR)

## common used
common_prep:
	mkdir -p $(COMMON_BUILD_DIR)
$(COMMON_BUILD_DIR)/%.o:$(COMMON_SRC_DIR)/%.c
	$(CC) $(COMMON_CFLAGS) -o $@ -c $^
common:common_prep $(COMMON_OBJ)

### tunnel build target ###
tunnel_prep:
	mkdir -p $(TUNNLE_BUILD_DIR)

$(TUNNLE_BUILD_DIR)/%.o:$(TUNNLE_SRC_DIR)/%.c
	$(CC) $(TUNNLE_CFLAGS) -o $@ -c $^

build_tunnel:$(TUNNLE_OBJ)
	$(LD) $^ $(TUNNLE_LDFLAGS) -o $(F_BUILD_DIR)/$(TUNNLE_NAME) $(COMMON_OBJ)
	cp $(PROJ_DIR)/tunnel/etc/tunnel.conf $(F_BUILD_DIR)/

tunnel:tunnel_prep common build_tunnel

### tunneld build target ###
$(TUNNLED_BUILD_DIR)/%.o:$(TUNNLED_SRC_DIR)/%.c
	$(CC) $(TUNNLED_CFLAGS) -o $@ -c $^

build_tunneld:$(TUNNLED_OBJ)
	$(LD) $^ $(TUNNLED_LDFLAGS) -o $(F_BUILD_DIR)/$(TUNNLED_NAME) $(COMMON_OBJ)
	cp $(PROJ_DIR)/tunneld/etc/tunneld.conf $(F_BUILD_DIR)/
	cp $(PROJ_DIR)/tunneld/etc/zlog.conf $(F_BUILD_DIR)/

tunneld_prep:
	mkdir -p $(TUNNLED_BUILD_DIR)

tunneld:tunneld_prep common build_tunneld