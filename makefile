# object  = coding.o common.o hashmap.o withdrawn_cnt.o wideArray.o Vector.o level_bitmap.o utils.o path_bitmap.o hrov.o hrov_basic.o hrov_binary.o hrov_nlbs.o rtr_process.o hrov_process.o
# CC      = gcc
# CPPFLAGS = 
# SOFLAGS =  -shared
# LIBS    = -lm -lrtr

# all : libhrov.so test

# libhrov.so:$(object)
# 	$(CC) $(SOFLAGS) -o -fPIC -o $@ $^

# %.o:%.c
# 	$(CC) -o  $@ -c -fPIC $< $(LIBS)

# test:test.c libhrov.so
# 	$(CC) -g -o  $@ test.c $(object) $(LIBS)

# .PHONY:clean
# clean:
# 	rm -f *.o

CC := gcc
CPP := g++
CFLAGS := -fPIC
LIBS := -lm -lrtr -lbgpstream -lcurl -lpthread -lxxhash
LDFLAGS := -pie

SRC_DIR := src
OBJ_DIR := obj

LIBNAME := libhrov
EXECUTABLE := main

SRCS := $(wildcard  $(SRC_DIR)/*.c $(SRC_DIR)/SupportDS/*.c $(SRC_DIR)/utils/*.c $(SRC_DIR)/pfx/*.c $(SRC_DIR)/algos/*.c $(SRC_DIR)/unit_test/*.c)
OBJS := $(addprefix $(OBJ_DIR)/,$(notdir $(SRCS:.c=.o)))

# 设置 VPATH 变量
VPATH := $(SRC_DIR) $(SRC_DIR)/SupportDS $(SRC_DIR)/utils $(SRC_DIR)/algos $(SRC_DIR)/unit_test $(SRC_DIR)/pfx

# 定义 vpath 模式
vpath %.c $(VPATH)

all : $(LIBNAME).so main dsys

$(LIBNAME).so: $(OBJS)
	$(CC) -shared -o $@ $^ $(LIBS) -Ofast

# 默认目标为可执行文件
main: test.c $(LIBNAME).so
	$(CC) -g -o  $@ test.c $(LIBS) -L. -lhrov -Ofast

dsys: live.cpp $(LIBNAME).so
	$(CPP) -g -o  $@ live.cpp $(LIBS) -L. -lhrov

# 目标文件的生成规则
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)
	
# 用于清理目标文件和可执行文件
.PHONY: clean
clean:
	rm -rf $(OBJ_DIR) $(EXECUTABLE) $(LIBNAME).so

# CC := gcc
# CXX := g++
# CFLAGS := -fPIC
# CXXFLAGS := -fPIC
# LIBS := -lm -lrtr -lbgpstream
# LDFLAGS := -shared

# SRC_DIR := src
# OBJ_DIR := obj
# BIN_DIR := bin

# SRCS := $(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/algos/*.c $(SRC_DIR)/pfx/*.c $(SRC_DIR)/supportDS/*.c $(SRC_DIR)/utils/*.c)
# OBJS := $(addprefix $(OBJ_DIR)/,$(notdir $(SRCS:.c=.o)))
# CXX_SRCS := live.cpp
# CXX_OBJS := $(addprefix $(OBJ_DIR)/,$(CXX_SRCS:.cpp=.o))

# VPATH := $(SRC_DIR) $(SRC_DIR)/algos $(SRC_DIR)/pfx $(SRC_DIR)/supportDS $(SRC_DIR)/utils

# .PHONY: all
# all: libhrov.so test live

# libhrov.so: $(OBJS)
# 	$(CC) $(LDFLAGS) $^ -o $(BIN_DIR)/$@ $(LIBS)

# test: $(OBJ_DIR)/test.o
# 	$(CC) $(LDFLAGS) -L$(BIN_DIR) $< -o $(BIN_DIR)/$@ $(LIBS) -L$(SRC_DIR) -lhrov

# live: $(CXX_OBJS)
# 	$(CXX) $(LDFLAGS) -L$(BIN_DIR) $< -o $(BIN_DIR)/$@ $(LIBS) -L$(SRC_DIR) -lhrov

# $(OBJ_DIR)/%.o: %.c
# 	mkdir -p $(OBJ_DIR)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: $(SRC_DIR)/%.c 
# 	mkdir -p $(OBJ_DIR)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: $(SRC_DIR)/algos/%.c
# 	mkdir -p $(OBJ_DIR)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: $(SRC_DIR)/pfx/%.c
# 	mkdir -p $(OBJ_DIR)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: $(SRC_DIR)/supportDS/%.c
# 	mkdir -p $(OBJ_DIR) 
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: $(SRC_DIR)/utils/%.c
# 	mkdir -p $(OBJ_DIR)
# 	$(CC) $(CFLAGS) -c $< -o $@ $(LIBS)

# $(OBJ_DIR)/%.o: %.cpp
# 	mkdir -p $(OBJ_DIR)
# 	$(CXX) $(CXXFLAGS) -c $< -o $@ $(LIBS)

# .PHONY: clean
# clean:
# 	rm -rf $(OBJ_DIR) $(BIN_DIR)/*.so $(BIN_DIR)/test $(BIN_DIR)/live



