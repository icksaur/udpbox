# Name of the output binary
TARGET := udpbox

# Variables
CXX := g++
CC := gcc
CXXFLAGS := -Wextra -Wpedantic -flto -std=c++20 -g -D_GLIBCXX_DEBUG -fno-common
CFLAGS := -Wall -g D_GLIBCXX_DEBUG -fno-common
LDFLAGS := -flto -lsodium

# Detect source and header files
CPP_SOURCES := $(wildcard *.cpp)
C_SOURCES := $(wildcard *.c)
HEADERS := $(wildcard *.h)
OBJ_DIR := obj
OBJECTS := $(addprefix $(OBJ_DIR)/,$(CPP_SOURCES:.cpp=.o)) $(addprefix $(OBJ_DIR)/,$(C_SOURCES:.c=.o))

# Rules
.PHONY: all clean

all: $(OBJ_DIR) $(TARGET) $(SPIRV)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(TARGET): $(OBJECTS)
	$(CXX) $^ $(LDFLAGS) -o $@

$(OBJ_DIR)/%.o: %.cpp $(HEADERS)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(TARGET) $(OBJ_DIR) *.spv