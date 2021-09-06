APP = testpcap

ifeq ($(wildcard ../PcapPlusPlus/mk/platform.mk),)
  $(error platform.mk not found! Please run configure script first)
endif
ifeq ($(wildcard ../PcapPlusPlus/mk/PcapPlusPlus.mk),)
  $(error PcapPlusPlus.mk not found! Please run configure script first)
endif



include ../PcapPlusPlus/mk/platform.mk
include ../PcapPlusPlus/mk/PcapPlusPlus.mk

SOURCES := $(wildcard *.cpp)
OBJS_FILENAMES := $(patsubst %.cpp,Obj/%.o,$(SOURCES))

BRIDGE_MODE := 0

HEADER := -I
HEADER += header/
ZMQFLAGS = -lpthread -lzmqpp -lzmq -lsodium -Wl,--no-as-needed -L/usr/local/lib

Obj/%.o: %.cpp 
	@echo Building file: $<
	@$(CXX) $(PCAPPP_BUILD_FLAGS) -c $(PCAPPP_INCLUDES) $(HEADER) -fmessage-length=0 -MMD -MP -MF"$(@:Obj/%.o=Obj/%.d)" -MT"$(@:Obj/%.o=Obj/%.d)" -o "$@" "$<" 

UNAME := $(shell uname)
CUR_TARGET := $(notdir $(shell pwd))

# .SILENT:

all: dependents $(APP)

start:
	@echo ==== Building target: $(CUR_TARGET) ====

create-directories:
	@$(MKDIR) -p Obj
	@$(MKDIR) -p build

dependents:
	@cd $(PCAPPLUSPLUS_HOME) && $(MAKE) libs

$(APP): start create-directories $(OBJS_FILENAMES)
	@$(CXX) $(PCAPPP_BUILD_FLAGS) $(PCAPPP_LIBS_DIR) -o "./build/$(APP)$(BIN_EXT)" $(OBJS_FILENAMES) $(PCAPPP_LIBS) ${ZMQFLAGS}
	@$(PCAPPP_POST_BUILD)
	@echo Finished successfully building: $(APP)
	@echo ' '

clean:
	@$(RM) -rf ./Obj/*
	@$(RM) -rf ./build/*
	@$(RM) -rf *.pcap
	@echo Clean finished: $(CUR_TARGET)
