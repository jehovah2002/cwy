#                                                                   
# makefile for application preconcole library
# 
#

EDIR = ./bin
LDIR = ./lib
ODIR = ./obj
SDIR = .
CC = gcc
AR = ar

INC_DIR = ./inc
ALL_DIR = -I$(INC_DIR)
LIBDIR = -Wl,-rpath=$(LDIR) -L$(LDIR)
LIBS = -lautoc -lssl -lcrypto

CCFLAGS=-g $(ALL_DIR)

LIBAPI_SO= $(LDIR)/libautoc.so
MYTEST= mytest


PROGRAM	= $(LIBAPI_SO) $(MYTEST) 
#$(M2000TEST) $(PERFTEST) $(RELIATEST)

########## object files #############
LIBAPI_OBJ	=$(ODIR)/sm3.o \
			$(ODIR)/autoc.o \
			$(ODIR)/common.o \
			$(ODIR)/sm2_point2oct.o \
			$(ODIR)/sm2_create_key_pair.o \
			$(ODIR)/sm2_sign_and_verify.o \
			$(ODIR)/sm2crypto.o 
#			$(ODIR)/mizar_common.o \
###############################################
MYTEST_OBJ	=$(ODIR)/main.o    
#SPITOOL_OBJ	=$(ODIR)/spitool.o
#M2000TEST_OBJ=$(ODIR)/m2000test.o \
#			$(ODIR)/sm4.o
#PERSO_OBJ	=$(ODIR)/perso.o
#PERFTEST_OBJ	=$(ODIR)/perftest.o
#RELIATEST_OBJ	=$(ODIR)/reliability_test.o
		        
###############################################
all:	$(PROGRAM)
$(LIBAPI_SO)::	$(LIBAPI_OBJ)
	@echo ------ Linking...	------
	$(CC) -fPIC -shared -o $(LIBAPI_SO) $(LIBAPI_OBJ) $(CCFLAGS)
	@echo ------ make $@ OK. ------

$(MYTEST)::	$(MYTEST_OBJ)
	@echo ------ Linking...	------
	$(CC) -o $(MYTEST) $(MYTEST_OBJ) $(CCFLAGS) $(LIBDIR) $(LIBS) 
	@echo ------ make $@ OK. ------


clean::
	@$(RM) $(LIBAPI_OBJ) $(LIBAPI_SO) $(MYTEST) $(MYTEST_OBJ)

cleanbin::
	@$(RM) $(PROGRAM)

.SUFFIXES: .cpp .c .o .so .a
##################### common #################### 
$(ODIR)/main.o:$(SDIR)/main.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/sm3.o:$(ODIR)/sm3.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/autoc.o:$(ODIR)/autoc.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/common.o:$(ODIR)/common.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/sm2_create_key_pair.o:$(ODIR)/sm2_create_key_pair.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/sm2_sign_and_verify.o:$(ODIR)/sm2_sign_and_verify.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/sm2_point2oct.o:$(ODIR)/sm2_point2oct.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?
$(ODIR)/sm2crypto.o:$(ODIR)/sm2crypto.c
	$(CC) -fPIC -o $@ $(CCFLAGS) -c $?


