# Makefile for Firedancer Ed25519 standalone test harness
#
# This builds against the Firedancer source tree. It assumes the
# Firedancer project has already been built (so .o/.a files exist).
#
# Usage:
#   make                    # build using Firedancer build artifacts
#   make FIREDANCER=<path>  # specify Firedancer source root
#   make clean

FIREDANCER ?= ../firedancer
FD_SRC     := $(FIREDANCER)/src

# Detect build directory (Firedancer uses build/<machine>/ by default)
BUILDDIR   ?= $(shell ls -d $(FIREDANCER)/build/native/gcc 2>/dev/null | head -1)

# Compiler settings
CC         ?= gcc
CFLAGS     := -std=c17 -O2 -Wall -Wextra

# Firedancer feature flags for the ref (non-AVX512) build.
# These match what Firedancer sets for a basic x86-64 Linux build.
FD_FLAGS   := -DFD_HAS_HOSTED=1     \
              -DFD_HAS_ATOMIC=1     \
              -DFD_HAS_THREADS=1    \
              -DFD_HAS_INT128=1     \
              -DFD_HAS_DOUBLE=1     \
              -DFD_HAS_ALLOCA=1     \
              -DFD_HAS_X86=1        \
              -DFD_HAS_SSE=0        \
              -DFD_HAS_AVX=0        \
              -DFD_HAS_AVX512=0

# Include paths into the Firedancer source tree
INCLUDES   := -I$(FD_SRC)/ballet/ed25519 \
              -I$(FD_SRC)/ballet/sha512   \
              -I$(FD_SRC)/ballet          \
              -I$(FD_SRC)/util            \
              -I$(FD_SRC)/util/bits       \
              -I$(FD_SRC)/util/sanitize   \
              -I$(FD_SRC)/util/rng        \
              -I$(FD_SRC)/util/spad       \
              -I$(FD_SRC)/util/alloc      \
              -I$(FD_SRC)/util/wksp       \
              -I$(FD_SRC)/util/tpool      \
              -I$(FD_SRC)/util/scratch     \
              -I$(FD_SRC)/util/shmem      \
              -I$(FD_SRC)/util/tile       \
              -I$(FD_SRC)/util/log        \
              -I$(FD_SRC)/util/env        \
              -I$(FD_SRC)/util/cstr       \
              -I$(FD_SRC)/util/io         \
              -I$(FD_SRC)/util/checkpt    \
              -I$(FD_SRC)/util/sandbox    \
              -I$(FD_SRC)/ballet/bigint   \
              -I$(FD_SRC)

# The Firedancer source files we need to compile
FD_ED25519_SRCS := $(FD_SRC)/ballet/ed25519/fd_ed25519_user.c   \
                   $(FD_SRC)/ballet/ed25519/fd_curve25519.c      \
                   $(FD_SRC)/ballet/ed25519/fd_f25519.c          \
                   $(FD_SRC)/ballet/ed25519/fd_curve25519_scalar.c \
                   $(FD_SRC)/ballet/ed25519/fd_curve25519_tables.c

# If a build directory exists with pre-built libraries, use those.
# Otherwise, compile from source.
ifneq ($(BUILDDIR),)
  # Link against pre-built Firedancer libraries
  FD_LIBS := $(BUILDDIR)/lib/libfd_ballet.a $(BUILDDIR)/lib/libfd_util.a
  LINK_MODE := prebuilt
else
  LINK_MODE := source
endif

.PHONY: all clean info

all: ed25519_test

info:
	@echo "FIREDANCER = $(FIREDANCER)"
	@echo "BUILDDIR   = $(BUILDDIR)"
	@echo "LINK_MODE  = $(LINK_MODE)"
	@echo "CC         = $(CC)"

ifeq ($(LINK_MODE),prebuilt)
# Link against pre-built libraries
ed25519_test: ed25519_test.c
	$(CC) $(CFLAGS) $(FD_FLAGS) $(INCLUDES) -o $@ $< $(FD_LIBS) -lpthread -lm
else
# Compile everything from source
ed25519_test: ed25519_test.c
	$(CC) $(CFLAGS) $(FD_FLAGS) $(INCLUDES) \
		-o $@ $< \
		$(FD_ED25519_SRCS) \
		$(FD_SRC)/ballet/sha512/fd_sha512.c \
		-lpthread -lm
endif

clean:
	rm -f ed25519_test ed25519_test.exe *.o

# --- Alternative: Link against the full Firedancer build ---
# If you've built Firedancer normally (make -j), you can also do:
#
#   gcc -std=c17 -O2 \
#     -DFD_HAS_HOSTED=1 -DFD_HAS_INT128=1 -DFD_HAS_X86=1 ... \
#     -I../firedancer/src \
#     -I../firedancer/src/ballet/ed25519 \
#     -o ed25519_test ed25519_test.c \
#     ../firedancer/build/native/gcc/lib/libfd_ballet.a \
#     ../firedancer/build/native/gcc/lib/libfd_util.a \
#     -lpthread -lm
