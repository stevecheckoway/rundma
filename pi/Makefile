CFLAGS := -std=gnu99 -Wall -D_GNU_SOURCE=1 -g

bins := bf rootkit

bf_OBJS := bf.o mem.o dma.o uart.o common.o
rootkit_OBJS := rootkit.o mem.o dma.o

.PHONY: all clean

all: $(bins)
clean:
	sudo $(RM) $(bins)
	$(RM) -r .obj

# Dependencies tracking
$(foreach bin,$(bins),$(eval $(bin): $(addprefix .obj/,$($(bin)_OBJS))))

$(bins):
	$(LINK.o) -o $@ $^
	sudo chown root $@
	sudo chmod u+s $@

src := $(wildcard *.c)
obj := $(src:%.c=.obj/%.o)
dep := $(src:%.c=.obj/%.d)

$(obj) $(dep): | .obj
.obj:
	mkdir $@
.obj/%.o: %.c
	$(COMPILE.c) -MMD -MP -o $@ $<

-include $(dep)
