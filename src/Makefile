LIBS	= -lnetsnmpagent -lnetsnmpmibs -lnetsnmp

OM_OBJS = omrfc5676.o
ST_OBJS = sensortrap.o
OBJS = $(OM_OBJS) $(ST_OBJS)

TARGETS = omrfc5676 sensortrap

all: $(TARGETS)

omrfc5676: $(OM_OBJS)
	$(CC) $(CFLAGS) -o $@ $(OM_OBJS) $(LDFLAGS) $(LIBS)

sensortrap: $(ST_OBJS)
	$(CC) $(CFLAGS) -o $@ $(ST_OBJS) $(LDFLAGS) $(LIBS)

clean:
	rm -f $(TARGETS) $(OBJS) core

.c.o:
	$(CC) -c $(CPPFLAGS) $(CFLAGS) -o $@ $<

.PHONY: clean install all
