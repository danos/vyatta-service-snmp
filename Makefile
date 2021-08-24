cpiop = find  . ! -regex '\(.*~\|.*\.bak\|.*\.swp\|.*\#.*\#\)' -print0 | \
  cpio -0pd

all:
	$(MAKE) -C src

check:
	$(MAKE) -C tests

install:
	mkdir -p $(DESTDIR)/opt/vyatta/bin
	install -m755 -t $(DESTDIR)/opt/vyatta/bin \
		scripts/snmp/vyatta-show-snmp-ifmib \
		scripts/snmp/vyatta-show-snmp.pl \
		scripts/snmp/vyatta-show-snmp-v3.pl \
		scripts/snmp/vyatta-show-snmp-view \
		scripts/snmp/vyatta-storm-ctl-trap.py \
		scripts/snmp/vyatta-buffer-congestion.py
	mkdir -p $(DESTDIR)/opt/vyatta/sbin
	install -m755 -t $(DESTDIR)/opt/vyatta/sbin \
		scripts/system/vyatta_check_snmp_name.pl \
		scripts/snmp/vyatta-snmp-validate \
		scripts/snmp/vyatta-snmp.pl \
		scripts/snmp/vyatta-snmp-v3.pl \
		scripts/snmp/vyatta-nat-mib.pl \
		scripts/snmp/vyatta-snmp-subagent \
		scripts/snmp/vyatta-entity-mibs-subagent \
		scripts/snmp/vyatta-ptp-mib-subagent \
		scripts/snmp/vyattaqosmib.pl \
		scripts/snmp/vyatta-storm-ctl-mib.pl \
		scripts/snmp/notification-to-syslog \
		scripts/snmp/syslog-to-notification-end \
		scripts/snmp/entity-sensor-ipmi \
		scripts/snmp/vyatta_sendtrap_daemonstopped
	mkdir -p $(DESTDIR)/opt/vyatta/share/perl5/Vyatta
	install -m644 -t $(DESTDIR)/opt/vyatta/share/perl5/Vyatta \
		lib/Vyatta/IFMib.pm \
		lib/Vyatta/MIBMisc.pm \
		lib/Vyatta/SNMPSubagent.pm \
		lib/Vyatta/SNMPListen.pm
	mkdir -p $(DESTDIR)/opt/vyatta/share/tmplscripts
	cd tmplscripts && $(cpiop) $(DESTDIR)/opt/vyatta/share/tmplscripts
	mkdir -p $(DESTDIR)/usr/share/configd/yang
	install -m644 -t $(DESTDIR)/usr/share/configd/yang \
		yang/vyatta-service-snmp-v1.yang
	mkdir -p $(DESTDIR)/opt/vyatta/share/vyatta-op/templates
	cd templates && $(cpiop) $(DESTDIR)/opt/vyatta/share/vyatta-op/templates
