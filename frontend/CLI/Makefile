NAME    := gocm-cli
DSTDIR  := /usr/local/bin
USER    := root
GROUP   := root

.PHONY: all
all: install

.PHONY: install
install:
	@mkdir -p $(DSTDIR)
	@cp -a $(NAME).py $(DSTDIR)/
	@chmod +x $(DSTDIR)/$(NAME).py

.PHONY: uninstall
uninstall: revoke_service
	@rm -f $(DSTDIR)/$(NAME).py

create_service:
	@echo -e "[Unit]\nDescription=$(NAME) (Certificate Update Service)\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nUser=$(USER)\nGroup=$(GROUP)\nExecStart=/usr/bin/python3 $(DSTDIR)/$(NAME).py\n\n[Install]\nWantedBy=network-online.target" | tee /etc/systemd/system/$(NAME).service
	@echo -e "[Unit]\nDescription=$(NAME) (Certificate Update Timer)\n\n[Timer]\nOnBootSec=5min\nOnCalendar=Sun *-*-* 04:00:00\nRandomizedDelaySec=15min\nUnit=$(NAME).service\n\n[Install]\nWantedBy=timers.target" | tee /etc/systemd/system/$(NAME).timer
	@systemctl daemon-reload
	@systemctl enable $(NAME).timer

.PHONY: start
start: create_service
	@systemctl start $(NAME).timer

.PHONY: revoke_service
revoke_service:
	@-systemctl stop $(NAME).timer 2>/dev/null
	@-systemctl disable $(NAME).timer 2>/dev/null
	@rm -f /etc/systemd/system/$(NAME).service
	@rm -f /etc/systemd/system/$(NAME).timer
	@-systemctl daemon-reload
