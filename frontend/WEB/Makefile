NAME    := gocm-web
DSTDIR  := /srv/http/gocm
USER    := http
GROUP   := http

.PHONY: all
all: install

.PHONY: install
install:
	@mkdir -p $(DSTDIR)
	@cp -ar index.html css js $(DSTDIR)/
	@-chown -R $(USER):$(GROUP) $(DSTDIR) 2>/dev/null || true

.PHONY: uninstall
uninstall:
	@rm -rf $(DSTDIR)
