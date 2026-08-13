NAME     := gocm
VERSION  := v0.1.0
REVISION := $(shell git rev-parse --short HEAD)

SRCS    := $(shell find . -type f -name '*.go')
DSTDIR  := /srv/http/bin
CONFDIR := /usr/local/etc
USER    := http
GROUP   := http
LDFLAGS := -ldflags="-s -w -X \"main.Version=$(VERSION)\" -X \"main.Revision=$(REVISION)\" -extldflags \"-static\""

GOVER     := $(shell go version | awk '{ print substr($$3, 3) }' | tr "." " ")
VER_JUDGE := $(shell if [ $(word 1,$(GOVER)) -eq 1 ] && [ $(word 2,$(GOVER)) -le 10 ]; then echo 0; else echo 1; fi)

DB_CONFIG := connect.toml
DB_TYPE   := $(shell grep 'db_type' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')
DB_USER   := $(shell grep 'user' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')
DB_PASS   := $(shell grep 'password' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')
DB_HOST   := $(shell grep 'server' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')
DB_PORT   := $(shell grep 'port' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/[^0-9]*([0-9]+).*/\1/')
DB_NAME   := $(shell grep 'name' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')
SSL_MODE  := $(shell grep 'sslmode' $(DB_CONFIG) 2>/dev/null | grep -v '^[[:space:]]*#' | head -n 1 | sed -E 's/.*=[[:space:]]*"([^"]+)".*/\1/')

ifeq ($(SSL_MODE),)
  SSL_MODE := disable
endif

ifeq ($(DB_TYPE),postgres)
  DB_URL       := "postgres://$(DB_USER):$(DB_PASS)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=$(SSL_MODE)"
  MIGRATE_PATH := migrations/postgres
else
  DB_URL       := "mysql://$(DB_USER):$(DB_PASS)@tcp($(DB_HOST):$(DB_PORT))/$(DB_NAME)?tls=false"
  MIGRATE_PATH := migrations/mysql
endif

.PHONY: run
run: build
	./bin/$(NAME)

.PHONY: init
init:
ifeq ($(VER_JUDGE),1)
	@go mod init $(NAME) && go mod tidy
else
	@echo "Packageの取得は手動で行ってください"
endif

.PHONY: modup
modup:
	@go mod tidy

build: $(SRCS)
	@go build -a -tags netgo -installsuffix netgo $(LDFLAGS) -o bin/$(NAME)
	@cp -ar $(DB_CONFIG) bin/

.PHONY: db
db:
	@migrate -database $(DB_URL) -path $(MIGRATE_PATH) up

.PHONY: db-down
db-down:
	@migrate -database $(DB_URL) -path $(MIGRATE_PATH) down

.PHONY: install
install:
	@mkdir -p $(DSTDIR)
	@mkdir -p $(CONFDIR)/$(NAME)
	@cp -r bin/$(NAME) $(DSTDIR)/
	@cp -r bin/$(DB_CONFIG) $(CONFDIR)/$(NAME)
	@chown $(USER):$(GROUP) $(DSTDIR)/$(NAME)
	@chown $(USER):$(GROUP) $(CONFDIR)/$(NAME)/$(DB_CONFIG)

.PHONY: uninstall
uninstall: revoke_service
	@rm -f $(DSTDIR)/$(NAME)
	@rm -rf $(CONFDIR)/$(NAME)

create_service:
	@echo -e "[Unit]\nDescription=$(NAME)(Golang App)\n\n[Service]\nEnvironment=\"GIN_MODE=release\"\nWorkingDirectory=$(DSTDIR)/\n\nExecStart=$(DSTDIR)/$(NAME)\nExecStop=/bin/kill -HUP $MAINPID\nExecReload=/bin/kill -HUP $MAINPID && $(DSTDIR)/$(NAME)\n\nRestart=always\nType=simple\nUser=$(USER)\nGroup=$(GROUP)\n\n[Install]\nWantedBy=multi-user.target" | tee /etc/systemd/system/$(NAME).service
	@systemctl enable $(NAME).service

.PHONY: start
start: create_service
	@systemctl start $(NAME).service

revoke_service: /etc/systemd/system/$(NAME).service
	@systemctl stop $(NAME).service
	@systemctl disable $(NAME).service
	@rm -f /etc/systemd/system/$(NAME).service

.PHONY: clean
clean:
	@rm -rf bin/*
	@rm -rf vendor/*

.PHONY: test
test:
	@go test
