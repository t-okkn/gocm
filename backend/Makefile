NAME     := gocm-api
VERSION  := v0.1.0
REVISION := $(shell git rev-parse --short HEAD)

SRCS    := $(shell find . -type f -name '*.go')
DSTDIR  := /srv/http/bin
USER    := http
GROUP   := http
LDFLAGS := -ldflags="-s -w -X \"main.Version=$(VERSION)\" -X \"main.Revision=$(REVISION)\" -extldflags \"-static\""

GOVER     := $(shell go version | awk '{ print substr($$3, 3) }' | tr "." " ")
VER_JUDGE := $(shell if [ $(word 1,$(GOVER)) -eq 1 ] && [ $(word 2,$(GOVER)) -le 10 ]; then echo 0; else echo 1; fi)

DB_CONFIG := $(NAME).sql/connect.toml
DB_USER := $(shell cat $(DB_CONFIG) | grep user | sed -e 's/user = //' -e 's/"//g')
DB_PASS := $(shell cat $(DB_CONFIG) | grep password | sed -e 's/password = //' -e 's/"//g')
DB_HOST := $(shell cat $(DB_CONFIG) | grep server | sed -e 's/server = //' -e 's/"//g')
DB_PORT := $(shell cat $(DB_CONFIG) | grep port | sed -e 's/port = //')
DB_NAME := $(shell cat $(DB_CONFIG) | grep name | sed -e 's/name = \(.*\) \#.*/\1/' -e 's/"//g')
DB_URL  := "mysql://$(DB_USER):$(DB_PASS)@tcp($(DB_HOST):$(DB_PORT))/$(DB_NAME)?tls=false"

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
	@cp -ar $(NAME).sql bin/

.PHONY: db
db:
	@migrate -database $(DB_URL) -path migrations up

.PHONY: db-down
db-down:
	@migrate -database $(DB_URL) -path migrations down

.PHONY: install
install:
	@cp -r bin/$(NAME) $(DSTDIR)/
	@cp -r bin/$(NAME).sql $(DSTDIR)/
	@chown $(USER):$(GROUP) $(DSTDIR)/$(NAME)
	@chown -R $(USER):$(GROUP) $(DSTDIR)/$(NAME).sql

.PHONY: uninstall
uninstall: revoke_service
	@rm -f $(DSTDIR)/$(NAME)
	@rm -f $(DSTDIR)/$(NAME).sql

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
