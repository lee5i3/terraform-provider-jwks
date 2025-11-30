# PROVIDER_DIR is used instead of PWD since docker volume commands can be dangerous to run in $HOME.
# This ensures docker volumes are mounted from within provider directory instead.
PROVIDER_DIR := $(abspath $(lastword $(dir $(MAKEFILE_LIST))))
TEST         := "$(PROVIDER_DIR)/provider"
GOFMT_FILES  := $$(find $(PROVIDER_DIR) -name '*.go')
PKG_NAME     := jwks
OS_ARCH      := $(shell go env GOOS)_$(shell go env GOARCH)

# The maximum number of tests to run simultaneously.
PARALLEL_RUNS?=8

fmt:
	gofmt -w $(GOFMT_FILES)

init:
	go mod tidy
	go mod vendor
	go mod download

test:
	go test $(TEST) -vet=off $(TESTARGS) -parallel $(PARALLEL_RUNS) -timeout=30s

testacc: 
	TF_LOG=DEBUG TESTARGS="-run '^TestAcc'" KUBE_CONFIG_PATH="~/.kube/kubeconfig-homelab" TF_ACC=1 go test $(TEST) -v -vet=off $(TESTARGS) -parallel $(PARALLEL_RUNS) -timeout 3h

testfuncs: 
	go test $(PROVIDER_FUNCTIONS_DIR) -v -vet=off $(TESTARGS) -parallel $(PARALLEL_RUNS)

frameworkacc:
	TF_ACC=1 go test $(PROVIDER_FRAMEWORK_DIR) -v -vet=off $(TESTARGS) -parallel $(PARALLEL_RUNS)