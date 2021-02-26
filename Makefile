default: test

testpackages = ./...

test:
	go test -count=1 ${testpackages}

test-verbose:
	go test -v ${testpackages}

lint:
	golangci-lint run