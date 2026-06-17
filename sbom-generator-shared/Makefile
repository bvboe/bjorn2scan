.PHONY: test lint clean

test:
	go test -v -race ./...

lint:
	golangci-lint run ./...

clean:
	go clean -testcache
