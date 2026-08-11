.PHONY: build test vet fmt templates clean

build:
	go build -o mantis ./cmd/mantis

test:
	go test ./... -v

vet:
	go vet ./...

fmt:
	gofmt -l .

templates: build
	./mantis templates validate

clean:
	rm -f mantis mantis.exe mantis-report.*
