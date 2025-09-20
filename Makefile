BINARY := go-chrome-curl

all:    lint build

build:
	go build -o ./${BINARY} ${VERSION_FLAGS} 

lint:
	gofmt -w *.go

clean:
	rm -rf ./${BINARY}
