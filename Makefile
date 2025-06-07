all:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-s -w" -o kerbtool

clean:
	rm -f kerbtool
