# Citrix Go

## Build

```shell
go build -o citrix-go
```

## Create a macOS Application

```shell
# Install appify
go get github.com/machinebox/appify

appify -author Jia1e -icon resources/icon.png -name "Citrix Go" ./citrix-go
```