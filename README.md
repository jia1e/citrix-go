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

## Usage

Create a `.citrix-go` file in `HOME` directory. 

```yaml
default-resource: 开发桌面
host: vdi.aishu.cn
password: p@ssw0rd
user: alice
```