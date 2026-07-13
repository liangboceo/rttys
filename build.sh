#!/bin/sh

VersionPath="rttys/version"
GitCommit=$(git log --pretty=format:"%h" -1)
BuildTime=$(date +%FT%T%z)

[ $# -lt 2 ] && {
	echo "Usage: $0 linux amd64"
	exit 1
}

generate() {
	local os="$1"
	local arch="$2"
	local dir="rttys-$os-$arch"
	local bin="rttys"
	[ "$os" = "windows" ] && {
		bin="rttys.exe"
	}
	mkdir -p $dir
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w -X $VersionPath.gitCommit=$GitCommit -X $VersionPath.buildTime=$BuildTime" -o $dir/$bin
}

generate_client() {
	local os="$1"
	local arch="$2"
	local dir="rtty-client-$os-$arch"
	local bin="rtty-client"
	[ "$os" = "windows" ] && {
		bin="rtty-client.exe"
	}
	mkdir -p $dir
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w" -o $dir/$bin ./rtty-client/
}

generate $1 $2
generate_client $1 $2
