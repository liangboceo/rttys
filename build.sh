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
	GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w -X $VersionPath.gitCommit=$GitCommit -X $VersionPath.buildTime=$BuildTime" -o $bin
}

generate $1 $2
