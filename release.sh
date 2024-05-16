#!/bin/bash

DATE="Mon May 16 2024"

MAJOR_VERSION=0
MINOR_VERSION=7
REVISION=1
VERSION=$MAJOR_VERSION.$MINOR_VERSION.$REVISION

LIBDIR=/usr/lib64
SBINDIR=/usr/sbin

# 设定项目根目录变量
PROJECT_ROOT=$(pwd)
RELEASE_DIR=$PROJECT_ROOT/release
TMP_BUILD_DIR=$PROJECT_ROOT/tmp

# 创建release和tmp目录
mkdir -p $RELEASE_DIR
mkdir -p $TMP_BUILD_DIR/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# 编译并打包项目为RPM源文件
make
SCRIPT_PATH=$(readlink -f "$0")
cp -r $(pwd) $RELEASE_DIR/cryptfs-tpm2-${VERSION}/

# 压缩RPM源文件
cd $RELEASE_DIR
tar czf $TMP_BUILD_DIR/rpmbuild/SOURCES/project.tar.gz cryptfs-tpm2-${VERSION}
cd $PROJECT_ROOT

# 创建RPM SPEC文件
cat > $TMP_BUILD_DIR/rpmbuild/SPECS/cryptfs-tpm2.spec <<EOF
Name: cryptfs-tpm2
Version: ${VERSION}
Release: ${RELEASE_VERSION}%{?dist}
Summary: cryptfs-tpm2 tools and library
License: MIT
Source0: project.tar.gz
BuildArch: x86_64
Requires: cryptsetup tpm2-tss tpm2-tools 

%description
Cryptfs-TPM2

%prep
%setup -q

%install
export DESTDIR=%{buildroot}
mkdir -p %{buildroot}${LIBDIR}
mkdir -p %{buildroot}${SBINDIR}
make install

%files
${LIBDIR}/*
${SBINDIR}/*

%changelog
* ${DATE} Jiale Zhang <zhangjiale@linux.alibaba.com> - ${VERSION}-1
- First package release
EOF

# 构建RPM包，使用tmp作为临时构建目录
rpmbuild -ba --define "_topdir $TMP_BUILD_DIR/rpmbuild" $TMP_BUILD_DIR/rpmbuild/SPECS/cryptfs-tpm2.spec

# 移动构建的RPM包到release目录
find $TMP_BUILD_DIR/rpmbuild/RPMS -type f -name '*.rpm' -exec mv {} $RELEASE_DIR \;
rm -rf $RELEASE_DIR/cryptfs-tpm2-${VERSION}

# 清理临时文件
rm -rf $TMP_BUILD_DIR

echo "RPM package has been successfully built and moved to $RELEASE_DIR"
