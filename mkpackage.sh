#!/bin/sh
cd `dirname "$0"`
SELF="${PWD}"
PARENTDIR=`dirname "${SELF}"`
VERSION=`cat ${SELF}/package_version`
ARCHIVE="${PARENTDIR}/ilias_net2-${VERSION}"

cd "${PARENTDIR}" || exit 1
echo "Generating source package ${ARCHIVE}.tar from ${SELF} in ${PARENTDIR}."
find `basename "${SELF}"` \( -name .git -a -prune \) -o -type f -print | sort | tar -cf "${ARCHIVE}.tar" -C "${PARENTDIR}" -I - || exit 1
echo "Compressing archive with gzip."
gzip -9 "${ARCHIVE}.tar" || exit 1
