#!/bin/sh

CORE_TOP=`pwd`

LIBSODIUM_VER="f553bb4bf22a6a8e4fa5f69cfbf91ce95327b790"
LIBSODIUM_ZIP="libsodium-$LIBSODIUM_VER.zip"
LIBSODIUM_DIR="$CORE_TOP/c_src/libsodium-$LIBSODIUM_VER"


UNZIP=`which unzip`
if ! test -n "UNZIP"; then
    display_error "Error: unzip is required. Add it to 'PATH'"
    exit 1
fi

clean() {
    echo "==> clean libsodium"
    if test -f $LIBSODIUM_DIR/Makefile; then
        cd $LIBSODIUM_DIR && make clean
    fi
}
    

build() {
    echo "==> build libsodium"
    # unzip
    if ! test -d $LIBSODIUM_DIR; then
        cd $CORE_TOP/c_src && $UNZIP $LIBSODIUM_ZIP
    fi

    cd $LIBSODIUM_DIR
    
    # configure
    if ! test -f $LIBSODIUM_DIR/Makefile; then
        ./autogen.sh
        ./configure --disable-shared --enable-static
    fi

    make
}

if [ "x$1" = "x" ]; then
    build
    exit 0
fi

case "$1" in
    build)
        shift 1
        build
        ;;
    clean)
        shift 1
        clean
        ;;
    *)
        echo "badarg"
        exit 1;
        ;;
esac
